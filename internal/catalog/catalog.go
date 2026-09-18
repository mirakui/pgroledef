// Package catalog reads the actual role/privilege state from PostgreSQL system
// catalogs. It is the "actual" side of the plan diff.
package catalog

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PrivSet is a set of privilege names as reported by aclexplode().
type PrivSet map[string]bool

func (p PrivSet) Sorted() []string {
	out := make([]string, 0, len(p))
	for k := range p {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ACL maps grantee role name -> privileges.
type ACL map[string]PrivSet

func (a ACL) add(grantee, priv string) {
	if a[grantee] == nil {
		a[grantee] = PrivSet{}
	}
	a[grantee][priv] = true
}

type Role struct {
	Name     string
	Login    bool
	Super    bool
	MemberOf map[string]bool
	// InheritsFrom is the subset of MemberOf granted WITH INHERIT. Only those
	// memberships carry the group's privileges; a membership granted with
	// ADMIN alone (what CREATE ROLE gives a non-superuser creator) does not,
	// and is not enough for ALTER DEFAULT PRIVILEGES FOR ROLE.
	InheritsFrom map[string]bool
	// IAMPrincipals holds the IAM ARNs mapped to this role on Aurora DSQL.
	// Always empty on Aurora PostgreSQL, which maps IAM identities through
	// rds_iam membership instead.
	IAMPrincipals map[string]bool
}

type Relation struct {
	Name  string
	Kind  byte // pg_class.relkind
	Owner string
	ACL   ACL
}

// DefaultACLKey identifies one pg_default_acl row (in-schema only).
type DefaultACLKey struct {
	ForRole string
	ObjType string // "tables" | "sequences"
}

type Schema struct {
	Name       string
	Owner      string
	ACL        ACL
	Relations  map[string]*Relation
	DefaultACL map[DefaultACLKey]ACL
}

type Database struct {
	Name  string
	Owner string
	ACL   ACL
	// AllowConn is pg_database.datallowconn. Its ACL is still readable when
	// false, so the database stays in State; only reading its schemas is
	// impossible.
	AllowConn bool
	Schemas   map[string]*Schema // nil until ReadDatabase is called
}

// State is the cluster-wide snapshot.
type State struct {
	CurrentUser string
	// ServerVersionNum is server_version_num (e.g. 170004); 0 when unknown.
	ServerVersionNum int
	Roles            map[string]*Role
	Databases        map[string]*Database
}

// Connector opens connections to a given database on the same server.
type Connector interface {
	Connect(ctx context.Context, database string) (*pgx.Conn, error)
}

// PasswordPrompt asks the operator for a password. It is called at most once,
// after the server has rejected the connection for want of one.
type PasswordPrompt func(ctx context.Context) (string, error)

// DSNConnector derives per-database connections from a base DSN.
type DSNConnector struct {
	Base *pgx.ConnConfig
	// Prompt, when set, is called the first time the server rejects the
	// connection with an authorization error. The answer is kept in Base, so
	// the operator is asked once however many databases the plan reads.
	Prompt   PasswordPrompt
	prompted bool
}

func NewDSNConnector(dsn string) (*DSNConnector, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	return &DSNConnector{Base: cfg}, nil
}

// NewConnConfigConnector wraps settings that were already resolved, which is
// how the CLI hands over a DSN that the -h/-p/-U/-d flags have overridden.
func NewConnConfigConnector(cfg *pgx.ConnConfig) *DSNConnector { return &DSNConnector{Base: cfg} }

// SetPassword overrides the password the DSN carries and suppresses the
// interactive retry: the caller has already asked.
func (c *DSNConnector) SetPassword(password string) {
	c.Base.Password = password
	c.prompted = true
}

func (c *DSNConnector) Connect(ctx context.Context, database string) (*pgx.Conn, error) {
	cfg := c.Base.Copy()
	if database != "" {
		cfg.Database = database
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err == nil {
		return conn, nil
	}
	if !c.shouldPrompt(err) {
		return nil, fmt.Errorf("connect to database %q: %w", cfg.Database, err)
	}
	c.prompted = true
	password, promptErr := c.Prompt(ctx)
	if promptErr != nil {
		return nil, fmt.Errorf("connect to database %q: %w (reading a password instead: %v)", cfg.Database, err, promptErr)
	}
	c.Base.Password = password
	cfg.Password = password
	conn, err = pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to database %q: %w", cfg.Database, err)
	}
	return conn, nil
}

// shouldPrompt reports whether err is the server turning us away over
// credentials. Class 28 is the whole authorization family: 28P01 is the failed
// password, and 28000 is what the server reports for every other
// authentication method, several of which are password-driven on Aurora.
// Taking the class whole asks once too often — a missing role answers 28000
// too, and no password fixes that — but that costs a wasted prompt, where
// narrowing to 28P01 would leave legitimate setups unprompted. Anything
// outside the class, an unreachable host or a missing database, is not about
// credentials at all.
func (c *DSNConnector) shouldPrompt(err error) bool {
	if c.Prompt == nil || c.prompted {
		return false
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return strings.HasPrefix(pgErr.Code, "28")
}

// ReadCluster reads roles, memberships and database-level ACLs using the
// connector's default database.
func ReadCluster(ctx context.Context, conn *pgx.Conn) (*State, error) {
	st := &State{Roles: map[string]*Role{}, Databases: map[string]*Database{}}
	if err := conn.QueryRow(ctx, `SELECT current_user, current_setting('server_version_num')::int`).
		Scan(&st.CurrentUser, &st.ServerVersionNum); err != nil {
		return nil, err
	}
	rows, err := conn.Query(ctx, `SELECT rolname, rolcanlogin, rolsuper FROM pg_roles ORDER BY rolname`)
	if err != nil {
		return nil, fmt.Errorf("read pg_roles: %w", err)
	}
	for rows.Next() {
		r := &Role{MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}, IAMPrincipals: map[string]bool{}}
		if err := rows.Scan(&r.Name, &r.Login, &r.Super); err != nil {
			return nil, err
		}
		st.Roles[r.Name] = r
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, rows.Err()
	}

	rows, err = conn.Query(ctx, `
		SELECT m.rolname AS member, g.rolname AS grp, am.inherit_option
		FROM pg_auth_members am
		JOIN pg_roles m ON m.oid = am.member
		JOIN pg_roles g ON g.oid = am.roleid`)
	if err != nil {
		return nil, fmt.Errorf("read pg_auth_members: %w", err)
	}
	for rows.Next() {
		var member, grp string
		var inherit bool
		if err := rows.Scan(&member, &grp, &inherit); err != nil {
			return nil, err
		}
		if r := st.Roles[member]; r != nil {
			r.MemberOf[grp] = true
			if inherit {
				r.InheritsFrom[grp] = true
			}
		}
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, rows.Err()
	}

	rows, err = conn.Query(ctx, `
		SELECT d.datname, pg_get_userbyid(d.datdba), d.datallowconn, a.grantee, a.privilege_type
		FROM pg_database d
		LEFT JOIN LATERAL (
			SELECT COALESCE(pg_get_userbyid(x.grantee), '') AS grantee, x.privilege_type
			FROM aclexplode(d.datacl) x WHERE x.grantee <> 0
		) a ON true
		WHERE NOT d.datistemplate`)
	if err != nil {
		return nil, fmt.Errorf("read pg_database: %w", err)
	}
	for rows.Next() {
		var name, owner string
		var allowConn bool
		var grantee, priv *string
		if err := rows.Scan(&name, &owner, &allowConn, &grantee, &priv); err != nil {
			return nil, err
		}
		db := st.Databases[name]
		if db == nil {
			db = &Database{Name: name, Owner: owner, AllowConn: allowConn, ACL: ACL{}}
			st.Databases[name] = db
		}
		if grantee != nil && priv != nil && *grantee != "" {
			db.ACL.add(*grantee, *priv)
		}
	}
	rows.Close()
	return st, rows.Err()
}

// ReadDatabase fills schema, relation and default-privilege ACLs for one database.
func ReadDatabase(ctx context.Context, conn *pgx.Conn, db *Database) error {
	db.Schemas = map[string]*Schema{}
	rows, err := conn.Query(ctx, `
		SELECT n.nspname, pg_get_userbyid(n.nspowner), a.grantee, a.privilege_type
		FROM pg_namespace n
		LEFT JOIN LATERAL (
			SELECT pg_get_userbyid(x.grantee) AS grantee, x.privilege_type
			FROM aclexplode(n.nspacl) x WHERE x.grantee <> 0
		) a ON true
		WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
		  AND n.nspname NOT LIKE 'pg\_temp\_%' AND n.nspname NOT LIKE 'pg\_toast\_%'`)
	if err != nil {
		return fmt.Errorf("read pg_namespace: %w", err)
	}
	for rows.Next() {
		var name, owner string
		var grantee, priv *string
		if err := rows.Scan(&name, &owner, &grantee, &priv); err != nil {
			return err
		}
		s := db.Schemas[name]
		if s == nil {
			s = &Schema{Name: name, Owner: owner, ACL: ACL{}, Relations: map[string]*Relation{}, DefaultACL: map[DefaultACLKey]ACL{}}
			db.Schemas[name] = s
		}
		if grantee != nil && priv != nil {
			s.ACL.add(*grantee, *priv)
		}
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}

	rows, err = conn.Query(ctx, `
		SELECT n.nspname, c.relname, c.relkind::text, pg_get_userbyid(c.relowner), a.grantee, a.privilege_type
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN LATERAL (
			SELECT pg_get_userbyid(x.grantee) AS grantee, x.privilege_type
			FROM aclexplode(c.relacl) x WHERE x.grantee <> 0
		) a ON true
		WHERE c.relkind IN ('r', 'v', 'm', 'p', 'f', 'S')
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
		  AND n.nspname NOT LIKE 'pg\_temp\_%' AND n.nspname NOT LIKE 'pg\_toast\_%'`)
	if err != nil {
		return fmt.Errorf("read pg_class: %w", err)
	}
	for rows.Next() {
		var nsp, rel, kind, owner string
		var grantee, priv *string
		if err := rows.Scan(&nsp, &rel, &kind, &owner, &grantee, &priv); err != nil {
			return err
		}
		s := db.Schemas[nsp]
		if s == nil {
			continue
		}
		r := s.Relations[rel]
		if r == nil {
			r = &Relation{Name: rel, Kind: kind[0], Owner: owner, ACL: ACL{}}
			s.Relations[rel] = r
		}
		if grantee != nil && priv != nil {
			r.ACL.add(*grantee, *priv)
		}
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}

	rows, err = conn.Query(ctx, `
		SELECT pg_get_userbyid(d.defaclrole), n.nspname, d.defaclobjtype::text,
		       pg_get_userbyid(x.grantee), x.privilege_type
		FROM pg_default_acl d
		JOIN pg_namespace n ON n.oid = d.defaclnamespace
		CROSS JOIN LATERAL aclexplode(d.defaclacl) x
		WHERE x.grantee <> 0 AND d.defaclobjtype IN ('r', 'S')`)
	if err != nil {
		return fmt.Errorf("read pg_default_acl: %w", err)
	}
	for rows.Next() {
		var forRole, nsp, objType, grantee, priv string
		if err := rows.Scan(&forRole, &nsp, &objType, &grantee, &priv); err != nil {
			return err
		}
		s := db.Schemas[nsp]
		if s == nil {
			continue
		}
		key := DefaultACLKey{ForRole: forRole, ObjType: map[string]string{"r": "tables", "S": "sequences"}[objType]}
		if s.DefaultACL[key] == nil {
			s.DefaultACL[key] = ACL{}
		}
		s.DefaultACL[key].add(grantee, priv)
	}
	rows.Close()
	return rows.Err()
}

// IsTableLike reports whether the relation participates in GRANT ... ON ALL TABLES.
func (r *Relation) IsTableLike() bool { return strings.ContainsRune("rvmpf", rune(r.Kind)) }

// IsSequence reports whether the relation is a sequence.
func (r *Relation) IsSequence() bool { return r.Kind == 'S' }

// ReadIAMPrincipals fills Role.IAMPrincipals from sys.iam_pg_role_mappings.
// Aurora DSQL only; the view does not exist on Aurora PostgreSQL.
func ReadIAMPrincipals(ctx context.Context, conn *pgx.Conn, st *State) error {
	rows, err := conn.Query(ctx, `SELECT pg_role_name, arn FROM sys.iam_pg_role_mappings`)
	if err != nil {
		return fmt.Errorf("read sys.iam_pg_role_mappings: %w", err)
	}
	for rows.Next() {
		var role, arn string
		if err := rows.Scan(&role, &arn); err != nil {
			return err
		}
		if r := st.Roles[role]; r != nil {
			r.IAMPrincipals[arn] = true
		}
	}
	rows.Close()
	return rows.Err()
}
