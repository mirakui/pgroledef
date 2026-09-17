// Package catalog reads the actual role/privilege state from PostgreSQL system
// catalogs. It is the "actual" side of the plan diff.
package catalog

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
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

// DSNConnector derives per-database connections from a base DSN.
type DSNConnector struct{ Base *pgx.ConnConfig }

func NewDSNConnector(dsn string) (*DSNConnector, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	return &DSNConnector{Base: cfg}, nil
}

func (c *DSNConnector) Connect(ctx context.Context, database string) (*pgx.Conn, error) {
	cfg := c.Base.Copy()
	if database != "" {
		cfg.Database = database
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to database %q: %w", cfg.Database, err)
	}
	return conn, nil
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
		r := &Role{MemberOf: map[string]bool{}}
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
		SELECT m.rolname AS member, g.rolname AS grp
		FROM pg_auth_members am
		JOIN pg_roles m ON m.oid = am.member
		JOIN pg_roles g ON g.oid = am.roleid`)
	if err != nil {
		return nil, fmt.Errorf("read pg_auth_members: %w", err)
	}
	for rows.Next() {
		var member, grp string
		if err := rows.Scan(&member, &grp); err != nil {
			return nil, err
		}
		if r := st.Roles[member]; r != nil {
			r.MemberOf[grp] = true
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
