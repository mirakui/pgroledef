// Package plan diffs the desired canonical config against the actual catalog
// state and produces the SQL statements that reconcile them.
package plan

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mirakui/pgroledef/internal/catalog"
	"github.com/mirakui/pgroledef/internal/config"
)

// Statement is one SQL statement to run. Database "" means cluster level
// (run on the connector's default database).
type Statement struct {
	Database    string
	SQL         string
	Destructive bool // REVOKE / DROP / removes access
	Note        string
}

// Plan is the ordered set of statements grouped by the database they run in.
type Plan struct {
	// Dialect is the engine the plan was built for; Apply reads its ApplyMode.
	Dialect    Dialect
	Statements []Statement
	// RoleDiffs is the same change set expressed in the shape of the
	// declaration, one entry per role, for human review.
	RoleDiffs []RoleDiff
}

func (p *Plan) Empty() bool { return len(p.Statements) == 0 }

func (p *Plan) add(db, sql string, destructive bool, note string) {
	p.Statements = append(p.Statements, Statement{Database: db, SQL: sql, Destructive: destructive, Note: note})
}

// Databases returns the distinct databases touched, "" first, then sorted.
func (p *Plan) Databases() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range p.Statements {
		if !seen[s.Database] {
			seen[s.Database] = true
			out = append(out, s.Database)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i] == "" || out[j] == "" {
			return out[i] == ""
		}
		return out[i] < out[j]
	})
	return out
}

// Build connects, reads the catalog, and computes the plan. Only roles
// declared in cfg are managed: their existence, login flag, memberships,
// and every privilege they hold on managed databases.
func Build(ctx context.Context, cfg *config.Config, connector catalog.Connector) (*Plan, error) {
	dialect := DialectFor(cfg.Target.Engine)
	conn, err := connector.Connect(ctx, "")
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)

	st, err := catalog.ReadCluster(ctx, conn)
	if err != nil {
		return nil, err
	}
	if err := config.CheckServerMajor(cfg, config.MajorFromVersionNum(st.ServerVersionNum)); err != nil {
		return nil, err
	}
	if dialect.IAMPrincipals {
		if err := catalog.ReadIAMPrincipals(ctx, conn, st); err != nil {
			return nil, err
		}
	}
	dbs := referencedDatabases(cfg)
	for _, name := range dbs {
		db := st.Databases[name]
		if db == nil {
			return nil, fmt.Errorf("database %q is referenced but does not exist (database creation is out of scope)", name)
		}
		if !db.AllowConn {
			return nil, fmt.Errorf("database %q is referenced but does not accept connections (pg_database.datallowconn is false)", name)
		}
		if err := readDatabase(ctx, connector, db); err != nil {
			return nil, err
		}
	}
	// Databases not referenced by the config but managed (not unmanaged) still
	// need reading so stray privileges of managed roles can be revoked.
	for name, db := range st.Databases {
		if db.Schemas != nil || !db.AllowConn || matchesAny(name, cfg.Policy.UnmanagedDatabases) {
			continue
		}
		if err := readDatabase(ctx, connector, db); err != nil {
			return nil, err
		}
	}
	return Diff(cfg, st)
}

// readDatabase fills one database's schemas. A managed database that cannot be
// read cannot be reconciled, so this is fatal; when the database is refusing
// this user rather than merely unreachable, the error names the way out.
func readDatabase(ctx context.Context, connector catalog.Connector, db *catalog.Database) error {
	conn, err := connector.Connect(ctx, db.Name)
	if err != nil {
		return notForUs(db.Name, err)
	}
	defer conn.Close(ctx)
	return notForUs(db.Name, catalog.ReadDatabase(ctx, conn, db))
}

// notForUs appends the policy hint when the server rejected this user, rather
// than to every failure: following the hint removes the database from
// reconciliation for good, which is the wrong answer to a transient error or an
// expired token.
func notForUs(name string, err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	// 28xxx: invalid authorization (pg_hba rejection, failed password).
	// 42501: insufficient privilege, e.g. a catalog read denied mid-way.
	if !strings.HasPrefix(pgErr.Code, "28") && pgErr.Code != "42501" {
		return err
	}
	return fmt.Errorf("%w\nadd %q to policy.unmanaged_databases if it is not meant to be managed", err, name)
}

func matchesAny(name string, patterns []string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

func referencedDatabases(cfg *config.Config) []string {
	seen := map[string]bool{}
	for _, g := range cfg.FlatGrants() {
		kind, val, _ := g.On.Kind()
		switch kind {
		case "database":
			seen[val] = true
		case "schema", "all_tables_in_schema", "all_sequences_in_schema":
			q, _ := config.ParseSchema(val)
			seen[q.Database] = true
		case "table", "sequence":
			q, _ := config.ParseRelation(val)
			seen[q.Database] = true
		}
	}
	for _, d := range cfg.FlatDefaultPrivileges() {
		q, _ := config.ParseSchema(d.InSchema)
		seen[q.Database] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ident(parts ...string) string { return pgx.Identifier(parts).Sanitize() }

// literal quotes a string literal. DSQL's AWS IAM GRANT takes the ARN as a
// literal, not an identifier.
func literal(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func privList(ps []string) string { return strings.Join(ps, ", ") }

type privSet = catalog.PrivSet

func toSet(ps []config.Privilege) privSet {
	s := privSet{}
	for _, p := range ps {
		s[string(p)] = true
	}
	return s
}

func diffSets(desired, actual privSet) (missing, extra []string) {
	for p := range desired {
		if !actual[p] {
			missing = append(missing, p)
		}
	}
	for p := range actual {
		if !desired[p] {
			extra = append(extra, p)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return
}

// Diff computes the plan from an already-read state (pure; used by tests).
func Diff(cfg *config.Config, st *catalog.State) (*Plan, error) {
	if st.ServerVersionNum != 0 {
		if err := config.CheckServerMajor(cfg, config.MajorFromVersionNum(st.ServerVersionNum)); err != nil {
			return nil, err
		}
	}
	p := &Plan{Dialect: DialectFor(cfg.Target.Engine)}
	d := &differ{cfg: cfg, st: st, p: p, dialect: p.Dialect, created: map[string]bool{}}
	if err := d.roles(); err != nil {
		return nil, err
	}
	if err := d.grants(); err != nil {
		return nil, err
	}
	if err := d.defaultPrivileges(); err != nil {
		return nil, err
	}
	order := make(map[string]int, len(cfg.Roles))
	for i, r := range cfg.Roles {
		order[r.Name] = i
	}
	p.sortRoleDiffs(order)
	return p, nil
}

type differ struct {
	cfg     *config.Config
	st      *catalog.State
	p       *Plan
	dialect Dialect
	// created are the roles this plan creates. CREATE ROLE by a non-superuser
	// leaves the executing user a member WITH ADMIN OPTION, which the catalog
	// snapshot predates.
	created map[string]bool
}

func (d *differ) managed(role string) bool {
	_, ok := d.cfg.Role(role)
	return ok
}

func (d *differ) roles() error {
	type pending struct {
		name          string
		grant, revoke []string
		before, after []string
	}
	var later []pending
	// Pass 1: existence and login flag, so memberships in pass 2 can reference
	// roles created in the same plan.
	for _, want := range d.cfg.Roles {
		name := want.Name
		desiredMembers := map[string]bool{}
		for _, m := range want.MemberOf {
			desiredMembers[m] = true
		}
		// Groups may be declared in the file or, like Aurora's rds_iam, provided by the server.
		for g := range desiredMembers {
			if _, declared := d.cfg.Role(g); !declared && d.st.Roles[g] == nil {
				return fmt.Errorf("role %q: member_of %q is neither declared nor present on this server", name, g)
			}
		}
		have := d.st.Roles[name]
		if have == nil {
			login := "NOLOGIN"
			if want.Login {
				login = "LOGIN"
			}
			d.p.add("", fmt.Sprintf("CREATE ROLE %s WITH %s", ident(name), login), false, "")
			d.created[name] = true
			have = &catalog.Role{Name: name, Login: want.Login, MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}}
			rd := d.roleDiff(name)
			rd.Created = true
			rd.LoginChanged, rd.LoginAfter = true, want.Login
		} else if have.Login != want.Login {
			flag := "NOLOGIN"
			if want.Login {
				flag = "LOGIN"
			}
			d.p.add("", fmt.Sprintf("ALTER ROLE %s WITH %s", ident(name), flag), !want.Login, "")
			rd := d.roleDiff(name)
			rd.LoginChanged, rd.LoginBefore, rd.LoginAfter = true, have.Login, want.Login
		}
		pd := pending{name: name}
		for g := range desiredMembers {
			if !have.MemberOf[g] {
				pd.grant = append(pd.grant, g)
			}
		}
		for g := range have.MemberOf {
			if !desiredMembers[g] {
				pd.revoke = append(pd.revoke, g)
			}
		}
		sort.Strings(pd.grant)
		sort.Strings(pd.revoke)
		for g := range have.MemberOf {
			pd.before = append(pd.before, g)
		}
		for g := range desiredMembers {
			pd.after = append(pd.after, g)
		}
		sort.Strings(pd.before)
		sort.Strings(pd.after)
		later = append(later, pd)
	}
	// Pass 2: memberships.
	for _, pd := range later {
		if len(pd.grant) > 0 || len(pd.revoke) > 0 {
			rd := d.roleDiff(pd.name)
			rd.MembersChanged, rd.MembersBefore, rd.MembersAfter = true, pd.before, pd.after
		}
		for _, g := range pd.grant {
			d.p.add("", fmt.Sprintf("GRANT %s TO %s", ident(g), ident(pd.name)), false, "")
		}
		for _, g := range pd.revoke {
			d.p.add("", fmt.Sprintf("REVOKE %s FROM %s", ident(g), ident(pd.name)), true, "membership not declared")
		}
	}
	d.iamPrincipals()
	return nil
}

// iamPrincipals reconciles the IAM ARNs mapped to each declared role. DSQL
// only: on Aurora the mapping lives in IAM policies, which are out of scope.
func (d *differ) iamPrincipals() {
	if !d.dialect.IAMPrincipals {
		return
	}
	for _, want := range d.cfg.Roles {
		desired := map[string]bool{}
		for _, arn := range want.IAMPrincipals {
			desired[arn] = true
		}
		var have map[string]bool
		if r := d.st.Roles[want.Name]; r != nil {
			have = r.IAMPrincipals
		}
		var grant, revoke, before, after []string
		for arn := range desired {
			if !have[arn] {
				grant = append(grant, arn)
			}
			after = append(after, arn)
		}
		for arn := range have {
			if !desired[arn] {
				revoke = append(revoke, arn)
			}
			before = append(before, arn)
		}
		if len(grant) == 0 && len(revoke) == 0 {
			continue
		}
		sort.Strings(grant)
		sort.Strings(revoke)
		sort.Strings(before)
		sort.Strings(after)
		rd := d.roleDiff(want.Name)
		rd.PrincipalsChanged, rd.PrincipalsBefore, rd.PrincipalsAfter = true, before, after
		for _, arn := range grant {
			d.p.add("", fmt.Sprintf("AWS IAM GRANT %s TO %s", ident(want.Name), literal(arn)), false, "")
		}
		for _, arn := range revoke {
			d.p.add("", fmt.Sprintf("AWS IAM REVOKE %s FROM %s", ident(want.Name), literal(arn)), true,
				"iam principal not declared")
		}
	}
}

// objectKey identifies a grant target within a database for diffing.
type objectKey struct {
	Database string
	Kind     string // database | schema | table | sequence
	Schema   string
	Name     string
}

func (k objectKey) sqlTarget() string {
	switch k.Kind {
	case "database":
		return "DATABASE " + ident(k.Database)
	case "schema":
		return "SCHEMA " + ident(k.Schema)
	case "table":
		return "TABLE " + ident(k.Schema, k.Name)
	case "sequence":
		return "SEQUENCE " + ident(k.Schema, k.Name)
	}
	panic("unknown kind " + k.Kind)
}

type grantKey struct {
	Object  objectKey
	Grantee string
}

func (d *differ) grants() error {
	desired := map[grantKey]privSet{}
	// allTables[schemaKey][grantee] tracks schema-wide desires for compact statements.
	type schemaGrantee struct {
		Database, Schema, Kind, Grantee string
	}
	wide := map[schemaGrantee]privSet{}

	addDesired := func(k grantKey, ps []config.Privilege) {
		if desired[k] == nil {
			desired[k] = privSet{}
		}
		for _, p := range ps {
			desired[k][string(p)] = true
		}
	}

	for _, g := range d.cfg.FlatGrants() {
		kind, val, _ := g.On.Kind()
		switch kind {
		case "database":
			addDesired(grantKey{objectKey{Database: val, Kind: "database"}, g.To}, g.Privileges)
		case "schema":
			q, _ := config.ParseSchema(val)
			if err := d.requireSchema(q); err != nil {
				return err
			}
			addDesired(grantKey{objectKey{Database: q.Database, Kind: "schema", Schema: q.Schema}, g.To}, g.Privileges)
		case "all_tables_in_schema", "all_sequences_in_schema":
			q, _ := config.ParseSchema(val)
			if err := d.requireSchema(q); err != nil {
				return err
			}
			relKind := "table"
			if kind == "all_sequences_in_schema" {
				relKind = "sequence"
			}
			sg := schemaGrantee{q.Database, q.Schema, relKind, g.To}
			if wide[sg] == nil {
				wide[sg] = privSet{}
			}
			for _, p := range g.Privileges {
				wide[sg][string(p)] = true
			}
			for _, rel := range d.st.Databases[q.Database].Schemas[q.Schema].Relations {
				if (relKind == "table" && rel.IsTableLike()) || (relKind == "sequence" && rel.IsSequence()) {
					addDesired(grantKey{objectKey{q.Database, relKind, q.Schema, rel.Name}, g.To}, g.Privileges)
				}
			}
		case "table", "sequence":
			q, _ := config.ParseRelation(val)
			if err := d.requireSchema(q.SchemaRef()); err != nil {
				return err
			}
			if d.st.Databases[q.Database].Schemas[q.Schema].Relations[q.Name] == nil {
				return fmt.Errorf("%s %q does not exist", kind, q)
			}
			addDesired(grantKey{objectKey{q.Database, kind, q.Schema, q.Name}, g.To}, g.Privileges)
		}
	}

	// Actual privileges held by managed roles on managed databases, excluding
	// what they hold as owner (owners keep implicit rights; not reconciled).
	actual := map[grantKey]privSet{}
	for dbName, db := range d.st.Databases {
		if matchesAny(dbName, d.cfg.Policy.UnmanagedDatabases) {
			continue
		}
		// Without an ON DATABASE form there is nothing to revoke with, and
		// emitting one anyway would fail mid-apply on an engine that cannot
		// roll the rest back.
		if d.dialect.DatabaseGrants {
			for grantee, ps := range db.ACL {
				if d.managed(grantee) && grantee != db.Owner {
					actual[grantKey{objectKey{Database: dbName, Kind: "database"}, grantee}] = ps
				}
			}
		}
		for _, s := range db.Schemas {
			for grantee, ps := range s.ACL {
				if d.managed(grantee) && grantee != s.Owner {
					actual[grantKey{objectKey{dbName, "schema", s.Name, ""}, grantee}] = ps
				}
			}
			for _, rel := range s.Relations {
				kind := "table"
				if rel.IsSequence() {
					kind = "sequence"
				}
				for grantee, ps := range rel.ACL {
					if d.managed(grantee) && grantee != rel.Owner {
						actual[grantKey{objectKey{dbName, kind, s.Name, rel.Name}, grantee}] = ps
					}
				}
			}
		}
	}

	keys := map[grantKey]bool{}
	for k := range desired {
		keys[k] = true
	}
	for k := range actual {
		keys[k] = true
	}
	sorted := make([]grantKey, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Object.Database != b.Object.Database {
			return a.Object.Database < b.Object.Database
		}
		if a.Object.Kind != b.Object.Kind {
			return kindOrder(a.Object.Kind) < kindOrder(b.Object.Kind)
		}
		if a.Object.Schema != b.Object.Schema {
			return a.Object.Schema < b.Object.Schema
		}
		if a.Object.Name != b.Object.Name {
			return a.Object.Name < b.Object.Name
		}
		return a.Grantee < b.Grantee
	})

	// Compact: when a schema-wide grant is missing for every relation, emit ON ALL ... IN SCHEMA once.
	emittedWide := map[schemaGrantee]privSet{}
	for sg, ps := range wide {
		schema := d.st.Databases[sg.Database].Schemas[sg.Schema]
		var rels []*catalog.Relation
		for _, r := range schema.Relations {
			if (sg.Kind == "table" && r.IsTableLike()) || (sg.Kind == "sequence" && r.IsSequence()) {
				rels = append(rels, r)
			}
		}
		if len(rels) == 0 {
			continue
		}
		missingEverywhere := privSet{}
		for p := range ps {
			all := true
			for _, r := range rels {
				if r.Owner == sg.Grantee || r.ACL[sg.Grantee][p] {
					all = false
					break
				}
			}
			if all {
				missingEverywhere[p] = true
			}
		}
		if len(missingEverywhere) > 0 {
			emittedWide[sg] = missingEverywhere
		}
	}
	wideKeys := make([]schemaGrantee, 0, len(emittedWide))
	for k := range emittedWide {
		wideKeys = append(wideKeys, k)
	}
	sort.Slice(wideKeys, func(i, j int) bool {
		return fmt.Sprint(wideKeys[i]) < fmt.Sprint(wideKeys[j])
	})
	type ranked struct {
		rank int
		st   Statement
	}
	var out []ranked
	for _, sg := range wideKeys {
		target := "ALL TABLES IN SCHEMA"
		if sg.Kind == "sequence" {
			target = "ALL SEQUENCES IN SCHEMA"
		}
		out = append(out, ranked{2, Statement{Database: sg.Database, SQL: fmt.Sprintf("GRANT %s ON %s %s TO %s",
			privList(emittedWide[sg].Sorted()), target, ident(sg.Schema), ident(sg.Grantee))}})
		d.addPrivDiff(sg.Grantee, PrivDiff{
			Label: fmt.Sprintf("%s %s.%s", target, sg.Database, sg.Schema),
			Added: emittedWide[sg].Sorted(),
		})
	}
	for _, k := range sorted {
		missing, extra := diffSets(desired[k], actual[k])
		if k.Object.Kind == "table" || k.Object.Kind == "sequence" {
			sg := schemaGrantee{k.Object.Database, k.Object.Schema, k.Object.Kind, k.Grantee}
			missing = without(missing, emittedWide[sg])
		}
		rank := map[string]int{"database": 0, "schema": 1, "table": 3, "sequence": 4}[k.Object.Kind]
		d.addPrivDiff(k.Grantee, PrivDiff{Label: k.Object.displayTarget(), Added: missing, Removed: extra})
		if len(missing) > 0 {
			out = append(out, ranked{rank, Statement{Database: k.Object.Database,
				SQL: fmt.Sprintf("GRANT %s ON %s TO %s", privList(missing), k.Object.sqlTarget(), ident(k.Grantee))}})
		}
		if len(extra) > 0 {
			out = append(out, ranked{rank, Statement{Database: k.Object.Database, Destructive: true, Note: "privilege not declared",
				SQL: fmt.Sprintf("REVOKE %s ON %s FROM %s", privList(extra), k.Object.sqlTarget(), ident(k.Grantee))}})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].st.Database != out[j].st.Database {
			return out[i].st.Database < out[j].st.Database
		}
		return out[i].rank < out[j].rank
	})
	for _, r := range out {
		d.p.Statements = append(d.p.Statements, r.st)
	}
	return nil
}

func without(ps []string, drop privSet) []string {
	var out []string
	for _, p := range ps {
		if !drop[p] {
			out = append(out, p)
		}
	}
	return out
}

func kindOrder(k string) int {
	return map[string]int{"database": 0, "schema": 1, "table": 2, "sequence": 3}[k]
}

func (d *differ) requireSchema(q config.QualifiedSchema) error {
	db := d.st.Databases[q.Database]
	if db == nil {
		return fmt.Errorf("database %q does not exist", q.Database)
	}
	if db.Schemas[q.Schema] == nil {
		return fmt.Errorf("schema %q does not exist in database %q (schema creation is out of scope)", q.Schema, q.Database)
	}
	return nil
}

type defaultKey struct {
	Database, Schema, ForRole, ObjType, Grantee string
}

func (d *differ) defaultPrivileges() error {
	desired := map[defaultKey]privSet{}
	for _, dp := range d.cfg.FlatDefaultPrivileges() {
		q, _ := config.ParseSchema(dp.InSchema)
		if err := d.requireSchema(q); err != nil {
			return err
		}
		desired[defaultKey{q.Database, q.Schema, dp.ForRole, string(dp.On), dp.To}] = toSet(dp.Privileges)
	}
	actual := map[defaultKey]privSet{}
	for dbName, db := range d.st.Databases {
		if matchesAny(dbName, d.cfg.Policy.UnmanagedDatabases) {
			continue
		}
		for _, s := range db.Schemas {
			for key, acl := range s.DefaultACL {
				for grantee, ps := range acl {
					// Reconcile when either side is managed: the creator or the grantee.
					if d.managed(key.ForRole) || d.managed(grantee) {
						actual[defaultKey{dbName, s.Name, key.ForRole, key.ObjType, grantee}] = ps
					}
				}
			}
		}
	}
	keys := map[defaultKey]bool{}
	for k := range desired {
		keys[k] = true
	}
	for k := range actual {
		keys[k] = true
	}
	sorted := make([]defaultKey, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Slice(sorted, func(i, j int) bool { return fmt.Sprint(sorted[i]) < fmt.Sprint(sorted[j]) })

	for _, k := range sorted {
		missing, extra := diffSets(desired[k], actual[k])
		if len(missing) == 0 && len(extra) == 0 {
			continue
		}
		objType := strings.ToUpper(k.ObjType)
		owner := k.Grantee
		if !d.managed(owner) {
			owner = k.ForRole
		}
		d.addPrivDiff(owner, PrivDiff{
			Default: true,
			Label: fmt.Sprintf("FOR ROLE %s IN SCHEMA %s.%s ON %s TO %s",
				k.ForRole, k.Database, k.Schema, objType, k.Grantee),
			Added:   missing,
			Removed: extra,
		})
		wrap := d.needsCreatorMembership(k.ForRole)
		if wrap {
			// INHERIT has to be named: on an existing membership GRANT leaves
			// the options it does not mention alone, so a plain GRANT can be a
			// no-op against a membership that carries ADMIN only.
			d.p.add(k.Database, fmt.Sprintf("GRANT %s TO CURRENT_USER WITH INHERIT TRUE", ident(k.ForRole)), false,
				"temporary: ALTER DEFAULT PRIVILEGES FOR ROLE requires an inheriting membership in the creator role")
		}
		if len(missing) > 0 {
			d.p.add(k.Database, fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT %s ON %s TO %s",
				ident(k.ForRole), ident(k.Schema), privList(missing), objType, ident(k.Grantee)), false, "")
		}
		if len(extra) > 0 {
			d.p.add(k.Database, fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s REVOKE %s ON %s FROM %s",
				ident(k.ForRole), ident(k.Schema), privList(extra), objType, ident(k.Grantee)), true, "default privilege not declared")
		}
		if wrap {
			d.p.add(k.Database, d.undoBorrow(k.ForRole), false, "undo temporary membership")
		}
	}
	d.releaseStaleBorrows(sorted)
	return nil
}

// undoBorrow gives back exactly what the borrow took: the whole membership
// only when there was none to begin with. A role this plan creates counts as
// having one, because CREATE ROLE already made the executing user a member
// WITH ADMIN OPTION - revoking that would leave it unable to administer a role
// it created itself.
func (d *differ) undoBorrow(creator string) string {
	me := d.st.Roles[d.st.CurrentUser]
	if d.created[creator] || (me != nil && me.MemberOf[creator]) {
		return fmt.Sprintf("REVOKE INHERIT OPTION FOR %s FROM CURRENT_USER", ident(creator))
	}
	return fmt.Sprintf("REVOKE %s FROM CURRENT_USER", ident(creator))
}

// releaseStaleBorrows returns an inheriting membership a previous apply took
// but never gave back. Where apply is not atomic a failure between the borrow
// and its undo leaves one behind, and nothing else would ever notice: the next
// plan sees the membership, decides no borrow is needed, and so never emits
// the undo either. The statements above still rely on the membership, so this
// runs after them, in the last database that used it.
func (d *differ) releaseStaleBorrows(keys []defaultKey) {
	me := d.st.Roles[d.st.CurrentUser]
	if me == nil || me.Super {
		return
	}
	last := map[string]string{}
	for _, k := range keys {
		if k.ForRole == d.st.CurrentUser || !me.InheritsFrom[k.ForRole] {
			continue
		}
		if db, seen := last[k.ForRole]; !seen || k.Database > db {
			last[k.ForRole] = k.Database
		}
	}
	creators := make([]string, 0, len(last))
	for creator := range last {
		creators = append(creators, creator)
	}
	sort.Strings(creators)
	for _, creator := range creators {
		d.p.add(last[creator], fmt.Sprintf("REVOKE INHERIT OPTION FOR %s FROM CURRENT_USER", ident(creator)), true,
			"membership borrowed by an earlier apply and never returned")
	}
}

// needsCreatorMembership reports whether the executing user must be granted the
// creator role before ALTER DEFAULT PRIVILEGES FOR ROLE <creator> can run.
// Plain membership is not enough: the grant has to carry INHERIT. Creating a
// role as a non-superuser leaves the creator a member WITH ADMIN OPTION only,
// which is what Aurora's master user and DSQL's admin end up holding for every
// role they create.
func (d *differ) needsCreatorMembership(creator string) bool {
	me := d.st.Roles[d.st.CurrentUser]
	if me == nil || me.Super || d.st.CurrentUser == creator {
		return false
	}
	return !me.InheritsFrom[creator]
}
