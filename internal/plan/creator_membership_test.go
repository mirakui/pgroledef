package plan_test

import (
	"strings"
	"testing"

	"github.com/mirakui/pgroledef/internal/catalog"
	"github.com/mirakui/pgroledef/internal/config"
	"github.com/mirakui/pgroledef/internal/plan"
)

// TestCreatorMembershipNeedsInherit pins the reason the borrow exists: a
// membership granted WITH ADMIN OPTION only - which is what a non-superuser
// creator is left holding for every role it creates - does not let
// ALTER DEFAULT PRIVILEGES FOR ROLE run.
func TestCreatorMembershipNeedsInherit(t *testing.T) {
	cfg := &config.Config{
		Version: 1,
		Target:  config.Target{Engine: config.EngineAuroraPostgres, Identifier: "staging"},
		Policy:  config.DefaultPolicy(),
		Roles: []config.Role{
			{Name: "grp_viewer", Grants: []config.RoleGrant{
				{On: config.GrantTarget{AllTablesInSchema: "app.public"}, Privileges: []config.Privilege{config.PrivSelect}},
			}},
			{Name: "migrator", Login: true, CreatesObjectsIn: []string{"app.public"}},
		},
	}
	normalized, err := config.Validate(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// membership describes what the executing user already holds in the
	// creator role before the plan runs.
	type membership int
	const (
		none membership = iota
		adminOnly
		inheriting
		roleAbsent // the plan creates the creator role itself
	)

	newState := func(m membership) *catalog.State {
		me := &catalog.Role{Name: "master", Login: true, MemberOf: map[string]bool{},
			InheritsFrom: map[string]bool{}}
		switch m {
		case adminOnly:
			me.MemberOf["migrator"] = true
		case inheriting:
			me.MemberOf["migrator"] = true
			me.InheritsFrom["migrator"] = true
		}
		roles := map[string]*catalog.Role{
			"master":     me,
			"grp_viewer": {Name: "grp_viewer", MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}},
			"migrator":   {Name: "migrator", Login: true, MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}},
		}
		if m == roleAbsent {
			delete(roles, "migrator")
		}
		return &catalog.State{
			CurrentUser: "master",
			Roles:       roles,
			Databases: map[string]*catalog.Database{
				"app": {Name: "app", Owner: "master", AllowConn: true, ACL: catalog.ACL{},
					Schemas: map[string]*catalog.Schema{
						"public": {Name: "public", Owner: "master", ACL: catalog.ACL{},
							Relations:  map[string]*catalog.Relation{},
							DefaultACL: map[catalog.DefaultACLKey]catalog.ACL{}},
					}},
			},
		}
	}

	const (
		borrow     = `GRANT "migrator" TO CURRENT_USER WITH INHERIT TRUE`
		undoAll    = `REVOKE "migrator" FROM CURRENT_USER`
		undoOption = `REVOKE INHERIT OPTION FOR "migrator" FROM CURRENT_USER`
	)
	for _, c := range []struct {
		name       string
		membership membership
		wantBorrow bool
		wantUndo   string
	}{
		// Nothing was held, so the whole membership goes back.
		{name: "no membership", membership: none, wantBorrow: true, wantUndo: undoAll},
		// Only the inherit bit was added, so only it comes off.
		{name: "admin option only", membership: adminOnly, wantBorrow: true, wantUndo: undoOption},
		// CREATE ROLE has already made the executing user an admin member by
		// the time the undo runs, even though the snapshot predates it.
		{name: "creator role created by this plan", membership: roleAbsent, wantBorrow: true, wantUndo: undoOption},
		// Already inheriting: no borrow, and the leftover is handed back.
		{name: "inheriting membership", membership: inheriting, wantBorrow: false, wantUndo: undoOption},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, err := plan.Diff(normalized, newState(c.membership))
			if err != nil {
				t.Fatal(err)
			}
			var sql []string
			for _, s := range p.Statements {
				sql = append(sql, s.SQL)
			}
			joined := strings.Join(sql, "\n")
			if !strings.Contains(joined, "ALTER DEFAULT PRIVILEGES FOR ROLE") {
				t.Fatalf("expected a default privilege statement, got:\n%s", joined)
			}
			if got := strings.Contains(joined, borrow); got != c.wantBorrow {
				t.Fatalf("borrow present = %t, want %t; statements:\n%s", got, c.wantBorrow, joined)
			}
			if !strings.Contains(joined, c.wantUndo) {
				t.Fatalf("want %q; statements:\n%s", c.wantUndo, joined)
			}
			if c.wantUndo == undoOption && strings.Contains(joined, undoAll+";") {
				t.Fatalf("the whole membership was revoked; statements:\n%s", joined)
			}
		})
	}
}

// TestStaleBorrowIsReleased pins the convergence promise where apply is not
// atomic: an inheriting membership the executing user holds in a managed role
// without the declaration asking for it must be handed back, because nothing
// else would ever notice it.
func TestStaleBorrowIsReleased(t *testing.T) {
	cases := []struct {
		name string
		// creates is the creator's creates_objects_in; dropping it removes the
		// creator from the default-privilege keys entirely.
		creates []string
		// inherits is what the executing user already inherits.
		inherits []string
		// defaultACL seeds pg_default_acl for the creator.
		defaultACL bool

		wantRelease  bool
		wantDatabase string
		wantReclaim  bool
	}{
		{
			// A borrow a failed apply left behind: the default privileges
			// still rely on it, so the release follows them and only gives
			// back what pgroledef took.
			name:    "borrow left behind by an earlier apply",
			creates: []string{"app.public"}, inherits: []string{"migrator"}, defaultACL: true,
			wantRelease: true, wantDatabase: "app", wantReclaim: true,
		},
		{
			// The declaration no longer names the creator, so nothing in the
			// plan relies on the membership and it is not attributable to a
			// borrow: cluster-level, and gated by --allow-destroy.
			name:        "creator no longer creates objects",
			inherits:    []string{"migrator"},
			wantRelease: true, wantDatabase: "", wantReclaim: false,
		},
		{
			// Aurora grants the master an inheriting membership in
			// rds_superuser. It is not declared, so it is not ours to touch.
			name:     "membership in an undeclared role is left alone",
			inherits: []string{"rds_superuser"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{
				Version: 1,
				Target:  config.Target{Engine: config.EngineAuroraPostgres, Identifier: "staging"},
				Policy:  config.DefaultPolicy(),
				Roles: []config.Role{
					{Name: "grp_viewer", Grants: []config.RoleGrant{
						{On: config.GrantTarget{AllTablesInSchema: "app.public"}, Privileges: []config.Privilege{config.PrivSelect}},
					}},
					{Name: "migrator", Login: true, CreatesObjectsIn: c.creates},
				},
			}
			normalized, err := config.Validate(cfg)
			if err != nil {
				t.Fatal(err)
			}
			me := &catalog.Role{Name: "master", Login: true, MemberOf: map[string]bool{},
				InheritsFrom: map[string]bool{}}
			for _, r := range c.inherits {
				me.MemberOf[r] = true
				me.InheritsFrom[r] = true
			}
			defaultACL := map[catalog.DefaultACLKey]catalog.ACL{}
			if c.defaultACL {
				defaultACL[catalog.DefaultACLKey{ForRole: "migrator", ObjType: "tables"}] =
					catalog.ACL{"grp_viewer": catalog.PrivSet{"SELECT": true}}
			}
			st := &catalog.State{
				CurrentUser: "master",
				Roles: map[string]*catalog.Role{
					"master":        me,
					"rds_superuser": {Name: "rds_superuser", MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}},
					"grp_viewer":    {Name: "grp_viewer", MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}},
					"migrator":      {Name: "migrator", Login: true, MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}},
				},
				Databases: map[string]*catalog.Database{
					"app": {Name: "app", Owner: "master", AllowConn: true, ACL: catalog.ACL{},
						Schemas: map[string]*catalog.Schema{
							"public": {Name: "public", Owner: "master", ACL: catalog.ACL{},
								Relations:  map[string]*catalog.Relation{},
								DefaultACL: defaultACL},
						}},
				},
			}
			p, err := plan.Diff(normalized, st)
			if err != nil {
				t.Fatal(err)
			}
			var found *plan.Statement
			for i, s := range p.Statements {
				if strings.HasPrefix(s.SQL, "REVOKE INHERIT OPTION FOR") {
					found = &p.Statements[i]
				}
			}
			if !c.wantRelease {
				if found != nil {
					t.Fatalf("released a membership it does not own: %q", found.SQL)
				}
				return
			}
			if found == nil {
				t.Fatalf("the membership was not released; statements: %v", p.Statements)
			}
			if !found.Destructive {
				t.Fatal("a revoke has to read as destructive")
			}
			if found.Database != c.wantDatabase {
				t.Fatalf("release ran in %q, want %q", found.Database, c.wantDatabase)
			}
			if found.Reclaim != c.wantReclaim {
				t.Fatalf("Reclaim = %t, want %t", found.Reclaim, c.wantReclaim)
			}
			// Recovering from a half-applied run must not also unlock every
			// other revoke in the plan.
			if got := p.NeedsAllowDestroy(); got == c.wantReclaim {
				t.Fatalf("NeedsAllowDestroy() = %t with Reclaim = %t", got, c.wantReclaim)
			}
		})
	}
}
