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
// atomic: a borrow a failed run left behind must be handed back, because
// nothing else would ever notice it.
func TestStaleBorrowIsReleased(t *testing.T) {
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
	st := &catalog.State{
		CurrentUser: "master",
		Roles: map[string]*catalog.Role{
			"master": {Name: "master", Login: true, MemberOf: map[string]bool{"migrator": true},
				InheritsFrom: map[string]bool{"migrator": true}},
			"grp_viewer": {Name: "grp_viewer", MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}},
			"migrator":   {Name: "migrator", Login: true, MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}},
		},
		Databases: map[string]*catalog.Database{
			"app": {Name: "app", Owner: "master", AllowConn: true, ACL: catalog.ACL{},
				Schemas: map[string]*catalog.Schema{
					"public": {Name: "public", Owner: "master", ACL: catalog.ACL{},
						Relations: map[string]*catalog.Relation{},
						DefaultACL: map[catalog.DefaultACLKey]catalog.ACL{
							{ForRole: "migrator", ObjType: "tables"}: {"grp_viewer": catalog.PrivSet{"SELECT": true}},
						}},
				}},
		},
	}
	p, err := plan.Diff(normalized, st)
	if err != nil {
		t.Fatal(err)
	}
	// The default privileges already match, so the release is the only change.
	var found *plan.Statement
	for i, s := range p.Statements {
		if strings.HasPrefix(s.SQL, "REVOKE INHERIT OPTION FOR") {
			found = &p.Statements[i]
		}
	}
	if found == nil {
		t.Fatalf("the leftover membership was not released; statements: %v", p.Statements)
	}
	if !found.Destructive {
		t.Fatal("releasing a membership is destructive and must need --allow-destroy")
	}
	if found.Database != "app" {
		t.Fatalf("release ran in %q, want the database whose default privileges used it", found.Database)
	}
}
