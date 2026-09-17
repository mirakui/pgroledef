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

	newState := func(inherits bool) *catalog.State {
		me := &catalog.Role{Name: "master", Login: true, MemberOf: map[string]bool{"migrator": true},
			InheritsFrom: map[string]bool{}}
		if inherits {
			me.InheritsFrom["migrator"] = true
		}
		return &catalog.State{
			CurrentUser: "master",
			Roles: map[string]*catalog.Role{
				"master":     me,
				"grp_viewer": {Name: "grp_viewer", MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}},
				"migrator":   {Name: "migrator", Login: true, MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}},
			},
			Databases: map[string]*catalog.Database{
				"app": {Name: "app", Owner: "master", ACL: catalog.ACL{}, Schemas: map[string]*catalog.Schema{
					"public": {Name: "public", Owner: "master", ACL: catalog.ACL{},
						Relations:  map[string]*catalog.Relation{},
						DefaultACL: map[catalog.DefaultACLKey]catalog.ACL{}},
				}},
			},
		}
	}

	const borrow = `GRANT "migrator" TO CURRENT_USER WITH INHERIT TRUE`
	for _, c := range []struct {
		name       string
		inherits   bool
		wantBorrow bool
	}{
		{name: "admin option only", inherits: false, wantBorrow: true},
		{name: "inheriting membership", inherits: true, wantBorrow: false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, err := plan.Diff(normalized, newState(c.inherits))
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
		})
	}
}
