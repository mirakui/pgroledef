package plan_test

import (
	"strings"
	"testing"

	"github.com/mirakui/pgroledef/internal/catalog"
	"github.com/mirakui/pgroledef/internal/config"
	"github.com/mirakui/pgroledef/internal/plan"
)

// TestDatabaseGrantsAreEngineSpecific covers the authoritative revoke path,
// which does not go through validate: a managed role holding a database
// privilege produces REVOKE ... ON DATABASE on Aurora, and must produce
// nothing on DSQL, where GRANT has no ON DATABASE form at all.
func TestDatabaseGrantsAreEngineSpecific(t *testing.T) {
	cases := []struct {
		name       string
		engine     config.Engine
		database   string
		wantRevoke bool
	}{
		{name: "aurora revokes it", engine: config.EngineAuroraPostgres, database: "app", wantRevoke: true},
		{name: "dsql cannot", engine: config.EngineDSQL, database: config.DSQLDatabase, wantRevoke: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			schema := c.database + ".public"
			cfg := &config.Config{
				Version: 1,
				Target:  config.Target{Engine: c.engine, Identifier: "x"},
				Policy:  config.DefaultPolicyFor(c.engine),
				Roles: []config.Role{{Name: "app", Login: true, Grants: []config.RoleGrant{
					{On: config.GrantTarget{Schema: schema}, Privileges: []config.Privilege{config.PrivUsage}},
				}}},
			}
			normalized, err := config.Validate(cfg)
			if err != nil {
				t.Fatal(err)
			}
			st := &catalog.State{
				CurrentUser: "master",
				Roles: map[string]*catalog.Role{
					"master": {Name: "master", Login: true, Super: true, MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}},
					"app":    {Name: "app", Login: true, MemberOf: map[string]bool{}, InheritsFrom: map[string]bool{}},
				},
				Databases: map[string]*catalog.Database{
					c.database: {
						Name: c.database, Owner: "master", AllowConn: true,
						// An undeclared privilege the role picked up by hand.
						ACL: catalog.ACL{"app": catalog.PrivSet{"CONNECT": true}},
						Schemas: map[string]*catalog.Schema{
							"public": {Name: "public", Owner: "master",
								ACL:        catalog.ACL{"app": catalog.PrivSet{"USAGE": true}},
								Relations:  map[string]*catalog.Relation{},
								DefaultACL: map[catalog.DefaultACLKey]catalog.ACL{}},
						},
					},
				},
			}
			p, err := plan.Diff(normalized, st)
			if err != nil {
				t.Fatal(err)
			}
			var sql []string
			for _, s := range p.Statements {
				sql = append(sql, s.SQL)
			}
			joined := strings.Join(sql, "\n")
			if got := strings.Contains(joined, "ON DATABASE"); got != c.wantRevoke {
				t.Fatalf("ON DATABASE statement present = %t, want %t; statements:\n%s", got, c.wantRevoke, joined)
			}
		})
	}
}
