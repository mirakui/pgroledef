package plan_test

import (
	"strings"
	"testing"

	"github.com/mirakui/pgroledef/internal/catalog"
	"github.com/mirakui/pgroledef/internal/config"
	"github.com/mirakui/pgroledef/internal/plan"
)

// scenario mirrors the example in the README: grp_viewer already exists but
// holds one privilege too many, migrator needs LOGIN and a new membership,
// worker does not exist yet.
func scenario(t *testing.T) *plan.Plan {
	t.Helper()
	cfg := &config.Config{
		Version: 1,
		Target:  config.Target{Engine: config.EngineAuroraPostgres, Identifier: "staging-shopfront"},
		Policy:  config.DefaultPolicy(),
		Roles: []config.Role{
			{Name: "grp_viewer", Grants: []config.RoleGrant{
				{On: config.GrantTarget{Database: "app"}, Privileges: []config.Privilege{config.PrivConnect}},
				{On: config.GrantTarget{Schema: "app.public"}, Privileges: []config.Privilege{config.PrivUsage}},
				{On: config.GrantTarget{AllTablesInSchema: "app.public"}, Privileges: []config.Privilege{config.PrivSelect}},
			}},
			{Name: "migrator", Login: true, MemberOf: []string{"grp_viewer", "rds_iam"}, CreatesObjectsIn: []string{"app.public"}},
			{Name: "worker", Login: true, Grants: []config.RoleGrant{
				{On: config.GrantTarget{Table: "app.public.jobs"}, Privileges: []config.Privilege{config.PrivSelect, config.PrivInsert}},
			}},
		},
	}
	normalized, err := config.Validate(cfg)
	if err != nil {
		t.Fatal(err)
	}

	table := func(name string, acl catalog.ACL) *catalog.Relation {
		return &catalog.Relation{Name: name, Kind: 'r', Owner: "postgres", ACL: acl}
	}
	st := &catalog.State{
		CurrentUser: "postgres",
		Roles: map[string]*catalog.Role{
			"postgres":   {Name: "postgres", Login: true, Super: true, MemberOf: map[string]bool{}},
			"rds_iam":    {Name: "rds_iam", MemberOf: map[string]bool{}},
			"grp_viewer": {Name: "grp_viewer", MemberOf: map[string]bool{}},
			"migrator":   {Name: "migrator", MemberOf: map[string]bool{"grp_viewer": true}},
		},
		Databases: map[string]*catalog.Database{
			"app": {
				Name:  "app",
				Owner: "postgres",
				ACL:   catalog.ACL{"grp_viewer": catalog.PrivSet{"CONNECT": true}},
				Schemas: map[string]*catalog.Schema{
					"public": {
						Name:  "public",
						Owner: "postgres",
						ACL:   catalog.ACL{"grp_viewer": catalog.PrivSet{"USAGE": true}},
						Relations: map[string]*catalog.Relation{
							"jobs":   table("jobs", catalog.ACL{"grp_viewer": catalog.PrivSet{"SELECT": true}}),
							"orders": table("orders", catalog.ACL{"grp_viewer": catalog.PrivSet{"SELECT": true, "DELETE": true}}),
						},
						DefaultACL: map[catalog.DefaultACLKey]catalog.ACL{},
					},
				},
			},
		},
	}
	p, err := plan.Diff(normalized, st)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const wantDiff = `~ role "grp_viewer"
  - grants on TABLE app.public.orders:
      - DELETE
  + default privileges FOR ROLE migrator IN SCHEMA app.public ON TABLES TO grp_viewer:
      + SELECT

~ role "migrator"
  ~ login:     false -> true
  ~ member_of: [grp_viewer] -> [grp_viewer, rds_iam]

+ role "worker"
  + login:     true
  + grants on TABLE app.public.jobs:
      + INSERT
      + SELECT

`

func TestWriteDiff(t *testing.T) {
	p := scenario(t)
	var b strings.Builder
	p.WriteDiff(&b)
	if b.String() != wantDiff {
		t.Errorf("diff mismatch\n--- got ---\n%s\n--- want ---\n%s", b.String(), wantDiff)
	}
}

func TestEmptyPlanHasNoDiff(t *testing.T) {
	p := &plan.Plan{}
	var b strings.Builder
	p.WriteDiff(&b)
	if b.String() != "" {
		t.Errorf("empty plan should print nothing, got %q", b.String())
	}
}
