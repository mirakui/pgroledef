package plan_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mirakui/pgroledef/internal/awsauth"
	"github.com/mirakui/pgroledef/internal/config"
	"github.com/mirakui/pgroledef/internal/conninfo"
	"github.com/mirakui/pgroledef/internal/plan"
)

// TestDSQLReconcileRoundTrip needs a live Aurora DSQL cluster and AWS
// credentials allowing dsql:DbConnectAdmin on it:
//
//	PGROLEDEF_TEST_DSQL_ENDPOINT=<cluster-id>.dsql.<region>.on.aws
//	PGROLEDEF_TEST_DSQL_IAM_ARN=arn:aws:iam::<account>:role/<role>   # optional
//
// It creates a uniquely named schema and roles, applies a declaration, checks
// that the plan is then empty, and tightens the declaration to exercise
// REVOKE and AWS IAM REVOKE. DSQL applies one statement per transaction, so a
// failure here can leave objects behind; the cleanup is best-effort.
func TestDSQLReconcileRoundTrip(t *testing.T) {
	endpoint := os.Getenv("PGROLEDEF_TEST_DSQL_ENDPOINT")
	if endpoint == "" {
		t.Skip("PGROLEDEF_TEST_DSQL_ENDPOINT not set")
	}
	iamARN := os.Getenv("PGROLEDEF_TEST_DSQL_IAM_ARN")
	ctx := context.Background()
	co := conninfo.Options{DSN: "postgres://admin@" + endpoint + ":5432/" + config.DSQLDatabase}
	resolved, err := co.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	connector, err := awsauth.NewConnector(ctx, awsauth.Options{
		Resolved: resolved,
		Mode:     awsauth.ModeDSQLAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := connector.Connect(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	// Registered first so it runs last; see the note in the Aurora test.
	t.Cleanup(func() { admin.Close(ctx) }) //nolint:errcheck // nothing to do about a failed close

	suffix := fmt.Sprintf("t%d", time.Now().UnixNano()%1e9)
	nsp := "pgroledef_" + suffix
	viewer, editor, app := "viewer_"+suffix, "editor_"+suffix, "app_"+suffix
	// DSQL allows one DDL statement per transaction, so every setup and
	// teardown statement runs on its own.
	mustExec(t, admin, `CREATE SCHEMA `+ident(nsp))
	mustExec(t, admin, `CREATE TABLE `+ident(nsp)+"."+ident("t1")+` (id int PRIMARY KEY)`)
	t.Cleanup(func() {
		// DROP OWNED BY is unsupported here ("unsupported statement:
		// DropOwned"), so the schema has to go first: it takes the schema and
		// table ACLs and the pg_default_acl rows with it, and a role that
		// still holds any of those cannot be dropped.
		_, _ = admin.Exec(ctx, `DROP TABLE `+ident(nsp)+"."+ident("t1"))
		_, _ = admin.Exec(ctx, `DROP SCHEMA `+ident(nsp))
		for _, r := range []string{app, editor, viewer} {
			if iamARN != "" {
				_, _ = admin.Exec(ctx, `AWS IAM REVOKE `+ident(r)+` FROM '`+iamARN+`'`)
			}
			if _, err := admin.Exec(ctx, `DROP ROLE `+ident(r)); err != nil {
				// Leaking a role is not a test failure, but it is worth saying
				// so: the cluster is shared and roles accumulate.
				t.Logf("could not drop role %s, please remove it by hand: %v", r, err)
			}
		}
	})

	schema := config.DSQLDatabase + "." + nsp
	appRole := config.Role{Name: app, Login: true, MemberOf: []string{editor}, CreatesObjectsIn: []string{schema}}
	if iamARN != "" {
		appRole.IAMPrincipals = []string{iamARN}
	}
	cfg := &config.Config{
		Version: 1,
		Target:  config.Target{Engine: config.EngineDSQL, Identifier: "test"},
		Policy:  config.DefaultPolicyFor(config.EngineDSQL),
		Roles: []config.Role{
			{Name: viewer, Grants: []config.RoleGrant{
				{On: config.GrantTarget{Schema: schema}, Privileges: []config.Privilege{config.PrivUsage}},
				{On: config.GrantTarget{AllTablesInSchema: schema}, Privileges: []config.Privilege{config.PrivSelect}},
			}},
			{Name: editor, MemberOf: []string{viewer}, Grants: []config.RoleGrant{
				{On: config.GrantTarget{Schema: schema}, Privileges: []config.Privilege{config.PrivUsage, config.PrivCreate}},
				{On: config.GrantTarget{AllTablesInSchema: schema}, Privileges: []config.Privilege{config.PrivSelect, config.PrivInsert, config.PrivUpdate, config.PrivDelete}},
			}},
			appRole,
		},
	}
	normalized := validate(t, cfg)

	p := build(t, ctx, normalized, connector)
	if p.Empty() {
		t.Fatal("first plan should create roles and grants")
	}
	if p.Dialect.Atomic() {
		t.Fatal("a dsql plan must not claim to apply atomically")
	}
	for _, s := range p.Statements {
		if s.Destructive {
			t.Fatalf("first plan must not be destructive: %s", s.SQL)
		}
	}
	if iamARN != "" {
		var sawIAMGrant bool
		for _, s := range p.Statements {
			sawIAMGrant = sawIAMGrant || strings.HasPrefix(s.SQL, "AWS IAM GRANT")
		}
		if !sawIAMGrant {
			t.Fatalf("expected an AWS IAM GRANT statement, got:\n%s", dump(p))
		}
	}
	if err := plan.Apply(ctx, p, connector, io.Discard); err != nil {
		t.Fatal(err)
	}
	if p := build(t, ctx, normalized, connector); !p.Empty() {
		t.Fatalf("plan after apply should be empty, got:\n%s", dump(p))
	}

	// Tighten: drop the viewer's table grant and the app's IAM mapping.
	tight := *cfg
	tight.Roles = append([]config.Role(nil), cfg.Roles...)
	for i := range tight.Roles {
		switch tight.Roles[i].Name {
		case viewer:
			g := tight.Roles[i].Grants
			tight.Roles[i].Grants = g[:len(g)-1]
		case app:
			tight.Roles[i].IAMPrincipals = nil
		}
	}
	tightN := validate(t, &tight)
	p = build(t, ctx, tightN, connector)
	if p.Empty() {
		t.Fatal("tightened plan should revoke")
	}
	if err := plan.Apply(ctx, p, connector, io.Discard); err != nil {
		t.Fatal(err)
	}
	if p := build(t, ctx, tightN, connector); !p.Empty() {
		t.Fatalf("plan after destructive apply should be empty, got:\n%s", dump(p))
	}
}
