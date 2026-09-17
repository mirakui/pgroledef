package plan_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mirakui/pgroledef/internal/catalog"
	"github.com/mirakui/pgroledef/internal/config"
	"github.com/mirakui/pgroledef/internal/plan"
)

// TestReconcileRoundTrip needs a live PostgreSQL (docker compose up -d) and
// PGROLEDEF_TEST_DSN. It creates a throwaway database plus uniquely named
// roles, applies a declaration, checks plan is a no-op, then tightens the
// declaration and checks that the destructive plan applies and converges.
func TestReconcileRoundTrip(t *testing.T) {
	dsn := os.Getenv("PGROLEDEF_TEST_DSN")
	if dsn == "" {
		t.Skip("PGROLEDEF_TEST_DSN not set")
	}
	ctx := context.Background()
	connector, err := catalog.NewDSNConnector(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := connector.Connect(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)

	suffix := fmt.Sprintf("t%d", time.Now().UnixNano()%1e9)
	db := "pgroledef_" + suffix
	viewer, editor, app := "viewer_"+suffix, "editor_"+suffix, "app_"+suffix
	mustExec(t, admin, `CREATE DATABASE `+ident(db))
	// Aurora ships rds_iam; plain PostgreSQL does not.
	_, _ = admin.Exec(ctx, `CREATE ROLE rds_iam`)
	t.Cleanup(func() {
		for _, r := range []string{app, editor, viewer} {
			_, _ = admin.Exec(ctx, `DROP OWNED BY `+ident(r))
		}
		_, _ = admin.Exec(ctx, `DROP DATABASE `+ident(db)+` WITH (FORCE)`)
		for _, r := range []string{app, editor, viewer} {
			_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS `+ident(r))
		}
	})
	dconn, err := connector.Connect(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, dconn, `CREATE TABLE t1 (id serial PRIMARY KEY)`)
	dconn.Close(ctx)

	schema := db + ".public"
	cfg := &config.Config{
		Version: 1,
		Target:  config.Target{Engine: config.EngineAuroraPostgres, Identifier: "test"},
		Roles: []config.Role{
			{Name: viewer},
			{Name: editor, MemberOf: []string{viewer}},
			{Name: app, Login: true, MemberOf: []string{editor}, IAM: &config.IAM{Enabled: true}, CreatesObjectsIn: []string{schema}},
		},
		Grants: []config.Grant{
			{On: config.GrantTarget{Database: db}, To: viewer, Privileges: []config.Privilege{config.PrivConnect}},
			{On: config.GrantTarget{Schema: schema}, To: viewer, Privileges: []config.Privilege{config.PrivUsage}},
			{On: config.GrantTarget{Schema: schema}, To: editor, Privileges: []config.Privilege{config.PrivUsage, config.PrivCreate}},
			{On: config.GrantTarget{AllTablesInSchema: schema}, To: viewer, Privileges: []config.Privilege{config.PrivSelect}},
			{On: config.GrantTarget{AllTablesInSchema: schema}, To: editor, Privileges: []config.Privilege{config.PrivSelect, config.PrivInsert, config.PrivUpdate, config.PrivDelete}},
			{On: config.GrantTarget{AllSequencesInSchema: schema}, To: editor, Privileges: []config.Privilege{config.PrivUsage, config.PrivSelect}},
		},
	}
	cfg.Policy = config.DefaultPolicy()
	normalized := validate(t, cfg)

	p := build(t, ctx, normalized, connector)
	if p.Empty() {
		t.Fatal("first plan should create roles and grants")
	}
	for _, s := range p.Statements {
		if s.Destructive {
			t.Fatalf("first plan must not be destructive: %s", s.SQL)
		}
	}
	if err := plan.Apply(ctx, p, connector, io.Discard); err != nil {
		t.Fatal(err)
	}
	if p := build(t, ctx, normalized, connector); !p.Empty() {
		t.Fatalf("plan after apply should be empty, got:\n%s", dump(p))
	}

	// A table created later by the migration role must already carry the
	// derived default privileges, so the plan stays empty.
	dconn, err = connector.Connect(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, dconn, `SET ROLE `+ident(app))
	mustExec(t, dconn, `CREATE TABLE t2 (id serial PRIMARY KEY)`)
	dconn.Close(ctx)
	if p := build(t, ctx, normalized, connector); !p.Empty() {
		t.Fatalf("default privileges did not cover a table created by the creator role:\n%s", dump(p))
	}

	// Tighten: drop the sequence grant and make app NOLOGIN -> destructive plan.
	tight := *cfg
	tight.Grants = cfg.Grants[:len(cfg.Grants)-1]
	tight.Roles = append([]config.Role(nil), cfg.Roles...)
	for i := range tight.Roles {
		if tight.Roles[i].Name == app {
			tight.Roles[i].Login = false
		}
	}
	tightN := validate(t, &tight)
	p = build(t, ctx, tightN, connector)
	var sawRevoke, sawNologin bool
	for _, s := range p.Statements {
		if !s.Destructive {
			t.Fatalf("tightened plan should only revoke, got: %s", s.SQL)
		}
		sawRevoke = sawRevoke || strings.HasPrefix(s.SQL, "REVOKE") || strings.Contains(s.SQL, " REVOKE ")
		sawNologin = sawNologin || strings.Contains(s.SQL, "NOLOGIN")
	}
	if !sawRevoke || !sawNologin {
		t.Fatalf("expected REVOKE and NOLOGIN statements, got:\n%s", dump(p))
	}
	if err := plan.Apply(ctx, p, connector, io.Discard); err != nil {
		t.Fatal(err)
	}
	if p := build(t, ctx, tightN, connector); !p.Empty() {
		t.Fatalf("plan after destructive apply should be empty, got:\n%s", dump(p))
	}
}

func validate(t *testing.T, c *config.Config) *config.Config {
	t.Helper()
	n, err := config.Validate(c)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func build(t *testing.T, ctx context.Context, c *config.Config, conn catalog.Connector) *plan.Plan {
	t.Helper()
	p, err := plan.Build(ctx, c, conn)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func dump(p *plan.Plan) string {
	var b strings.Builder
	for _, s := range p.Statements {
		fmt.Fprintf(&b, "[%s] %s\n", s.Database, s.SQL)
	}
	return b.String()
}

func mustExec(t *testing.T, conn *pgx.Conn, sql string) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func ident(s string) string { return pgx.Identifier{s}.Sanitize() }
