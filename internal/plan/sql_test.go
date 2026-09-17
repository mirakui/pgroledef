package plan

import (
	"strings"
	"testing"
)

func TestWriteSQL(t *testing.T) {
	p := &Plan{Statements: []Statement{
		{Database: "", SQL: `CREATE ROLE "grp_viewer" WITH NOLOGIN`},
		{Database: "", SQL: `REVOKE "grp_viewer" FROM "app_ro"`, Destructive: true, Note: "membership not declared"},
		{Database: "app", SQL: `GRANT USAGE ON SCHEMA "public" TO "grp_viewer"`},
	}}
	var b strings.Builder
	if err := WriteSQL(p, &b); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	for _, want := range []string{
		"-- cluster (current database)",
		"CREATE ROLE \"grp_viewer\" WITH NOLOGIN;\n",
		"REVOKE \"grp_viewer\" FROM \"app_ro\";  -- destructive: membership not declared\n",
		"\\connect \"app\"\n",
		"GRANT USAGE ON SCHEMA \"public\" TO \"grp_viewer\";\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\n+ ") || strings.Contains(got, "\n- ") {
		t.Errorf("output must not carry plan markers:\n%s", got)
	}
	// The cluster block must come before any \connect.
	if strings.Index(got, "CREATE ROLE") > strings.Index(got, "\\connect") {
		t.Errorf("cluster statements must come first:\n%s", got)
	}
}

func TestWriteSQLEmptyPlan(t *testing.T) {
	var b strings.Builder
	if err := WriteSQL(&Plan{}, &b); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if !strings.Contains(got, "No changes.") {
		t.Errorf("empty plan should say so:\n%s", got)
	}
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if !strings.HasPrefix(line, "--") {
			t.Errorf("empty plan must contain comments only, got %q", line)
		}
	}
}
