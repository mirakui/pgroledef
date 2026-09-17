package config_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirakui/pgroledef/internal/config"
	"github.com/mirakui/pgroledef/internal/jsonnetx"
)

var update = flag.Bool("update", false, "rewrite golden files")

func load(t *testing.T, path string, ext map[string]string) (*config.Config, error) {
	t.Helper()
	raw, err := jsonnetx.EvaluateFile(path, jsonnetx.Options{ExtStrs: ext})
	if err != nil {
		return nil, err
	}
	cfg, err := config.Decode(raw)
	if err != nil {
		return nil, err
	}
	return config.Validate(cfg)
}

// TestInvalid asserts that every testdata/invalid/*.jsonnet is rejected with
// the message recorded in its .want file. This is the contract that typos and
// unsafe declarations fail before any database is touched.
func TestInvalid(t *testing.T) {
	files, err := filepath.Glob("../../testdata/invalid/*.jsonnet")
	if err != nil || len(files) == 0 {
		t.Fatalf("no invalid fixtures found: %v", err)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".jsonnet")
		t.Run(name, func(t *testing.T) {
			wantRaw, err := os.ReadFile(strings.TrimSuffix(f, ".jsonnet") + ".want")
			if err != nil {
				t.Fatal(err)
			}
			want := strings.TrimSpace(string(wantRaw))
			_, err = load(t, f, nil)
			if err == nil {
				t.Fatalf("expected validation failure containing %q, got success", want)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error does not contain %q:\n%v", want, err)
			}
		})
	}
}

// TestGoldenRender pins the normalized canonical output of the example,
// including default privileges derived from creates_objects_in.
func TestGoldenRender(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		t.Run(env, func(t *testing.T) {
			cfg, err := load(t, "../../examples/shopfront.jsonnet", map[string]string{"env": env})
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetIndent("", "  ")
			if err := enc.Encode(cfg); err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("../../testdata/golden", "shopfront-"+env+".json")
			if *update {
				if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			if !bytes.Equal(want, buf.Bytes()) {
				t.Fatalf("render differs from %s; run go test ./internal/config -update after reviewing:\n%s", golden, buf.String())
			}
		})
	}
}

func TestDerivedDefaultPrivileges(t *testing.T) {
	cfg, err := load(t, "../../examples/shopfront.jsonnet", map[string]string{"env": "staging"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range cfg.FlatDefaultPrivileges() {
		got = append(got, d.To+"/"+string(d.On)+"/for:"+d.ForRole)
	}
	want := []string{
		"grp_shopfront_reader/tables/for:shopfront_migrator",
		"grp_shopfront_writer/sequences/for:shopfront_migrator",
		"grp_shopfront_writer/tables/for:shopfront_migrator",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("derived default privileges = %v, want %v", got, want)
	}
	for _, r := range cfg.Roles {
		if r.Name == "shopfront_migrator" && len(r.DefaultPrivileges) != 0 {
			t.Fatalf("the creator itself must not receive derived default privileges: %v", r.DefaultPrivileges)
		}
	}
}

// TestCheckServerMajor pins the rules that connect a declaration to a live
// server: supported majors only, a declared version must match, and
// version-gated privileges need a new enough server.
func TestCheckServerMajor(t *testing.T) {
	base := func(pv int, privs ...config.Privilege) *config.Config {
		return &config.Config{
			Version: 1,
			Target:  config.Target{Engine: config.EngineAuroraPostgres, Identifier: "x", PostgresVersion: pv},
			Roles: []config.Role{{Name: "app", Grants: []config.RoleGrant{
				{On: config.GrantTarget{AllTablesInSchema: "db.public"}, Privileges: privs},
			}}},
		}
	}
	cases := []struct {
		name  string
		cfg   *config.Config
		major int
		want  string
	}{
		{"pg16", base(0, config.PrivSelect), 16, ""},
		{"pg17", base(0, config.PrivSelect), 17, ""},
		{"pg18", base(0, config.PrivSelect), 18, ""},
		{"declared matches", base(17, config.PrivSelect), 17, ""},
		{"too old", base(0, config.PrivSelect), 15, "requires 16 or later"},
		{"declared mismatch", base(18, config.PrivSelect), 17, "target.postgres_version is 18 but the server is PostgreSQL 17"},
		{"maintain on 16", base(0, config.PrivMaintain), 16, `privilege "MAINTAIN" requires PostgreSQL 17 or later`},
		{"maintain on 17", base(0, config.PrivMaintain), 17, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := config.CheckServerMajor(tc.cfg, tc.major)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("expected error containing %q, got nil", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error %v does not contain %q", err, tc.want)
			}
		})
	}
	if got := config.MajorFromVersionNum(170004); got != 17 {
		t.Fatalf("MajorFromVersionNum(170004) = %d, want 17", got)
	}
}
