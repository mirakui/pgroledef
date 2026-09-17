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
	for _, d := range cfg.DefaultPrivileges {
		got = append(got, d.ForRole+"/"+string(d.On)+"/"+d.To)
	}
	want := []string{
		"shopfront_migrator/sequences/grp_shopfront_writer",
		"shopfront_migrator/tables/grp_shopfront_reader",
		"shopfront_migrator/tables/grp_shopfront_writer",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("derived default privileges = %v, want %v", got, want)
	}
	for _, d := range cfg.DefaultPrivileges {
		if d.ForRole != "shopfront_migrator" {
			t.Fatalf("FOR ROLE must be the declared creator, got %q", d.ForRole)
		}
	}
}
