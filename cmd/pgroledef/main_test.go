package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func subcommand(t *testing.T, name string) *cobra.Command {
	t.Helper()
	for _, c := range newRootCmd().Commands() {
		if c.Name() == name {
			return c
		}
	}
	t.Fatalf("command %q is not registered", name)
	return nil
}

// TestConnectionFlagShorthands pins the psql-compatible spelling, -h included:
// cobra would otherwise claim -h for --help.
func TestConnectionFlagShorthands(t *testing.T) {
	want := map[string]string{"h": "host", "p": "port", "U": "username", "d": "dbname"}
	for _, name := range []string{"plan", "apply"} {
		t.Run(name, func(t *testing.T) {
			cmd := subcommand(t, name)
			cmd.InitDefaultHelpFlag()
			for short, long := range want {
				f := cmd.Flags().ShorthandLookup(short)
				if f == nil {
					t.Errorf("-%s is not defined", short)
					continue
				}
				if f.Name != long {
					t.Errorf("-%s is %q, want %q", short, f.Name, long)
				}
			}
			if f := cmd.Flags().Lookup("help"); f == nil || f.Shorthand != "" {
				t.Errorf("--help must keep no shorthand, got %+v", f)
			}
		})
	}
}

// TestOfflineCommandsKeepHelpShorthand makes sure only the commands that
// connect gave -h away.
func TestOfflineCommandsKeepHelpShorthand(t *testing.T) {
	for _, name := range []string{"render", "validate"} {
		t.Run(name, func(t *testing.T) {
			cmd := subcommand(t, name)
			cmd.InitDefaultHelpFlag()
			f := cmd.Flags().ShorthandLookup("h")
			if f == nil || f.Name != "help" {
				t.Fatalf("-h should still be help, got %+v", f)
			}
		})
	}
}

// TestPlanHelp checks that --help still prints usage rather than trying to
// connect, now that the flag is registered by hand.
func TestPlanHelp(t *testing.T) {
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"plan", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("plan --help failed: %v", err)
	}
	for _, want := range []string{"-h, --host", "-U, --username", "-d, --dbname", "-p, --port"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage does not document %q:\n%s", want, out.String())
		}
	}
}
