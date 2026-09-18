package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/mirakui/pgroledef/internal/catalog"
	"github.com/mirakui/pgroledef/internal/config"
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
	want := map[string]string{"h": "host", "p": "port", "U": "username", "d": "dbname", "W": "password", "w": "no-password"}
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
	for _, want := range []string{"-h, --host", "-U, --username", "-d, --dbname", "-p, --port", "-W, --password", "-w, --no-password"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage does not document %q:\n%s", want, out.String())
		}
	}
}

// TestPasswordFlagRejectsTokenAuth pins the combination that cannot mean
// anything: an IAM token is signed, never typed. The message has to name what
// the user actually wrote, so an --auth they never gave is described as the
// engine's default instead.
func TestPasswordFlagRejectsTokenAuth(t *testing.T) {
	for _, tc := range []struct {
		name   string
		auth   string
		engine config.Engine
		want   string
	}{
		{
			name:   "explicit --auth",
			auth:   "rds-iam",
			engine: config.EngineAuroraPostgres,
			want:   "--password cannot be used with --auth rds-iam",
		},
		{
			name:   "the engine's default",
			engine: config.EngineDSQL,
			want:   "--password cannot be used with the dsql-admin token mode, the default for engine dsql",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Registering the flags resets the variables they bind, so build
			// the command before setting them.
			cmd := subcommand(t, "plan")
			t.Cleanup(func() { flagPassword, flagAuth = false, "" })
			flagPassword, flagAuth = true, tc.auth

			_, err := newConnector(cmd, &config.Config{Target: config.Target{Engine: tc.engine}})
			if err == nil {
				t.Fatal("newConnector(): got nil error, want a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestNoPromptWithoutATerminal pins the guard the README leans on: a pipe or a
// CI runner has nobody to ask, so the run must fail with the server's own
// error instead of blocking on a prompt. The other side of the guard — a
// prompt actually being installed — needs a tty, which go test has not got.
func TestNoPromptWithoutATerminal(t *testing.T) {
	for _, tc := range []struct {
		name       string
		password   bool
		noPassword bool
		wantErr    string
	}{
		{name: "left to the server"},
		{name: "--password", password: true, wantErr: "--password needs a terminal to read from"},
		{name: "--no-password", noPassword: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := subcommand(t, "plan")
			cmd.SetIn(&bytes.Buffer{})
			t.Cleanup(func() { flagPassword, flagNoPassword = false, false })
			flagPassword, flagNoPassword = tc.password, tc.noPassword

			c, err := newConnector(cmd, &config.Config{Target: config.Target{Engine: config.EngineAuroraPostgres}})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("newConnector() error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			dsn, ok := c.(*catalog.DSNConnector)
			if !ok {
				t.Fatalf("newConnector() returned %T, want *catalog.DSNConnector", c)
			}
			if dsn.Prompt != nil {
				t.Error("a prompt was installed without a terminal to read it from")
			}
		})
	}
}

// TestPasswordFlagsAreMutuallyExclusive: -W and -w ask for opposite things.
func TestPasswordFlagsAreMutuallyExclusive(t *testing.T) {
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"plan", "-f", "examples/shopfront.jsonnet", "-W", "-w"})
	err := root.Execute()
	if err == nil {
		t.Fatal("plan -W -w: got nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "password") || !strings.Contains(err.Error(), "no-password") {
		t.Errorf("error = %v, want it to name both flags", err)
	}
}
