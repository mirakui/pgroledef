package termcolor_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/mirakui/pgroledef/internal/termcolor"
)

func TestPaletteEnabled(t *testing.T) {
	p := termcolor.New(true)
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"add", p.Add("x"), "\x1b[32mx\x1b[0m"},
		{"remove", p.Remove("x"), "\x1b[31mx\x1b[0m"},
		{"change", p.Change("x"), "\x1b[33mx\x1b[0m"},
		{"bold", p.Bold("x"), "\x1b[1mx\x1b[0m"},
		{"dim", p.Dim("x"), "\x1b[2mx\x1b[0m"},
		{"combined", p.Paint("x", termcolor.Bold, termcolor.Green), "\x1b[1;32mx\x1b[0m"},
		{"no style", p.Paint("x"), "x"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestPaletteDisabled(t *testing.T) {
	for _, p := range []*termcolor.Palette{termcolor.New(false), nil} {
		if p.Enabled() {
			t.Error("palette should be disabled")
		}
		got := []string{p.Add("x"), p.Remove("x"), p.Change("x"), p.Bold("x"), p.Dim("x"), p.Paint("x", termcolor.Bold, termcolor.Green)}
		for _, s := range got {
			if s != "x" {
				t.Errorf("got %q, want plain %q", s, "x")
			}
		}
	}
}

// TestEnvAllowsColor and TestEnvForcesColor cover the environment half of
// Detect, which needs no terminal and so runs everywhere.
func TestEnvAllowsColor(t *testing.T) {
	cases := []struct {
		name    string
		noColor string
		term    string
		want    bool
	}{
		{"plain terminal", "", "xterm-256color", true},
		{"empty NO_COLOR is unset", "", "xterm-256color", true},
		{"NO_COLOR set", "1", "xterm-256color", false},
		{"NO_COLOR set to anything", "no", "xterm-256color", false},
		{"TERM=dumb", "", "dumb", false},
		{"TERM unset", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", c.noColor)
			t.Setenv("TERM", c.term)
			if got := termcolor.EnvAllowsColor(); got != c.want {
				t.Errorf("EnvAllowsColor() = %t, want %t", got, c.want)
			}
		})
	}
}

func TestEnvForcesColor(t *testing.T) {
	cases := []struct {
		name  string
		force string
		clim  string
		want  bool
	}{
		{"neither set", "", "", false},
		{"FORCE_COLOR", "1", "", true},
		{"FORCE_COLOR=0", "0", "", false},
		{"CLICOLOR_FORCE", "", "1", true},
		{"CLICOLOR_FORCE=0", "", "0", false},
		{"both off", "0", "0", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("FORCE_COLOR", c.force)
			t.Setenv("CLICOLOR_FORCE", c.clim)
			if got := termcolor.EnvForcesColor(); got != c.want {
				t.Errorf("EnvForcesColor() = %t, want %t", got, c.want)
			}
		})
	}
}

func TestIsTerminal(t *testing.T) {
	if termcolor.IsTerminal(&bytes.Buffer{}) {
		t.Error("a non-file writer is not a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // nothing was written, so the close error says nothing
	if termcolor.IsTerminal(f) {
		t.Error("a regular file is not a terminal")
	}

	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		t.Skip("no controlling terminal:", err)
	}
	defer tty.Close() //nolint:errcheck // nothing was written, so the close error says nothing
	if !termcolor.IsTerminal(tty) {
		t.Error("/dev/tty should be detected as a terminal")
	}
}

// TestDetect checks how the two halves combine: a pipe stays plain unless the
// environment forces colour, and NO_COLOR wins over that.
func TestDetect(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	cases := []struct {
		name    string
		noColor string
		force   string
		want    bool
	}{
		{"pipe", "", "", false},
		{"pipe with FORCE_COLOR", "", "1", true},
		{"pipe with FORCE_COLOR and NO_COLOR", "1", "1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", c.noColor)
			t.Setenv("FORCE_COLOR", c.force)
			t.Setenv("CLICOLOR_FORCE", "")
			if got := termcolor.Detect(&bytes.Buffer{}); got != c.want {
				t.Errorf("Detect() = %t, want %t", got, c.want)
			}
		})
	}
}
