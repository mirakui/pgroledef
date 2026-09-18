// Package termcolor renders the small set of ANSI styles the plan output uses,
// and decides whether they should be emitted at all.
package termcolor

import (
	"io"
	"os"
	"strings"
)

// Style is one SGR parameter. Several of them combine into a single escape
// sequence, so a bold green line costs one sequence rather than two.
type Style string

// The styles, in the shape terraform uses: green for additions, red for
// removals, yellow for in-place changes.
const (
	Bold   Style = "1"
	Dim    Style = "2"
	Red    Style = "31"
	Green  Style = "32"
	Yellow Style = "33"
)

const reset = "\x1b[0m"

// Palette wraps text in ANSI styles, or returns it untouched when colour is
// disabled. A nil *Palette is a disabled one, so callers may leave it unset.
type Palette struct {
	enabled bool
}

// New returns a palette that styles text only when enabled.
func New(enabled bool) *Palette { return &Palette{enabled: enabled} }

// Enabled reports whether the palette emits escape sequences.
func (p *Palette) Enabled() bool { return p != nil && p.enabled }

// Paint wraps s in styles, applied as one escape sequence.
func (p *Palette) Paint(s string, styles ...Style) string {
	if !p.Enabled() || len(styles) == 0 {
		return s
	}
	codes := make([]string, len(styles))
	for i, st := range styles {
		codes[i] = string(st)
	}
	return "\x1b[" + strings.Join(codes, ";") + "m" + s + reset
}

// Add styles an added line (green).
func (p *Palette) Add(s string) string { return p.Paint(s, Green) }

// Remove styles a removed or destructive line (red).
func (p *Palette) Remove(s string) string { return p.Paint(s, Red) }

// Change styles an in-place change (yellow).
func (p *Palette) Change(s string) string { return p.Paint(s, Yellow) }

// Bold styles a heading.
func (p *Palette) Bold(s string) string { return p.Paint(s, Bold) }

// Dim styles secondary text, such as a trailing SQL comment.
func (p *Palette) Dim(s string) string { return p.Paint(s, Dim) }

// Detect reports whether w should be coloured. The environment can forbid
// colour outright (NO_COLOR, TERM=dumb) or ask for it even when the output is
// not a terminal (FORCE_COLOR, CLICOLOR_FORCE), which is how colour reaches a
// CI log viewer through a pipe.
func Detect(w io.Writer) bool {
	if !envAllowsColor() {
		return false
	}
	return envForcesColor() || isTerminal(w)
}

// envAllowsColor reports whether the environment permits colour at all. An
// empty NO_COLOR counts as unset, as no-color.org specifies.
func envAllowsColor() bool {
	return os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}

// envForcesColor reports whether colour was asked for regardless of the
// output. Both variables treat "0" as off, the way the tools that introduced
// them do.
func envForcesColor() bool {
	for _, name := range []string{"FORCE_COLOR", "CLICOLOR_FORCE"} {
		switch os.Getenv(name) {
		case "", "0":
		default:
			return true
		}
	}
	return false
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
