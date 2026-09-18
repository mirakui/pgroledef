package plan

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/mirakui/pgroledef/internal/termcolor"
)

// RoleDiff is the human-readable, declaration-shaped change for one role:
// what the database has now versus what the file declares. It carries the same
// information as the statements, grouped the way the declaration is written.
type RoleDiff struct {
	Name    string
	Created bool // the role does not exist yet

	LoginChanged bool
	LoginBefore  bool
	LoginAfter   bool

	MembersChanged bool
	MembersBefore  []string
	MembersAfter   []string

	// Principals are the IAM ARNs mapped to the role; DSQL only.
	PrincipalsChanged bool
	PrincipalsBefore  []string
	PrincipalsAfter   []string

	Privileges []PrivDiff
}

// PrivDiff is the change to one privilege target (a grant target or a default
// privilege entry). Label is already rendered, e.g. "TABLE app.public.jobs" or
// "FOR ROLE migrator IN SCHEMA app.public ON TABLES TO grp_viewer".
type PrivDiff struct {
	Label   string
	Default bool // default privileges rather than a direct grant
	Added   []string
	Removed []string
}

func (d *RoleDiff) empty() bool {
	return !d.Created && !d.LoginChanged && !d.MembersChanged && !d.PrincipalsChanged && len(d.Privileges) == 0
}

// roleDiff returns the diff entry for role, creating it on first use. Entries
// keep declaration order; roles not in the file (possible for default
// privileges whose creator is unmanaged) come last, sorted by name.
func (d *differ) roleDiff(role string) *RoleDiff {
	for i := range d.p.RoleDiffs {
		if d.p.RoleDiffs[i].Name == role {
			return &d.p.RoleDiffs[i]
		}
	}
	d.p.RoleDiffs = append(d.p.RoleDiffs, RoleDiff{Name: role})
	return &d.p.RoleDiffs[len(d.p.RoleDiffs)-1]
}

func (d *differ) addPrivDiff(role string, pd PrivDiff) {
	if len(pd.Added) == 0 && len(pd.Removed) == 0 {
		return
	}
	rd := d.roleDiff(role)
	rd.Privileges = append(rd.Privileges, pd)
}

// sortRoleDiffs orders by declaration order first, then by name, and drops
// entries that ended up with no change.
func (p *Plan) sortRoleDiffs(order map[string]int) {
	kept := p.RoleDiffs[:0]
	for _, rd := range p.RoleDiffs {
		if !rd.empty() {
			kept = append(kept, rd)
		}
	}
	p.RoleDiffs = kept
	for i := range p.RoleDiffs {
		ps := p.RoleDiffs[i].Privileges
		sort.SliceStable(ps, func(a, b int) bool { return privRank(ps[a]) < privRank(ps[b]) })
	}
	sort.SliceStable(p.RoleDiffs, func(i, j int) bool {
		a, aok := order[p.RoleDiffs[i].Name]
		b, bok := order[p.RoleDiffs[j].Name]
		if aok != bok {
			return aok
		}
		if aok && a != b {
			return a < b
		}
		return p.RoleDiffs[i].Name < p.RoleDiffs[j].Name
	})
}

// privRank orders the privilege lines of one role from the widest target to
// the narrowest, with default privileges last.
func privRank(pd PrivDiff) int {
	if pd.Default {
		return 9
	}
	switch {
	case strings.HasPrefix(pd.Label, "DATABASE "):
		return 0
	case strings.HasPrefix(pd.Label, "SCHEMA "):
		return 1
	case strings.HasPrefix(pd.Label, "ALL "):
		return 2
	case strings.HasPrefix(pd.Label, "TABLE "):
		return 3
	default: // SEQUENCE
		return 4
	}
}

// displayTarget renders a grant target for the diff, fully qualified and
// unquoted: "DATABASE app", "SCHEMA app.public", "TABLE app.public.jobs".
func (k objectKey) displayTarget() string {
	switch k.Kind {
	case "database":
		return "DATABASE " + k.Database
	case "schema":
		return fmt.Sprintf("SCHEMA %s.%s", k.Database, k.Schema)
	case "table":
		return fmt.Sprintf("TABLE %s.%s.%s", k.Database, k.Schema, k.Name)
	case "sequence":
		return fmt.Sprintf("SEQUENCE %s.%s.%s", k.Database, k.Schema, k.Name)
	}
	panic("unknown kind " + k.Kind)
}

// WriteDiff prints the declaration-shaped diff, styled with pal. It writes
// nothing when there is no change. Pass a disabled palette (or nil) for plain
// text; the plain output is compared byte-for-byte by the tests.
func (p *Plan) WriteDiff(w io.Writer, pal *termcolor.Palette) {
	for _, rd := range p.RoleDiffs {
		mark, style := "~", termcolor.Yellow
		if rd.Created {
			mark, style = "+", termcolor.Green
		}
		fmt.Fprintln(w, pal.Paint(fmt.Sprintf("%s role %q", mark, rd.Name), termcolor.Bold, style))
		if rd.LoginChanged {
			if rd.Created {
				attr(w, pal, termcolor.Green, "+ login:     %t", rd.LoginAfter)
			} else {
				attr(w, pal, termcolor.Yellow, "~ login:     %t -> %t", rd.LoginBefore, rd.LoginAfter)
			}
		}
		if rd.MembersChanged {
			if rd.Created {
				attr(w, pal, termcolor.Green, "+ member_of: %s", list(rd.MembersAfter))
			} else {
				attr(w, pal, termcolor.Yellow, "~ member_of: %s -> %s", list(rd.MembersBefore), list(rd.MembersAfter))
			}
		}
		if rd.PrincipalsChanged {
			if rd.Created {
				attr(w, pal, termcolor.Green, "+ iam_principals: %s", list(rd.PrincipalsAfter))
			} else {
				attr(w, pal, termcolor.Yellow, "~ iam_principals: %s -> %s", list(rd.PrincipalsBefore), list(rd.PrincipalsAfter))
			}
		}
		for _, pd := range rd.Privileges {
			kind := "grants on"
			if pd.Default {
				kind = "default privileges"
			}
			mark, style := "~", termcolor.Yellow
			switch {
			case len(pd.Removed) == 0:
				mark, style = "+", termcolor.Green
			case len(pd.Added) == 0:
				mark, style = "-", termcolor.Red
			}
			attr(w, pal, style, "%s %s %s:", mark, kind, pd.Label)
			for _, priv := range pd.Added {
				fmt.Fprintf(w, "      %s\n", pal.Add("+ "+priv))
			}
			for _, priv := range pd.Removed {
				fmt.Fprintf(w, "      %s\n", pal.Remove("- "+priv))
			}
		}
		fmt.Fprintln(w)
	}
}

// attr prints one indented attribute line, styled as a whole so the mark and
// the text share a colour.
func attr(w io.Writer, pal *termcolor.Palette, style termcolor.Style, format string, args ...any) {
	fmt.Fprintf(w, "  %s\n", pal.Paint(fmt.Sprintf(format, args...), style))
}

func list(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	return "[" + strings.Join(ss, ", ") + "]"
}
