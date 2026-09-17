package config

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

var (
	roleNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
	iamArnRe   = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/.+$`)
)

// rdsIAM is the Aurora-provided role that enables IAM DB authentication.
const rdsIAM = "rds_iam"

var privilegesByKind = map[string]map[Privilege]bool{
	"database": {PrivConnect: true, PrivCreate: true, PrivTemp: true},
	"schema":   {PrivUsage: true, PrivCreate: true},
	"tables": {
		PrivSelect: true, PrivInsert: true, PrivUpdate: true, PrivDelete: true,
		PrivTruncate: true, PrivReferences: true, PrivTrigger: true,
	},
	"sequences": {PrivUsage: true, PrivSelect: true, PrivUpdate: true},
}

// ValidationError aggregates every problem found so a single run reports all of them.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%d validation problem(s):\n  - %s", len(e.Problems), strings.Join(e.Problems, "\n  - "))
}

// Validate checks the canonical config and returns a normalized copy with
// creates_objects_in expanded into default_privileges. It never touches a database.
func Validate(in *Config) (*Config, error) {
	v := &validator{cfg: in}
	v.run()
	if len(v.problems) > 0 {
		return nil, &ValidationError{Problems: v.problems}
	}
	return v.normalized(), nil
}

type validator struct {
	cfg      *Config
	problems []string
	expanded []DefaultPrivilege
}

func (v *validator) errf(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

func (v *validator) run() {
	c := v.cfg
	if c.Version != 1 {
		v.errf("version must be 1, got %d", c.Version)
	}
	switch c.Target.Engine {
	case EngineAuroraPostgres, EngineDSQL:
	default:
		v.errf("target.engine must be %q or %q, got %q", EngineAuroraPostgres, EngineDSQL, c.Target.Engine)
	}
	if c.Target.Identifier == "" {
		v.errf("target.identifier is required")
	}
	v.roles()
	v.grants()
	v.defaultPrivileges()
	v.expandCreators()
}

func (v *validator) isProtected(name string) bool {
	for _, pat := range v.cfg.Policy.ProtectedRoles {
		if ok, _ := path.Match(pat, name); ok {
			return true
		}
	}
	return false
}

func (v *validator) isUnmanagedDB(name string) bool {
	for _, pat := range v.cfg.Policy.UnmanagedDatabases {
		if ok, _ := path.Match(pat, name); ok {
			return true
		}
	}
	return false
}

func (v *validator) roleExists(name string) bool {
	_, ok := v.cfg.Role(name)
	return ok
}

func (v *validator) roles() {
	c := v.cfg
	seen := map[string]bool{}
	for i, r := range c.Roles {
		name := r.Name
		if name == "" {
			v.errf("roles[%d]: name is required", i)
			continue
		}
		if seen[name] {
			v.errf("role %q: declared more than once", name)
		}
		seen[name] = true
		if !roleNameRe.MatchString(name) {
			v.errf("role %q: name must match %s", name, roleNameRe)
		}
		if v.isProtected(name) {
			v.errf("role %q: matches policy.protected_roles and cannot be managed", name)
		}
		for _, m := range r.MemberOf {
			switch {
			case m == rdsIAM:
				if c.Target.Engine == EngineDSQL {
					v.errf("role %q: member_of %q is Aurora-only; use iam.principals on dsql", name, rdsIAM)
				}
			case !v.roleExists(m):
				v.errf("role %q: member_of references undeclared role %q", name, m)
			case m == name:
				v.errf("role %q: cannot be a member of itself", name)
			}
		}
		if r.IAM != nil {
			if !r.IAM.Enabled {
				v.errf("role %q: iam.enabled must be true when iam is set (omit iam to disable)", name)
			}
			for _, p := range r.IAM.Principals {
				if !iamArnRe.MatchString(p) {
					v.errf("role %q: iam.principals entry %q is not an IAM role ARN", name, p)
				}
			}
			switch c.Target.Engine {
			case EngineDSQL:
				if len(r.IAM.Principals) == 0 {
					v.errf("role %q: dsql requires at least one iam.principals entry (AWS IAM GRANT target)", name)
				}
				if !r.Login {
					v.errf("role %q: dsql iam mapping requires login: true", name)
				}
			case EngineAuroraPostgres:
				if len(r.IAM.Principals) > 0 {
					v.errf("role %q: iam.principals must be empty on aurora-postgresql (rds-db:connect is managed in IAM/Terraform)", name)
				}
			}
		}
		for _, s := range r.CreatesObjectsIn {
			if _, err := ParseSchema(s); err != nil {
				v.errf("role %q: creates_objects_in: %v", name, err)
			}
		}
	}
}

func (v *validator) checkPrivileges(ctx string, kind string, privs []Privilege) {
	if len(privs) == 0 {
		v.errf("%s: privileges must not be empty", ctx)
		return
	}
	seen := map[Privilege]bool{}
	for _, p := range privs {
		if !allPrivileges[p] {
			v.errf("%s: unknown privilege %q", ctx, p)
			continue
		}
		if allowed := privilegesByKind[kind]; allowed != nil && !allowed[p] {
			v.errf("%s: privilege %q is not applicable to %s", ctx, p, kind)
		}
		if seen[p] {
			v.errf("%s: duplicate privilege %q", ctx, p)
		}
		seen[p] = true
	}
}

func (v *validator) grants() {
	seen := map[string]bool{}
	for i, g := range v.cfg.Grants {
		ctx := fmt.Sprintf("grants[%d]", i)
		kind, val, err := g.On.Kind()
		if err != nil {
			v.errf("%s: %v", ctx, err)
			continue
		}
		ctx = fmt.Sprintf("grants[%d] (%s %s to %s)", i, kind, val, g.To)
		if !v.roleExists(g.To) {
			v.errf("%s: grantee references undeclared role %q", ctx, g.To)
		}
		var db string
		privKind := kind
		switch kind {
		case "database":
			db = val
		case "schema", "all_tables_in_schema", "all_sequences_in_schema":
			q, err := ParseSchema(val)
			if err != nil {
				v.errf("%s: %v", ctx, err)
				continue
			}
			db = q.Database
			privKind = map[string]string{"schema": "schema", "all_tables_in_schema": "tables", "all_sequences_in_schema": "sequences"}[kind]
		case "table", "sequence":
			q, err := ParseRelation(val)
			if err != nil {
				v.errf("%s: %v", ctx, err)
				continue
			}
			db = q.Database
			privKind = map[string]string{"table": "tables", "sequence": "sequences"}[kind]
		}
		if v.isUnmanagedDB(db) {
			v.errf("%s: database %q matches policy.unmanaged_databases", ctx, db)
		}
		v.checkPrivileges(ctx, privKind, g.Privileges)
		key := kind + "\x00" + val + "\x00" + g.To
		if seen[key] {
			v.errf("%s: duplicate grant for the same target and grantee; merge the privileges into one entry", ctx)
		}
		seen[key] = true
	}
}

func dpKey(d DefaultPrivilege) string {
	return d.ForRole + "\x00" + d.InSchema + "\x00" + string(d.On) + "\x00" + d.To
}

func (v *validator) defaultPrivileges() {
	seen := map[string]bool{}
	for i, d := range v.cfg.DefaultPrivileges {
		ctx := fmt.Sprintf("default_privileges[%d] (for %s in %s on %s to %s)", i, d.ForRole, d.InSchema, d.On, d.To)
		if !v.roleExists(d.ForRole) {
			v.errf("%s: for_role references undeclared role %q", ctx, d.ForRole)
		}
		if !v.roleExists(d.To) {
			v.errf("%s: grantee references undeclared role %q", ctx, d.To)
		}
		if _, err := ParseSchema(d.InSchema); err != nil {
			v.errf("%s: %v", ctx, err)
		}
		switch d.On {
		case ObjTables, ObjSequences:
			v.checkPrivileges(ctx, string(d.On), d.Privileges)
		default:
			v.errf("%s: on must be %q or %q", ctx, ObjTables, ObjSequences)
		}
		if seen[dpKey(d)] {
			v.errf("%s: duplicate default privilege", ctx)
		}
		seen[dpKey(d)] = true
	}
}

// expandCreators derives ALTER DEFAULT PRIVILEGES FOR ROLE <creator> entries:
// for every role that declares creates_objects_in, each all_tables_in_schema /
// all_sequences_in_schema grant on that schema becomes a default privilege so
// objects created later by that role carry the same grants.
func (v *validator) expandCreators() {
	explicit := map[string]DefaultPrivilege{}
	for _, d := range v.cfg.DefaultPrivileges {
		explicit[dpKey(d)] = d
	}
	out := append([]DefaultPrivilege(nil), v.cfg.DefaultPrivileges...)
	for _, r := range v.cfg.Roles {
		creator := r.Name
		for _, schema := range r.CreatesObjectsIn {
			for _, g := range v.cfg.Grants {
				var on ObjectKind
				switch {
				case g.On.AllTablesInSchema == schema:
					on = ObjTables
				case g.On.AllSequencesInSchema == schema:
					on = ObjSequences
				default:
					continue
				}
				d := DefaultPrivilege{ForRole: creator, InSchema: schema, On: on, To: g.To, Privileges: g.Privileges}
				if e, ok := explicit[dpKey(d)]; ok {
					if !samePrivileges(e.Privileges, d.Privileges) {
						v.errf("default privilege for %s in %s on %s to %s conflicts with the one derived from creates_objects_in (%v vs %v)",
							d.ForRole, d.InSchema, d.On, d.To, e.Privileges, d.Privileges)
					}
					continue
				}
				explicit[dpKey(d)] = d
				out = append(out, d)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return dpKey(out[i]) < dpKey(out[j]) })
	v.expanded = out
}

func (v *validator) normalized() *Config {
	c := *v.cfg
	c.DefaultPrivileges = v.expanded
	return &c
}

func samePrivileges(a, b []Privilege) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[Privilege]bool{}
	for _, p := range a {
		m[p] = true
	}
	for _, p := range b {
		if !m[p] {
			return false
		}
	}
	return true
}

// IsValidationError reports whether err is a *ValidationError.
func IsValidationError(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}
