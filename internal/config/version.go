package config

import "fmt"

// MajorFromVersionNum converts server_version_num (e.g. 170004) to its major
// version (17). PostgreSQL 10 and later use major * 10000 + minor.
func MajorFromVersionNum(num int) int { return num / 10000 }

// CheckServerMajor verifies that a live server can host the declaration:
// the major version must be supported, must match target.postgres_version
// when that is declared, and must know every privilege the config uses.
func CheckServerMajor(c *Config, major int) error {
	if major < MinMajor {
		return fmt.Errorf("PostgreSQL %d is not supported; pgroledef requires %d or later", major, MinMajor)
	}
	if want := c.Target.PostgresVersion; want != 0 && want != major {
		return fmt.Errorf("target.postgres_version is %d but the server is PostgreSQL %d", want, major)
	}
	for _, p := range c.usedPrivileges() {
		if min := PrivilegeMinMajor(p); min > major {
			return fmt.Errorf("privilege %q requires PostgreSQL %d or later; the server is PostgreSQL %d", p, min, major)
		}
	}
	return nil
}

// usedPrivileges returns the distinct privileges the config mentions.
func (c *Config) usedPrivileges() []Privilege {
	seen := map[Privilege]bool{}
	var out []Privilege
	add := func(ps []Privilege) {
		for _, p := range ps {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	for _, g := range c.FlatGrants() {
		add(g.Privileges)
	}
	for _, d := range c.FlatDefaultPrivileges() {
		add(d.Privileges)
	}
	return out
}
