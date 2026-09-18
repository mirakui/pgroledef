// Package conninfo merges the connection string with the psql-compatible
// connection flags into the settings a connection is actually made with.
package conninfo

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Options carries --dsn together with the psql-compatible flags. An empty
// string means "not given", so the libpq PG* fallbacks pgx applies while
// parsing the DSN are left in place.
type Options struct {
	DSN string
	// Host, Port, User and Database are -h, -p, -U and -d. Each one overrides
	// whatever the DSN or the environment said.
	Host     string
	Port     string
	User     string
	Database string
}

// Resolve parses the DSN and lays the flags over it.
func (o Options) Resolve() (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(o.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	if o.Host != "" {
		cfg.Host = o.Host
		// Fallbacks are the remaining host/port x TLS combinations pgx would
		// try; naming one host means the others were not asked for.
		cfg.Fallbacks = nil
	}
	if o.Port != "" {
		port, err := strconv.ParseUint(o.Port, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("--port %q must be a number between 1 and 65535", o.Port)
		}
		cfg.Port = uint16(port)
		for _, fb := range cfg.Fallbacks {
			fb.Port = uint16(port)
		}
	}
	if o.User != "" {
		cfg.User = o.User
	}
	if o.Database != "" {
		cfg.Database = o.Database
	}
	return cfg, nil
}

// UserExplicit reports whether the caller named the database user, rather than
// leaving pgx to guess it from the OS. A connection service file may supply it
// too, so naming a service counts.
func (o Options) UserExplicit() bool {
	if o.User != "" {
		return true
	}
	if os.Getenv("PGUSER") != "" || os.Getenv("PGSERVICE") != "" {
		return true
	}
	if strings.HasPrefix(o.DSN, "postgres://") || strings.HasPrefix(o.DSN, "postgresql://") {
		u, err := url.Parse(o.DSN)
		if err != nil {
			return false
		}
		if u.User != nil && u.User.Username() != "" {
			return true
		}
		q := u.Query()
		return q.Get("user") != "" || q.Get("service") != ""
	}
	for _, field := range strings.Fields(o.DSN) {
		k, v, ok := strings.Cut(field, "=")
		if ok && v != "" && (k == "user" || k == "service") {
			return true
		}
	}
	return false
}

// SSLModePinned reports whether the caller pinned a verification level, in
// which case pgx's own handling of it is left alone.
func (o Options) SSLModePinned() bool {
	return strings.Contains(o.DSN, "sslmode=") || os.Getenv("PGSSLMODE") != ""
}
