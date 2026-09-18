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
// string means "not given", so the DSN and then the libpq PG* fallbacks pgx
// applies while parsing it are left in place.
type Options struct {
	DSN string
	// Host, Port, User and Database are -h, -p, -U and -d. Each one overrides
	// whatever the DSN or the environment said. Host may be a comma-separated
	// list or a unix socket directory, as it may in psql.
	Host     string
	Port     string
	User     string
	Database string
}

// Resolved is everything downstream needs to know about the connection: the
// settings themselves, plus the two facts that cannot be read back off them.
type Resolved struct {
	Conn *pgx.ConnConfig
	// UserExplicit reports whether the database user was named deliberately
	// rather than guessed from the OS.
	UserExplicit bool
	// SSLModePinned reports whether the caller chose a verification level.
	SSLModePinned bool
}

// Resolve folds the flags into the connection string and parses the result.
//
// The flags are applied before the parse rather than after it because pgx
// derives the TLS configuration, the host fallbacks and the .pgpass lookup
// from the string: patching Host or Port on the parsed config afterwards
// leaves all three describing the host that was replaced.
func (o Options) Resolve() (Resolved, error) {
	dsn, err := o.dsn()
	if err != nil {
		return Resolved{}, err
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return Resolved{}, fmt.Errorf("parse dsn: %w", err)
	}
	return Resolved{
		Conn:          cfg,
		UserExplicit:  o.userExplicit(),
		SSLModePinned: o.sslModePinned(),
	}, nil
}

// dsn appends the flags to the connection string. libpq takes the last
// occurrence of a keyword, and a URL's query overrides its authority, so
// appending is how an override is spelled in either form.
func (o Options) dsn() (string, error) {
	overrides := make([][2]string, 0, 4)
	if o.Host != "" {
		overrides = append(overrides, [2]string{"host", o.Host})
	}
	if o.Port != "" {
		port, err := strconv.ParseUint(o.Port, 10, 16)
		if err != nil || port == 0 {
			return "", fmt.Errorf("--port %q must be a number between 1 and 65535", o.Port)
		}
		overrides = append(overrides, [2]string{"port", strconv.FormatUint(port, 10)})
	}
	if o.User != "" {
		overrides = append(overrides, [2]string{"user", o.User})
	}
	if o.Database != "" {
		overrides = append(overrides, [2]string{"dbname", o.Database})
	}
	if len(overrides) == 0 {
		return o.DSN, nil
	}
	if isURL(o.DSN) {
		u, err := url.Parse(o.DSN)
		if err != nil {
			return "", fmt.Errorf("parse dsn: %w", err)
		}
		q := u.Query()
		for _, kv := range overrides {
			q.Set(kv[0], kv[1])
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	var b strings.Builder
	b.WriteString(strings.TrimSpace(o.DSN))
	for _, kv := range overrides {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%s", kv[0], quote(kv[1]))
	}
	return b.String(), nil
}

func isURL(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

// quote wraps a keyword value the way libpq expects, so that a value with a
// space or a quote in it survives the round trip.
func quote(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// userExplicit reports whether the caller named the database user, rather than
// leaving pgx to guess it from the OS. A connection service file may supply it
// too, so naming a service counts.
func (o Options) userExplicit() bool {
	if o.User != "" {
		return true
	}
	if os.Getenv("PGUSER") != "" || os.Getenv("PGSERVICE") != "" {
		return true
	}
	if isURL(o.DSN) {
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

// sslModePinned reports whether the caller pinned a verification level, in
// which case pgx's own handling of it is left alone.
func (o Options) sslModePinned() bool {
	return strings.Contains(o.DSN, "sslmode=") || os.Getenv("PGSSLMODE") != ""
}
