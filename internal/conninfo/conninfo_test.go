package conninfo_test

import (
	"strings"
	"testing"

	"github.com/mirakui/pgroledef/internal/conninfo"
)

// clearEnv drops the libpq variables so the ambient environment cannot decide
// the outcome of a case.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"PGHOST", "PGPORT", "PGUSER", "PGDATABASE", "PGSERVICE", "PGSSLMODE"} {
		t.Setenv(k, "")
	}
}

func TestResolve(t *testing.T) {
	cases := []struct {
		name           string
		opts           conninfo.Options
		host, user, db string
		port           uint16
	}{
		{
			name: "the dsn alone",
			opts: conninfo.Options{DSN: "postgres://app@db.example:5433/orders"},
			host: "db.example", port: 5433, user: "app", db: "orders",
		},
		{
			name: "the flags alone",
			opts: conninfo.Options{Host: "db.example", Port: "5433", User: "app", Database: "orders"},
			host: "db.example", port: 5433, user: "app", db: "orders",
		},
		{
			name: "every flag overrides the dsn",
			opts: conninfo.Options{
				DSN:  "postgres://dsnuser@dsnhost:5432/dsndb",
				Host: "flaghost", Port: "5555", User: "flaguser", Database: "flagdb",
			},
			host: "flaghost", port: 5555, user: "flaguser", db: "flagdb",
		},
		{
			name: "one flag leaves the rest of the dsn alone",
			opts: conninfo.Options{DSN: "postgres://app@db.example:5433/orders", Database: "template1"},
			host: "db.example", port: 5433, user: "app", db: "template1",
		},
		{
			name: "keyword form works too",
			opts: conninfo.Options{DSN: "host=db.example port=5433 user=app dbname=orders", Host: "other"},
			host: "other", port: 5433, user: "app", db: "orders",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			cfg, err := c.opts.Resolve()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Host != c.host {
				t.Errorf("host: got %q, want %q", cfg.Host, c.host)
			}
			if cfg.Port != c.port {
				t.Errorf("port: got %d, want %d", cfg.Port, c.port)
			}
			if cfg.User != c.user {
				t.Errorf("user: got %q, want %q", cfg.User, c.user)
			}
			if cfg.Database != c.db {
				t.Errorf("database: got %q, want %q", cfg.Database, c.db)
			}
		})
	}
}

// TestResolveHostDropsFallbacks covers the multi-host case: naming one host
// means the others were not asked for, and a stale fallback would silently
// connect somewhere else.
func TestResolveHostDropsFallbacks(t *testing.T) {
	clearEnv(t)
	cfg, err := conninfo.Options{DSN: "postgres://app@a.example,b.example:5432/orders", Host: "c.example"}.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "c.example" {
		t.Fatalf("host: got %q, want c.example", cfg.Host)
	}
	if len(cfg.Fallbacks) != 0 {
		t.Fatalf("got %d fallback(s), want none", len(cfg.Fallbacks))
	}
}

// TestResolvePortAppliesToFallbacks keeps every host of a multi-host DSN on the
// port the caller named.
func TestResolvePortAppliesToFallbacks(t *testing.T) {
	clearEnv(t)
	cfg, err := conninfo.Options{DSN: "postgres://app@a.example,b.example:5432/orders", Port: "5433"}.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 5433 {
		t.Fatalf("port: got %d, want 5433", cfg.Port)
	}
	for _, fb := range cfg.Fallbacks {
		if fb.Port != 5433 {
			t.Fatalf("fallback %s: port %d, want 5433", fb.Host, fb.Port)
		}
	}
}

func TestResolveRejectsBadPort(t *testing.T) {
	for _, port := range []string{"abc", "0", "-1", "70000", "5432x"} {
		t.Run(port, func(t *testing.T) {
			clearEnv(t)
			_, err := conninfo.Options{Port: port}.Resolve()
			if err == nil || !strings.Contains(err.Error(), "--port") {
				t.Fatalf("want a --port error for %q, got %v", port, err)
			}
		})
	}
}

func TestUserExplicit(t *testing.T) {
	cases := []struct {
		name string
		opts conninfo.Options
		env  map[string]string
		want bool
	}{
		{name: "nothing names a user", opts: conninfo.Options{DSN: "postgres://h:5432/d"}},
		{name: "the url names one", opts: conninfo.Options{DSN: "postgres://app@h:5432/d"}, want: true},
		{name: "a url query names one", opts: conninfo.Options{DSN: "postgres://h:5432/d?user=app"}, want: true},
		{name: "keyword form names one", opts: conninfo.Options{DSN: "host=h user=app"}, want: true},
		{name: "a service may supply one", opts: conninfo.Options{DSN: "host=h service=prod"}, want: true},
		{name: "-U names one", opts: conninfo.Options{Host: "h", User: "app"}, want: true},
		{name: "PGUSER names one", env: map[string]string{"PGUSER": "app"}, want: true},
		{name: "PGSERVICE may supply one", env: map[string]string{"PGSERVICE": "prod"}, want: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if got := c.opts.UserExplicit(); got != c.want {
				t.Fatalf("UserExplicit() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSSLModePinned(t *testing.T) {
	cases := []struct {
		name string
		opts conninfo.Options
		env  map[string]string
		want bool
	}{
		{name: "nothing pins it", opts: conninfo.Options{DSN: "postgres://app@h:5432/d"}},
		{name: "a url query pins it", opts: conninfo.Options{DSN: "postgres://app@h:5432/d?sslmode=require"}, want: true},
		{name: "keyword form pins it", opts: conninfo.Options{DSN: "host=h sslmode=verify-ca"}, want: true},
		{name: "PGSSLMODE pins it", env: map[string]string{"PGSSLMODE": "require"}, want: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if got := c.opts.SSLModePinned(); got != c.want {
				t.Fatalf("SSLModePinned() = %v, want %v", got, c.want)
			}
		})
	}
}
