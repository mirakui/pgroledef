package conninfo_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

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
			r, err := c.opts.Resolve()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cfg := r.Conn
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

// TestResolveHostIsParsedNotPatched covers the reason the flags are folded
// into the connection string before it is parsed: pgx derives the TLS
// settings and the host fallbacks from the string, and patching Host on the
// parsed config afterwards leaves both describing the host that was replaced.
func TestResolveHostIsParsedNotPatched(t *testing.T) {
	t.Run("a pinned sslmode verifies the flag's host", func(t *testing.T) {
		clearEnv(t)
		r, err := conninfo.Options{
			DSN:  "postgres://u@old.example:5432/d?sslmode=verify-full",
			Host: "new.example",
		}.Resolve()
		if err != nil {
			t.Fatal(err)
		}
		if r.Conn.TLSConfig == nil {
			t.Fatal("verify-full lost its TLS configuration")
		}
		if got := r.Conn.TLSConfig.ServerName; got != "new.example" {
			t.Fatalf("ServerName: got %q, want new.example", got)
		}
	})

	t.Run("sslmode=prefer keeps its plaintext fallback", func(t *testing.T) {
		clearEnv(t)
		r, err := conninfo.Options{
			DSN:  "postgres://u@db.example:5432/d",
			Host: "db.example",
		}.Resolve()
		if err != nil {
			t.Fatal(err)
		}
		if r.Conn.TLSConfig == nil {
			t.Fatal("the TLS attempt was dropped")
		}
		if !hasPlaintextFallback(r.Conn.Fallbacks) {
			t.Fatal("the plaintext fallback was dropped; prefer can no longer fall back")
		}
	})

	t.Run("the flags alone still offer TLS", func(t *testing.T) {
		clearEnv(t)
		r, err := conninfo.Options{Host: "db.example", Port: "5433", User: "app", Database: "orders"}.Resolve()
		if err != nil {
			t.Fatal(err)
		}
		if r.Conn.TLSConfig == nil {
			t.Fatal("a connection made from the flags alone would never attempt TLS")
		}
		if got := r.Conn.TLSConfig.ServerName; got != "db.example" {
			t.Fatalf("ServerName: got %q, want db.example", got)
		}
		if !hasPlaintextFallback(r.Conn.Fallbacks) {
			t.Fatal("prefer lost its plaintext fallback")
		}
	})

	t.Run("a unix socket directory drops TLS", func(t *testing.T) {
		clearEnv(t)
		r, err := conninfo.Options{
			DSN:  "postgres://u@db.example:5432/d",
			Host: "/var/run/postgresql",
		}.Resolve()
		if err != nil {
			t.Fatal(err)
		}
		if r.Conn.Host != "/var/run/postgresql" {
			t.Fatalf("host: got %q", r.Conn.Host)
		}
		if r.Conn.TLSConfig != nil {
			t.Fatal("a unix socket must not be asked for TLS")
		}
	})
}

// TestResolveHostList covers psql's comma-separated -h.
func TestResolveHostList(t *testing.T) {
	clearEnv(t)
	r, err := conninfo.Options{DSN: "postgres://app@ignored.example:5432/orders", Host: "a.example,b.example"}.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]bool{r.Conn.Host: true}
	for _, fb := range r.Conn.Fallbacks {
		hosts[fb.Host] = true
	}
	for _, want := range []string{"a.example", "b.example"} {
		if !hosts[want] {
			t.Fatalf("host %s is missing; got %v", want, hosts)
		}
	}
	if hosts["ignored.example"] {
		t.Fatal("the host the DSN named survived the override")
	}
}

// TestResolveQuotesValues keeps a value with a space or a quote in it from
// being read back as two settings.
func TestResolveQuotesValues(t *testing.T) {
	clearEnv(t)
	r, err := conninfo.Options{User: "o'brien jr", Database: "some db", Host: "db.example"}.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if r.Conn.User != "o'brien jr" {
		t.Errorf("user: got %q", r.Conn.User)
	}
	if r.Conn.Database != "some db" {
		t.Errorf("database: got %q", r.Conn.Database)
	}
}

func hasPlaintextFallback(fallbacks []*pgconn.FallbackConfig) bool {
	for _, fb := range fallbacks {
		if fb.TLSConfig == nil {
			return true
		}
	}
	return false
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
	// A named service is only resolvable against a service file, so give the
	// cases one rather than whatever the developer has in $HOME.
	serviceFile := filepath.Join(t.TempDir(), "pg_service.conf")
	if err := os.WriteFile(serviceFile, []byte("[prod]\nhost=h\nuser=svcuser\n"), 0o600); err != nil {
		t.Fatal(err)
	}

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
			t.Setenv("PGSERVICEFILE", serviceFile)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			r, err := c.opts.Resolve()
			if err != nil {
				t.Fatal(err)
			}
			if r.UserExplicit != c.want {
				t.Fatalf("UserExplicit = %v, want %v", r.UserExplicit, c.want)
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
			r, err := c.opts.Resolve()
			if err != nil {
				t.Fatal(err)
			}
			if r.SSLModePinned != c.want {
				t.Fatalf("SSLModePinned = %v, want %v", r.SSLModePinned, c.want)
			}
		})
	}
}
