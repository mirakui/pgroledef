package awsauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mirakui/pgroledef/internal/awsauth"
	"github.com/mirakui/pgroledef/internal/conninfo"
)

func TestParseMode(t *testing.T) {
	for _, want := range awsauth.Modes {
		got, err := awsauth.ParseMode(string(want))
		if err != nil || got != want {
			t.Fatalf("ParseMode(%q) = %q, %v", want, got, err)
		}
	}
	if _, err := awsauth.ParseMode("iam"); err == nil {
		t.Fatal("ParseMode(\"iam\") should fail")
	}
}

func TestUsesToken(t *testing.T) {
	if awsauth.ModePassword.UsesToken() {
		t.Fatal("password mode must not need AWS credentials")
	}
	for _, m := range []awsauth.Mode{awsauth.ModeRDSIAM, awsauth.ModeDSQL, awsauth.ModeDSQLAdmin} {
		if !m.UsesToken() {
			t.Fatalf("%q must need AWS credentials", m)
		}
	}
}

func TestNewConnector(t *testing.T) {
	ca := writeCABundle(t)

	// The cases are written as a DSN plus the options that survive the merge,
	// which is how the CLI builds them: conninfo resolves the DSN and reports
	// whether a user and an sslmode were named.
	cases := []struct {
		name string
		dsn  string
		opts awsauth.Options
		want string // substring of the expected error; "" means success
	}{
		{
			name: "password mode is not ours",
			dsn:  "postgres://u@h:5432/d",
			opts: awsauth.Options{Mode: awsauth.ModePassword},
			want: "does not use AWS tokens",
		},
		{
			name: "the database user has to be named",
			dsn:  "postgres://h:5432/d",
			opts: awsauth.Options{Mode: awsauth.ModeRDSIAM},
			want: "needs an explicit database user",
		},
		{
			name: "a user in keyword form counts",
			dsn:  "host=h port=5432 dbname=d user=app sslmode=require",
			opts: awsauth.Options{Mode: awsauth.ModeRDSIAM},
		},
		{
			name: "aurora without a CA bundle explains the remedy",
			dsn:  "postgres://u@h:5432/d",
			opts: awsauth.Options{Mode: awsauth.ModeRDSIAM},
			want: "RDS CA bundle",
		},
		{
			name: "aurora with a CA bundle",
			dsn:  "postgres://u@h:5432/d",
			opts: awsauth.Options{Mode: awsauth.ModeRDSIAM, SSLRootCert: ca},
		},
		{
			name: "an explicit sslmode is left alone",
			dsn:  "postgres://u@h:5432/d?sslmode=require",
			opts: awsauth.Options{Mode: awsauth.ModeRDSIAM},
		},
		{
			name: "dsql trusts the system roots",
			dsn:  "postgres://admin@c.dsql.ap-northeast-1.on.aws:5432/postgres",
			opts: awsauth.Options{Mode: awsauth.ModeDSQLAdmin},
		},
		{
			name: "sslrootcert=system means the system roots, not a file",
			dsn:  "postgres://u@h:5432/d",
			opts: awsauth.Options{Mode: awsauth.ModeRDSIAM, SSLRootCert: "system"},
		},
		{
			name: "a missing CA bundle is reported",
			dsn:  "postgres://u@h:5432/d",
			opts: awsauth.Options{Mode: awsauth.ModeRDSIAM, SSLRootCert: "/nonexistent.pem"},
			want: "read sslrootcert",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The connector must not depend on the ambient libpq environment.
			t.Setenv("PGSSLMODE", "")
			t.Setenv("PGSSLROOTCERT", "")
			t.Setenv("PGUSER", "")
			t.Setenv("PGSERVICE", "")
			t.Setenv("AWS_REGION", "ap-northeast-1")
			opts := c.opts
			opts.Conn, opts.UserExplicit, opts.SSLModePinned = resolve(t, c.dsn)
			_, err := awsauth.NewConnector(context.Background(), opts)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.want != "" && err == nil:
				t.Fatalf("want error containing %q, got none", c.want)
			case c.want != "" && !strings.Contains(err.Error(), c.want):
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

// TestPinnedSSLModeKeepsRootCert covers the case where the caller pinned the
// verification level themselves: pgx decides how to verify, but --sslrootcert
// still has to be the bundle it verifies against.
func TestPinnedSSLModeKeepsRootCert(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSSLROOTCERT", "")
	t.Setenv("PGUSER", "")
	t.Setenv("PGSERVICE", "")
	t.Setenv("AWS_REGION", "ap-northeast-1")
	ca := writeCABundle(t)
	conn, userExplicit, sslModePinned := resolve(t, "postgres://u@h:5432/d?sslmode=verify-ca")
	c, err := awsauth.NewConnector(context.Background(), awsauth.Options{
		Conn:          conn,
		UserExplicit:  userExplicit,
		SSLModePinned: sslModePinned,
		Mode:          awsauth.ModeRDSIAM,
		SSLRootCert:   ca,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := c.ConnConfig()
	if cfg.TLSConfig == nil {
		t.Fatal("expected TLS to stay enabled")
	}
	if cfg.TLSConfig.RootCAs == nil {
		t.Fatal("--sslrootcert was discarded because the dsn pinned an sslmode")
	}
}

// TestUpgradeKeepsExtraHosts covers the multi-host case: clearing Fallbacks
// outright would drop the plaintext attempts and the other hosts with them.
func TestUpgradeKeepsExtraHosts(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSSLROOTCERT", "")
	t.Setenv("PGUSER", "")
	t.Setenv("PGSERVICE", "")
	t.Setenv("AWS_REGION", "ap-northeast-1")
	conn, userExplicit, sslModePinned := resolve(t, "postgres://admin@a.dsql.ap-northeast-1.on.aws,b.dsql.ap-northeast-1.on.aws:5432/postgres")
	c, err := awsauth.NewConnector(context.Background(), awsauth.Options{
		Conn:          conn,
		UserExplicit:  userExplicit,
		SSLModePinned: sslModePinned,
		Mode:          awsauth.ModeDSQLAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := c.ConnConfig()
	hosts := map[string]bool{cfg.Host: true}
	for _, fb := range cfg.Fallbacks {
		if fb.TLSConfig == nil {
			t.Fatalf("a plaintext fallback survived for host %s", fb.Host)
		}
		if fb.TLSConfig.ServerName != fb.Host {
			t.Fatalf("fallback for %s verifies the name %q", fb.Host, fb.TLSConfig.ServerName)
		}
		hosts[fb.Host] = true
	}
	for _, want := range []string{"a.dsql.ap-northeast-1.on.aws", "b.dsql.ap-northeast-1.on.aws"} {
		if !hosts[want] {
			t.Fatalf("host %s was dropped; kept %v", want, hosts)
		}
	}
}

func TestNewConnectorNeedsRegion(t *testing.T) {
	t.Setenv("PGSSLMODE", "require")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "absent"))
	conn, userExplicit, sslModePinned := resolve(t, "postgres://u@h:5432/d?sslmode=require")
	_, err := awsauth.NewConnector(context.Background(), awsauth.Options{
		Conn:          conn,
		UserExplicit:  userExplicit,
		SSLModePinned: sslModePinned,
		Mode:          awsauth.ModeRDSIAM,
	})
	if err == nil || !strings.Contains(err.Error(), "needs a region") {
		t.Fatalf("want a region error, got %v", err)
	}
}

// resolve does what the CLI does before it reaches this package: merge the DSN
// with the connection flags and report what the caller named explicitly.
func resolve(t *testing.T, dsn string) (*pgx.ConnConfig, bool, bool) {
	t.Helper()
	co := conninfo.Options{DSN: dsn}
	cfg, err := co.Resolve()
	if err != nil {
		t.Fatalf("resolve %q: %v", dsn, err)
	}
	return cfg, co.UserExplicit(), co.SSLModePinned()
}

// writeCABundle writes a throwaway self-signed certificate; only the fact that
// it parses as PEM matters here.
func writeCABundle(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pgroledef-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
