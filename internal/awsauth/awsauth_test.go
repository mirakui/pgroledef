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

	"github.com/mirakui/pgroledef/internal/awsauth"
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

	cases := []struct {
		name string
		opts awsauth.Options
		want string // substring of the expected error; "" means success
	}{
		{
			name: "password mode is not ours",
			opts: awsauth.Options{DSN: "postgres://u@h:5432/d", Mode: awsauth.ModePassword},
			want: "does not use AWS tokens",
		},
		{
			name: "aurora without a CA bundle explains the remedy",
			opts: awsauth.Options{DSN: "postgres://u@h:5432/d", Mode: awsauth.ModeRDSIAM},
			want: "RDS CA bundle",
		},
		{
			name: "aurora with a CA bundle",
			opts: awsauth.Options{DSN: "postgres://u@h:5432/d", Mode: awsauth.ModeRDSIAM, SSLRootCert: ca},
		},
		{
			name: "an explicit sslmode is left alone",
			opts: awsauth.Options{DSN: "postgres://u@h:5432/d?sslmode=require", Mode: awsauth.ModeRDSIAM},
		},
		{
			name: "dsql trusts the system roots",
			opts: awsauth.Options{DSN: "postgres://admin@c.dsql.ap-northeast-1.on.aws:5432/postgres", Mode: awsauth.ModeDSQLAdmin},
		},
		{
			name: "a missing CA bundle is reported",
			opts: awsauth.Options{DSN: "postgres://u@h:5432/d", Mode: awsauth.ModeRDSIAM, SSLRootCert: "/nonexistent.pem"},
			want: "read sslrootcert",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The connector must not depend on the ambient libpq environment.
			t.Setenv("PGSSLMODE", "")
			t.Setenv("PGSSLROOTCERT", "")
			t.Setenv("AWS_REGION", "ap-northeast-1")
			_, err := awsauth.NewConnector(context.Background(), c.opts)
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

func TestNewConnectorNeedsRegion(t *testing.T) {
	t.Setenv("PGSSLMODE", "require")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "absent"))
	_, err := awsauth.NewConnector(context.Background(), awsauth.Options{
		DSN:  "postgres://u@h:5432/d?sslmode=require",
		Mode: awsauth.ModeRDSIAM,
	})
	if err == nil || !strings.Contains(err.Error(), "needs a region") {
		t.Fatalf("want a region error, got %v", err)
	}
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
