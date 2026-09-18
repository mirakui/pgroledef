// Package awsauth connects to Aurora PostgreSQL and Aurora DSQL using IAM
// authentication tokens instead of a password.
package awsauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	dsqlauth "github.com/aws/aws-sdk-go-v2/feature/dsql/auth"
	rdsauth "github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Mode selects how the connection password is obtained.
type Mode string

const (
	// ModePassword takes the password from the DSN or the PG* environment.
	ModePassword Mode = "password"
	// ModeRDSIAM signs an Aurora PostgreSQL IAM database authentication token.
	ModeRDSIAM Mode = "rds-iam"
	// ModeDSQL signs an Aurora DSQL token for a custom database role.
	ModeDSQL Mode = "dsql"
	// ModeDSQLAdmin signs an Aurora DSQL token for the admin role.
	ModeDSQLAdmin Mode = "dsql-admin"
)

// Modes lists the accepted --auth values in the order they are documented.
var Modes = []Mode{ModePassword, ModeRDSIAM, ModeDSQL, ModeDSQLAdmin}

func ParseMode(s string) (Mode, error) {
	for _, m := range Modes {
		if Mode(s) == m {
			return m, nil
		}
	}
	names := make([]string, len(Modes))
	for i, m := range Modes {
		names[i] = string(m)
	}
	return "", fmt.Errorf("unknown auth mode %q (want one of %s)", s, strings.Join(names, ", "))
}

// UsesToken reports whether the mode needs AWS credentials.
func (m Mode) UsesToken() bool { return m != ModePassword }

type Options struct {
	// Conn is the already-resolved connection configuration; see
	// internal/conninfo, which merges the DSN with the -h/-p/-U/-d flags.
	Conn *pgx.ConnConfig
	// UserExplicit reports whether the database user was named deliberately
	// rather than guessed from the OS.
	UserExplicit bool
	// SSLModePinned reports whether the caller chose a verification level, in
	// which case pgx's handling of it is left alone.
	SSLModePinned bool
	// Mode must not be ModePassword; use catalog.NewDSNConnector for that.
	Mode Mode
	// Region defaults to the AWS SDK's resolved region.
	Region string
	// SSLRootCert is the CA bundle used for verify-full. Aurora needs the RDS
	// bundle; DSQL chains to a public root, so it can be empty.
	SSLRootCert string
}

// Connector mints a fresh token for every connection, so the 15-minute token
// lifetime never has to be tracked.
type Connector struct {
	base   *pgx.ConnConfig
	mode   Mode
	region string
	creds  aws.CredentialsProvider
}

func NewConnector(ctx context.Context, opts Options) (*Connector, error) {
	if !opts.Mode.UsesToken() {
		return nil, fmt.Errorf("auth mode %q does not use AWS tokens", opts.Mode)
	}
	if opts.Conn == nil {
		return nil, fmt.Errorf("auth mode %q needs a connection configuration", opts.Mode)
	}
	base := opts.Conn.Copy()
	// pgx falls back to the OS username, which for IAM authentication means a
	// token signed for the wrong role and an opaque PAM failure from the
	// server. The database user has to be a deliberate choice here.
	if !opts.UserExplicit {
		return nil, fmt.Errorf("auth mode %q needs an explicit database user: put it in --dsn "+
			"(postgres://<role>@host:5432/db), pass -U/--username, or set PGUSER", opts.Mode)
	}
	if err := applyTLS(base, opts.Mode, opts.SSLModePinned, opts.SSLRootCert); err != nil {
		return nil, err
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	region := opts.Region
	if region == "" {
		region = awsCfg.Region
	}
	if region == "" {
		return nil, fmt.Errorf("auth mode %q needs a region (set --region or AWS_REGION)", opts.Mode)
	}
	return &Connector{base: base, mode: opts.Mode, region: region, creds: awsCfg.Credentials}, nil
}

// ConnConfig returns a copy of the settings connections are made with, so the
// TLS decisions above can be inspected.
func (c *Connector) ConnConfig() *pgx.ConnConfig { return c.base.Copy() }

func (c *Connector) Connect(ctx context.Context, database string) (*pgx.Conn, error) {
	cfg := c.base.Copy()
	if database != "" {
		cfg.Database = database
	}
	token, err := c.token(ctx, cfg)
	if err != nil {
		return nil, err
	}
	cfg.Password = token
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to database %q: %w", cfg.Database, err)
	}
	return conn, nil
}

func (c *Connector) token(ctx context.Context, cfg *pgx.ConnConfig) (string, error) {
	switch c.mode {
	case ModeRDSIAM:
		// RDS signs host:port, and only the real cluster endpoint - a CNAME
		// produces a token the server rejects.
		endpoint := net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
		token, err := rdsauth.BuildAuthToken(ctx, endpoint, c.region, cfg.User, c.creds)
		if err != nil {
			return "", fmt.Errorf("build rds auth token for %s@%s: %w", cfg.User, endpoint, err)
		}
		return token, nil
	case ModeDSQLAdmin:
		// DSQL signs the hostname alone, without the port.
		token, err := dsqlauth.GenerateDBConnectAdminAuthToken(ctx, cfg.Host, c.region, c.creds)
		if err != nil {
			return "", fmt.Errorf("build dsql admin auth token for %s: %w", cfg.Host, err)
		}
		return token, nil
	case ModeDSQL:
		token, err := dsqlauth.GenerateDbConnectAuthToken(ctx, cfg.Host, c.region, c.creds)
		if err != nil {
			return "", fmt.Errorf("build dsql auth token for %s: %w", cfg.Host, err)
		}
		return token, nil
	}
	return "", fmt.Errorf("unknown auth mode %q", c.mode)
}

// applyTLS makes sure the connection verifies the server against the intended
// CA, and that it cannot silently end up in plaintext. IAM authentication is
// rejected over a plaintext connection, and pgx's default ("prefer") would fall
// back to one.
//
// When the caller pinned an sslmode, that choice is left alone; only the CA
// bundle is installed, so --sslrootcert keeps meaning "verify against this".
func applyTLS(cfg *pgx.ConnConfig, mode Mode, sslModePinned bool, rootCert string) error {
	if rootCert == "" {
		rootCert = os.Getenv("PGSSLROOTCERT")
	}
	pool, err := certPool(rootCert)
	if err != nil {
		return err
	}
	if sslModePinned {
		if pool != nil {
			setRootCAs(cfg.TLSConfig, pool)
			for _, fb := range cfg.Fallbacks {
				setRootCAs(fb.TLSConfig, pool)
			}
		}
		return nil
	}
	if pool == nil && rootCert == "" && mode == ModeRDSIAM {
		return fmt.Errorf("aurora needs the RDS CA bundle for verify-full: pass --sslrootcert " +
			"(curl -o global-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem), " +
			"or set sslmode= in --dsn to choose the verification level yourself")
	}
	cfg.TLSConfig = verifyFull(cfg.Host, pool)
	// Fallbacks carries every host/port x TLS combination after the primary,
	// so the plaintext attempts have to be dropped one by one rather than by
	// clearing the slice, which would take the extra hosts with them.
	kept := make([]*pgconn.FallbackConfig, 0, len(cfg.Fallbacks))
	for _, fb := range cfg.Fallbacks {
		if fb.TLSConfig == nil {
			continue
		}
		fb.TLSConfig = verifyFull(fb.Host, pool)
		kept = append(kept, fb)
	}
	cfg.Fallbacks = kept
	return nil
}

// verifyFull is the equivalent of libpq's sslmode=verify-full. A nil pool means
// the system roots, which is what Aurora DSQL's public chain needs.
func verifyFull(host string, pool *x509.CertPool) *tls.Config {
	return &tls.Config{
		ServerName: host,
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
}

func setRootCAs(c *tls.Config, pool *x509.CertPool) {
	if c != nil {
		c.RootCAs = pool
	}
}

// systemRootCert is libpq's spelling for "use the system trust store" - a
// value, not a path.
const systemRootCert = "system"

func certPool(path string) (*x509.CertPool, error) {
	if path == "" || path == systemRootCert {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sslrootcert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("sslrootcert %s contains no certificate", path)
	}
	return pool, nil
}
