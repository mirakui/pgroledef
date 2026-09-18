package catalog_test

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mirakui/pgroledef/internal/catalog"
)

// TestDSNConnectorPromptSkippedWhenNotAuth checks that a failure the operator
// cannot fix by typing a password does not turn into a prompt. The DSN points
// at a port nothing listens on, so the error never reaches SQLSTATE class 28.
func TestDSNConnectorPromptSkippedWhenNotAuth(t *testing.T) {
	c, err := catalog.NewDSNConnector(closedDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	prompted := 0
	c.Prompt = func(context.Context) (string, error) {
		prompted++
		return "secret", nil
	}
	if _, err := c.Connect(context.Background(), ""); err == nil {
		t.Fatal("Connect() to a closed port: got nil error, want a connection failure")
	}
	if prompted != 0 {
		t.Errorf("prompt calls = %d, want 0: only an authorization error should prompt", prompted)
	}
}

func TestDSNConnectorSetPasswordOverridesDSN(t *testing.T) {
	c, err := catalog.NewDSNConnector(closedDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := c.Base.Password, "fromdsn"; got != want {
		t.Fatalf("Base.Password = %q, want the DSN's %q", got, want)
	}
	c.SetPassword("typed")
	if got, want := c.Base.Password, "typed"; got != want {
		t.Errorf("Base.Password = %q, want %q", got, want)
	}
}

// TestDSNConnectorPromptsOnAuthFailure needs a live PostgreSQL (mise run db:up)
// and PGROLEDEF_TEST_DSN carrying a password. It strips the password so the
// server rejects the first attempt, and checks the connector asks once and
// reuses the answer for every later database.
func TestDSNConnectorPromptsOnAuthFailure(t *testing.T) {
	c, password := liveConnector(t)
	prompted := 0
	c.Prompt = func(context.Context) (string, error) {
		prompted++
		return password, nil
	}
	ctx := context.Background()
	for i := range 2 {
		conn, err := c.Connect(ctx, "")
		if err != nil {
			t.Fatalf("Connect() #%d: %v", i+1, err)
		}
		conn.Close(ctx) //nolint:errcheck // nothing to do about a failed close
	}
	if prompted != 1 {
		t.Errorf("prompt calls = %d, want 1: the password must be reused after the first answer", prompted)
	}
}

// TestDSNConnectorDoesNotRepeatTheQuestion pins the other half of "once": a
// wrong answer is reported, not asked again. Re-prompting in a loop would be
// the obvious thing to do and the wrong one — plan reads many databases, and
// every one of them would ask.
func TestDSNConnectorDoesNotRepeatTheQuestion(t *testing.T) {
	c, _ := liveConnector(t)
	prompted := 0
	c.Prompt = func(context.Context) (string, error) {
		prompted++
		return "not the password", nil
	}
	ctx := context.Background()
	for i := range 2 {
		if _, err := c.Connect(ctx, ""); !isAuthError(err) {
			t.Fatalf("Connect() #%d: got %v, want an authorization error", i+1, err)
		}
	}
	if prompted != 1 {
		t.Errorf("prompt calls = %d, want 1", prompted)
	}
}

// TestDSNConnectorSetPasswordSuppressesPrompt checks that answering up front
// (what --password does) stops the connector asking again, even though the
// answer turns out to be wrong.
func TestDSNConnectorSetPasswordSuppressesPrompt(t *testing.T) {
	c, _ := liveConnector(t)
	c.Prompt = func(context.Context) (string, error) {
		t.Error("prompt called after SetPassword")
		return "", nil
	}
	c.SetPassword("not the password")
	if _, err := c.Connect(context.Background(), ""); !isAuthError(err) {
		t.Fatalf("Connect() with a wrong password: got %v, want an authorization error", err)
	}
}

// liveConnector returns a connector for PGROLEDEF_TEST_DSN with the password
// removed, plus the password that was in it.
func liveConnector(t *testing.T) (*catalog.DSNConnector, string) {
	t.Helper()
	dsn := os.Getenv("PGROLEDEF_TEST_DSN")
	if dsn == "" {
		t.Skip("PGROLEDEF_TEST_DSN not set")
	}
	base, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if base.Password == "" {
		t.Skip("PGROLEDEF_TEST_DSN has no password to re-type")
	}
	c, err := catalog.NewDSNConnector(dsn)
	if err != nil {
		t.Fatal(err)
	}
	c.Base.Password = ""
	return c, base.Password
}

func isAuthError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "28P01"
}

// closedDSN points at a port that accepted a listener a moment ago and so is
// free, but has nothing on it now.
func closedDSN(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return "postgres://someone:fromdsn@" + addr + "/postgres?sslmode=disable&connect_timeout=2"
}
