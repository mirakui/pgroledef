package plan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mirakui/pgroledef/internal/catalog"
)

// occRetries is how many times a statement is retried after an optimistic
// concurrency failure. Aurora DSQL raises 40001 for concurrent catalog changes.
const occRetries = 5

// Apply executes the plan. Statements are grouped per database and, where the
// engine allows it, each database's statements run inside one transaction, so
// a failure leaves that database untouched. Cluster-level statements ("" as the
// database) run first.
//
// Aurora DSQL allows only one DDL statement per transaction, and every
// statement a role plan produces is DDL there, so statements run one at a time
// and a failure leaves the changes made so far in place. The log names every
// statement as it runs, so the point of failure is the last line printed; the
// plan is idempotent, so re-running after fixing the cause converges.
func Apply(ctx context.Context, p *Plan, connector catalog.Connector, log io.Writer) error {
	for _, db := range p.Databases() {
		conn, err := connector.Connect(ctx, db)
		if err != nil {
			return err
		}
		err = func() error {
			defer conn.Close(ctx)
			if p.Dialect.ApplyMode == ApplyPerStatementTx {
				return applyStatements(ctx, conn, p, db, log)
			}
			tx, err := conn.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op
			if err := applyStatements(ctx, tx, p, db, log); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// execer is satisfied by both *pgx.Conn and pgx.Tx.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func applyStatements(ctx context.Context, ex execer, p *Plan, db string, log io.Writer) error {
	for _, s := range p.Statements {
		if s.Database != db {
			continue
		}
		fmt.Fprintf(log, "[%s] %s;\n", dbLabel(db), s.SQL)
		if err := execRetrying(ctx, ex, s.SQL); err != nil {
			return fmt.Errorf("execute %q in %s: %w", s.SQL, dbLabel(db), err)
		}
	}
	return nil
}

func execRetrying(ctx context.Context, ex execer, sql string) error {
	var err error
	for attempt := 0; ; attempt++ {
		_, err = ex.Exec(ctx, sql)
		if err == nil || !isSerializationFailure(err) || attempt == occRetries {
			return err
		}
		// Catalog changes race with each other; back off and let the loser retry.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
		}
	}
}

func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "40001"
	}
	return false
}

func dbLabel(db string) string {
	if db == "" {
		return "cluster"
	}
	return db
}

var _ execer = (*pgx.Conn)(nil)
