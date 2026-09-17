package plan

import (
	"context"
	"fmt"
	"io"

	"github.com/mirakui/pgroledef/internal/catalog"
)

// Apply executes the plan. Statements are grouped per database and each
// database's statements run inside one transaction, so a failure leaves that
// database untouched. Cluster-level statements ("" database) run first.
func Apply(ctx context.Context, p *Plan, connector catalog.Connector, log io.Writer) error {
	for _, db := range p.Databases() {
		conn, err := connector.Connect(ctx, db)
		if err != nil {
			return err
		}
		err = func() error {
			defer conn.Close(ctx)
			tx, err := conn.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op
			for _, s := range p.Statements {
				if s.Database != db {
					continue
				}
				fmt.Fprintf(log, "[%s] %s;\n", dbLabel(db), s.SQL)
				if _, err := tx.Exec(ctx, s.SQL); err != nil {
					return fmt.Errorf("execute %q in %s: %w", s.SQL, dbLabel(db), err)
				}
			}
			return tx.Commit(ctx)
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func dbLabel(db string) string {
	if db == "" {
		return "cluster"
	}
	return db
}
