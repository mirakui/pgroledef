package plan

import "github.com/mirakui/pgroledef/internal/config"

// ApplyMode says how statements may be grouped into transactions.
type ApplyMode int

const (
	// ApplyPerDatabaseTx wraps each database's statements in one transaction.
	ApplyPerDatabaseTx ApplyMode = iota
	// ApplyPerStatementTx runs every statement on its own. Aurora DSQL rejects
	// a second DDL statement in a transaction with "multiple ddl statements not
	// supported in a transaction", and CREATE ROLE, GRANT, REVOKE, ALTER
	// DEFAULT PRIVILEGES and AWS IAM GRANT are all DDL there, so a role plan
	// cannot be applied atomically.
	ApplyPerStatementTx
)

// Dialect carries the engine differences the planner and the executor need.
type Dialect struct {
	Engine config.Engine
	// DatabaseGrants is false where GRANT has no ON DATABASE form.
	DatabaseGrants bool
	// IAMPrincipals is true where roles are mapped to IAM ARNs in the database
	// itself (AWS IAM GRANT) rather than through a server-provided role.
	IAMPrincipals bool
	ApplyMode     ApplyMode
}

func DialectFor(engine config.Engine) Dialect {
	if engine == config.EngineDSQL {
		return Dialect{
			Engine:         engine,
			DatabaseGrants: false,
			IAMPrincipals:  true,
			ApplyMode:      ApplyPerStatementTx,
		}
	}
	return Dialect{
		Engine:         engine,
		DatabaseGrants: true,
		IAMPrincipals:  false,
		ApplyMode:      ApplyPerDatabaseTx,
	}
}

// Atomic reports whether a plan is applied all-or-nothing.
func (d Dialect) Atomic() bool { return d.ApplyMode == ApplyPerDatabaseTx }
