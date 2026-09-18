# Aurora DSQL

Set `target.engine` to `dsql`. The declaration format is the same, but a DSQL
cluster constrains it:

| | Aurora PostgreSQL | Aurora DSQL |
|---|---|---|
| databases | many | exactly one, always `postgres`; identifiers still spell it out (`postgres.app.jobs`) |
| `GRANT ... ON DATABASE` | yes | rejected by the server, so rejected by `validate` |
| IAM identities | `member_of: ['rds_iam']` plus an IAM policy | `iam_principals: ['arn:aws:iam::…:role/…']`, applied as `AWS IAM GRANT` |
| privileges | all of PostgreSQL's | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `USAGE`, `CREATE`, `TRIGGER` (`TRUNCATE` and `REFERENCES` are rejected even though an owner's own ACL carries them) |
| `apply` | one transaction per database | **one transaction per statement** |

The last row is the one to plan around. DSQL allows a single DDL statement per
transaction, and `CREATE ROLE`, `GRANT`, `REVOKE`, `ALTER DEFAULT PRIVILEGES`
and `AWS IAM GRANT` are all DDL there, so a role plan cannot be applied
atomically. `plan` says so, and `apply` logs every statement as it runs, so the
point of failure is the last line printed. Re-run after fixing the cause: the
plan is derived from the live catalog, so it converges.

One consequence is worth knowing about. `ALTER DEFAULT PRIVILEGES FOR ROLE`
needs an inheriting membership in the creator role, so `apply` borrows one and
hands it straight back. Where that pair is not atomic, a failure in between
leaves the borrow in place — and nothing would otherwise notice, because the
next `plan` would see the membership and decide no borrow is needed. `plan`
therefore proposes handing a leftover borrow back:

```text
  REVOKE INHERIT OPTION FOR "shopfront_migrator" FROM CURRENT_USER;  -- membership borrowed by an earlier apply and never returned
```

It reads as destructive, because it is a revoke, but it does **not** need
`--allow-destroy`: recovering from a half-applied run would otherwise also have
to unlock every other revoke in the plan, which is the opposite of what you
want at that moment.

More generally, the executing user is normally in `policy.protected_roles`, so
its own memberships are not declared anywhere — which makes any inheriting
membership it holds in a managed role undeclared, and pgroledef proposes
returning it. When no default privilege in the plan still relies on it, that
one runs at cluster level and does need `--allow-destroy`, since it cannot be
attributed to a borrow. If you granted it on purpose, declare the privileges it
carries instead of relying on the membership.

A role's IAM mapping has to be revoked before the role can be dropped, which
matters if you remove a role by hand — DSQL reports it as
`role "x" cannot be dropped because some objects depend on it`.

```bash
export PGROLEDEF_DSN="postgres://admin@<cluster-id>.dsql.ap-northeast-1.on.aws:5432/postgres"
pgroledef plan  -f roles.jsonnet   # --auth dsql-admin is the default here
pgroledef apply -f roles.jsonnet
```

## Predefined roles

A DSQL cluster ships `admin`, `dbowner` (the only superuser) and
`pg_dsql_diagnostic`, plus PostgreSQL's own `pg_*` roles. The default
`policy.protected_roles` on `dsql` is therefore

```jsonnet
protected_roles: ['admin', 'dbowner', 'pg_*', 'awsdsql_*'],
```

and `policy.unmanaged_databases` defaults to nothing (`render` prints `null`), because the one
database is always the one being reconciled. Declaring a role that matches
`protected_roles` is rejected by `validate`. See
[Declaration format](declaration.md#policy) for the Aurora PostgreSQL
defaults.
