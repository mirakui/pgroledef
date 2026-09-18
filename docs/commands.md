# Commands

Every command except `version` evaluates the jsonnet named by `-f`, decodes it strictly and
validates it offline before anything else happens. `render` and `validate`
stop there; `plan` and `apply` then connect to the database.

| command | what it does | connects |
|---|---|---|
| `render` | evaluate, validate, print the normalized canonical JSON (with `creates_objects_in` expanded into `default_privileges`) | no |
| `validate` | evaluate and validate; print `OK: N roles, N grants, N default privileges` | no |
| `plan` | read the catalog, diff it against the declaration, print the diff and the SQL | yes |
| `apply` | the same, then ask for confirmation and execute the SQL | yes |
| `version` | print the version, commit and build date (`--version` prints the same line) | no |

## Global flags

These are accepted by every command.

| flag | meaning |
|---|---|
| `-f`, `--file FILE` | jsonnet file to evaluate (required by every command except `version`) |
| `--ext-str KEY=VALUE` | external string variable, read in jsonnet with `std.extVar('KEY')`; repeatable |
| `-J`, `--jpath DIR` | additional jsonnet import path; repeatable |

```bash
pgroledef validate -f examples/shopfront.jsonnet --ext-str env=staging
pgroledef render   -f examples/shopfront.jsonnet --ext-str env=staging
```

## Connecting: `plan` and `apply`

Both commands take the same connection flags. The connection string comes from
`--dsn`, which defaults to `$PGROLEDEF_DSN`:

```bash
export PGROLEDEF_DSN=postgres://postgres:postgres@localhost:55417/postgres
pgroledef plan  -f examples/shopfront.jsonnet --ext-str env=staging
pgroledef apply -f examples/shopfront.jsonnet --ext-str env=staging
```

`plan` and `apply` also take the psql spellings, which override whatever the
DSN said, so the connection can be named without one:

```bash
pgroledef plan -f examples/shopfront.jsonnet --ext-str env=staging \
  -h localhost -p 55417 -U postgres -d postgres
```

| flag | psql | falls back to |
|---|---|---|
| `-h`, `--host` | `-h` | the DSN, then `$PGHOST` |
| `-p`, `--port` | `-p` | the DSN, then `$PGPORT` |
| `-U`, `--username` | `-U` | the DSN, then `$PGUSER` |
| `-d`, `--dbname` | `-d` | the DSN, then `$PGDATABASE` |
| `-W`, `--password` | `-W` | [the prompt](#the-password) |
| `-w`, `--no-password` | `-w` | nothing; it turns the prompt off |

The order is the flag, then the DSN, then the environment, which is libpq's.
`-h` takes psql's spellings too: a comma-separated list of hosts, or a unix
socket directory.

`-d` only picks the database the first connection is made to; which databases
are reconciled comes from the declaration. Because `-h` is the host on `plan`
and `apply`, those two commands spell their help `--help` in full.

The remaining connection flags:

| flag | meaning |
|---|---|
| `--dsn STRING` | PostgreSQL connection string (URL or `key=value` form); default `$PGROLEDEF_DSN` |
| `--auth MODE` | `password`, `rds-iam`, `dsql`, `dsql-admin`; default `password` on `aurora-postgresql`, `dsql-admin` on `dsql`. See [AWS IAM authentication](aws-iam-auth.md) |
| `--region REGION` | AWS region for IAM token signing; default: the AWS SDK's resolved region |
| `--sslrootcert FILE` | CA bundle for `verify-full` in the IAM token modes (`rds-iam`, `dsql`, `dsql-admin`); falls back to `$PGSSLROOTCERT`. **Ignored with `--auth password`**, where TLS is whatever the DSN's `sslmode` and `sslrootcert` say |
| `--no-color` | disable coloured output (also honours `NO_COLOR`) |

### The password

The password can stay out of the DSN and out of the environment. When the server
asks for one, `plan` and `apply` prompt for it on the terminal (without echoing
it) and retry once; `-W` / `--password` asks up front instead of waiting for the
rejection. The prompt names the user the connection resolved to, `-U` included,
and the answer is read once and reused for every database the run touches.

```bash
pgroledef plan -f examples/shopfront.jsonnet --ext-str env=staging \
  -h localhost -p 55417 -U postgres -d postgres
# Password for user postgres:
```

Without a terminal on stdin — a pipe, a CI job — nothing is prompted and the
server's authentication error is reported as before, so scripts fail instead of
hanging. `-w` / `--no-password` turns the prompt off on a terminal too, for a
script that wants the same failure while being run by hand. `PGPASSWORD` and
`~/.pgpass` still work; the prompt fills the gap when neither has an answer, or
when the answer they have is rejected. `-W` / `--password` is
rejected in the IAM token modes (a token is signed, never typed), and rejected
without a terminal on stdin.

The prompt reads stdin rather than the controlling terminal, so feeding `apply`
its confirmation (`echo yes | pgroledef apply …`) also turns the password
prompt off; pass the password some other way, or use `--auto-approve` and keep
stdin free.

## `plan`

`plan` prints the diff and the SQL, described in [Plan output](plan-output.md),
and exits **2 when there is a diff**, 0 when the database already matches.
That is the contract for CI: a non-zero exit from a scheduled `plan` means
someone changed roles by hand.

| flag | meaning |
|---|---|
| `-o`, `--out FILE` | also write the plan to `FILE` as an executable psql script |

### Writing the plan to a SQL file

`plan --out FILE` (`-o`) writes the same plan to `FILE` as an executable psql
script, in addition to printing it. Statements appear in the order `apply` would
run them: cluster-level ones first, then one block per database introduced by
`\connect`. On Aurora PostgreSQL each block is wrapped in `BEGIN; … COMMIT;`,
just as `apply` runs it, so a failure rolls that database back. Destructive
statements and notes are kept as trailing comments.

```bash
pgroledef plan -f examples/shopfront.jsonnet --ext-str env=staging --out pgroledef-plan.sql
psql -v ON_ERROR_STOP=1 -f pgroledef-plan.sql "$PGROLEDEF_DSN"
```

```sql
-- Generated by pgroledef plan.
-- Run with: psql -v ON_ERROR_STOP=1 -f <this file>

-- cluster (current database)
BEGIN;
CREATE ROLE "grp_shopfront_reader" WITH NOLOGIN;
REVOKE "grp_shopfront_writer" FROM "shopfront_api";  -- destructive: membership not declared
COMMIT;

-- shopfront
\connect "shopfront"
BEGIN;
GRANT USAGE ON SCHEMA "public" TO "grp_shopfront_reader";
COMMIT;
```

Run it with `ON_ERROR_STOP=1`: without it psql keeps going after an error, and
the `COMMIT` of an aborted transaction is a rollback, so later blocks would run
against a half-applied cluster. Do not add `-1` / `--single-transaction`: the
script manages its own transactions, and `\connect` would discard the outer
one anyway. The transaction is per database, not per script — `\connect`
drops an open transaction, so the `COMMIT` has to come before it — which is
the same granularity `apply` uses. The file is written even when there is no
diff (comments only), and `--out` does not change the exit code.

On Aurora DSQL the script has no `BEGIN`/`COMMIT` at all, because DSQL takes
one DDL statement per transaction; the header comment says so. As with `apply`
there, a failure leaves the statements before it in place, and re-running
`plan` converges. Two things differ from `apply`. psql does not retry
serialization failures (SQLSTATE 40001) the way `apply` does, so a concurrent
catalog change stops the script where `apply` would have backed off and
retried; re-run it. And the borrowed membership described under
[Aurora DSQL](aurora-dsql.md) is not returned on failure: a failure between the
borrow and its return leaves the executing user inheriting everything the
creator role has.

## `apply`

`apply` prints the same plan, then asks:

```text
Apply these statements? Only 'yes' is accepted:
```

Anything other than `yes` aborts with exit 1. Statements are logged one per
line as `[database] SQL;` while they run, and the run ends with
`Applied N statement(s).`

| flag | meaning |
|---|---|
| `--auto-approve` | skip the confirmation prompt |
| `--allow-destroy` | allow REVOKE / NOLOGIN statements |

`apply` refuses a plan that contains destructive statements (REVOKE or
NOLOGIN) unless `--allow-destroy` is given, and it refuses before asking for
confirmation, so the check cannot be waved through by typing `yes`. The one
exception is a statement that hands back a membership pgroledef borrowed
itself; see [Aurora DSQL](aurora-dsql.md).

On Aurora PostgreSQL the statements for each database run in one transaction,
so a failure rolls that database back and leaves the others untouched. On
Aurora DSQL every statement is its own transaction; `apply` retries
serialization failures (SQLSTATE 40001) and otherwise stops at the failing
statement, which is the last line logged. Re-running `plan` after fixing the
cause converges, because the plan is always derived from the live catalog.

Because the confirmation is read from stdin, `echo yes | pgroledef apply …`
also disables the password prompt. Prefer `--auto-approve` and keep stdin free.

## Environment variables

| variable | read by | meaning |
|---|---|---|
| `PGROLEDEF_DSN` | `plan`, `apply` | default for `--dsn` |
| `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSWORD`, `PGSERVICE`, `PGSSLMODE` | `plan`, `apply` | libpq's defaults, applied after the flags and the DSN |
| `PGSSLROOTCERT` | `plan`, `apply` | default for `--sslrootcert` in the IAM token modes; in `password` mode pgx reads it itself, like the other `PG*` variables |
| `AWS_REGION` and the rest of the AWS SDK chain | `plan`, `apply` with `--auth rds-iam` / `dsql` / `dsql-admin` | credentials and region for token signing |
| `NO_COLOR`, `TERM=dumb` | `plan`, `apply` | turn colour off |
| `FORCE_COLOR`, `CLICOLOR_FORCE` | `plan`, `apply` | keep colour on when the output is not a terminal |

## Exit codes

| code | meaning |
|---|---|
| 0 | success; for `plan`, the database matches the declaration |
| 1 | any error: evaluation, validation, connection, SQL failure, or an aborted `apply` |
| 2 | `plan` found a diff |
| 130 / 143 | interrupted by SIGINT / SIGTERM while the password prompt was open; the terminal is restored first |
