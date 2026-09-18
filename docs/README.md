# pgroledef documentation

The [README](../README.md) covers installation, the declaration format at a
glance and the commands. These pages go deeper.

Suggested reading order for a first deployment:

1. [How it works](how-it-works.md) — the reconciliation model: what is
   reconciled, what "authoritative" means, destructive statements,
   transactions and re-runs.
2. [Declaration format](declaration.md) — every field, the policy defaults per
   engine, grant targets, the privilege matrix, the validation rules and
   jsonnet idioms.
3. [Commands](commands.md) — `render`, `validate`, `plan`, `apply`,
   `version`: every flag, the connection flags and their precedence, the
   password prompt, `plan --out`, environment variables and exit codes.
4. [Plan output](plan-output.md) — how to read the diff and the SQL section,
   and how colour is decided.

Then whichever of these applies to your cluster:

- [AWS IAM authentication](aws-iam-auth.md) — `--auth rds-iam`, `dsql`,
  `dsql-admin`, TLS and the RDS CA bundle.
- [Aurora DSQL](aurora-dsql.md) — what a DSQL cluster constrains, one
  transaction per statement, the borrowed membership, predefined roles.
- [Supported PostgreSQL versions](postgres-versions.md) — 16, 17, 18 and
  `target.postgres_version`.

For contributors: [Development](development.md) covers the local databases,
tests, lint, golden files and releases.
