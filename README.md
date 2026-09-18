# pgroledef

Declarative, authoritative management of PostgreSQL roles, memberships, grants
and default privileges for Aurora PostgreSQL and Aurora DSQL.
Declarations are written in jsonnet; `pgroledef` evaluates them, validates them
strictly, diffs them against the live catalog and applies the resulting SQL.

Think `psqldef` for roles: schema is psqldef's job, roles are pgroledef's.

## Status

Early development. Current milestone: `render` / `validate` / `plan` / `apply`
against Aurora PostgreSQL and Aurora DSQL, exercised in CI on PostgreSQL 16, 17
and 18.

Out of scope for now: passwords, database/schema creation, IAM policies
(`rds-db:connect`, `dsql:DbConnect`), dropping undeclared roles.

## Install

Download a prebuilt binary from the [releases page](https://github.com/mirakui/pgroledef/releases).
Archives are published for linux and darwin on amd64 and arm64:

```bash
VERSION=0.1.0
OS=$(uname -s | tr '[:upper:]' '[:lower:]')          # linux | darwin
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')  # amd64 | arm64
BASE=https://github.com/mirakui/pgroledef/releases/download/v${VERSION}

curl -fsSLO ${BASE}/pgroledef_${VERSION}_${OS}_${ARCH}.tar.gz
curl -fsSLO ${BASE}/checksums.txt
shasum -a 256 -c checksums.txt --ignore-missing

tar xzf pgroledef_${VERSION}_${OS}_${ARCH}.tar.gz pgroledef
install -m 0755 pgroledef /usr/local/bin/pgroledef
```

Or build from source with the Go toolchain (`go.mod` requires Go 1.27.1 or newer):

```bash
go install github.com/mirakui/pgroledef/cmd/pgroledef@latest
```

Either way, `pgroledef version` prints the version, commit and build date of the
binary (`--version` prints the same line).

## Quick start

From a clone of this repository (`go install` above puts `pgroledef` on your
`PATH`; `go run ./cmd/pgroledef` works in its place):

```bash
mise install
mise run db:up                                   # PostgreSQL 16, 17 and 18 with an Aurora-like fixture
export PGROLEDEF_DSN=postgres://postgres:postgres@localhost:55417/postgres

pgroledef validate -f examples/shopfront.jsonnet --ext-str env=staging
pgroledef render   -f examples/shopfront.jsonnet --ext-str env=staging
pgroledef plan     -f examples/shopfront.jsonnet --ext-str env=staging
pgroledef apply    -f examples/shopfront.jsonnet --ext-str env=staging
```

| command | does |
|---|---|
| `validate` | evaluate the jsonnet and check it offline; no connection |
| `render` | the same, then print the normalized canonical JSON |
| `plan` | connect, diff the declaration against the catalog, print the diff and the SQL |
| `apply` | the same, then ask for confirmation and run the SQL |

`plan` and `apply` also take psql's `-h -p -U -d`, which override the DSN, and
prompt for the password when the server asks for one:

```bash
pgroledef plan -f examples/shopfront.jsonnet --ext-str env=staging \
  -h localhost -p 55417 -U postgres -d postgres
```

Two things to know before the first run against a real cluster: `plan` exits
2 when there is a diff, and `apply` refuses a plan containing REVOKE or
NOLOGIN unless `--allow-destroy` is given. Every flag and the exit codes are
in [docs/commands.md](docs/commands.md); the IAM token modes are in
[docs/aws-iam-auth.md](docs/aws-iam-auth.md).

## Declaration format

The jsonnet must evaluate to the canonical form below. Unknown fields, unknown
privileges, references to undeclared roles and engine-specific mistakes are all
rejected by `validate` before any connection is made.

```jsonnet
{
  version: 1,
  target: { engine: 'aurora-postgresql', identifier: 'staging-shopfront' },
  policy: {},   // defaults: authoritative, protected_roles, unmanaged_databases
  roles: [
    {
      name: 'grp_viewer',
      grants: [
        { on: { database: 'app' }, privileges: ['CONNECT'] },
        { on: { schema: 'app.public' }, privileges: ['USAGE'] },
        { on: { all_tables_in_schema: 'app.public' }, privileges: ['SELECT'] },
      ],
    },
    {
      name: 'grp_editor',
      member_of: ['grp_viewer'],
      grants: [
        { on: { schema: 'app.public' }, privileges: ['USAGE', 'CREATE'] },
        { on: { all_tables_in_schema: 'app.public' }, privileges: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] },
      ],
    },
    {
      name: 'migrator',
      login: true,
      member_of: ['grp_editor', 'rds_iam'],   // Aurora IAM auth is just membership in rds_iam
                                              // (DSQL instead: iam_principals: ['arn:aws:iam::...:role/...'])
      creates_objects_in: ['app.public'],     // derives ALTER DEFAULT PRIVILEGES FOR ROLE migrator
    },
    {
      name: 'worker',
      login: true,
      grants: [{ on: { table: 'app.public.jobs' }, privileges: ['SELECT', 'INSERT'] }],
      // default_privileges: [...] may be declared here too; normally derived from creates_objects_in
    },
  ],
}
```

Identifiers are `database.schema` and `database.schema.relation`. Everything a
role can do lives under that role: its memberships, its grants and the default
privileges it receives. Object names never appear as keys.

| key | meaning |
|---|---|
| `target.engine` | `aurora-postgresql` or `dsql`; picks the dialect, the policy defaults and the validation rules |
| `policy` | `protected_roles` and `unmanaged_databases` bound what pgroledef will touch; the defaults cover the engine's own roles and databases |
| `roles[].login` | `LOGIN` / `NOLOGIN`; default `false` |
| `roles[].member_of` | memberships; `rds_iam` for Aurora IAM authentication |
| `roles[].iam_principals` | DSQL only: IAM role ARNs mapped with `AWS IAM GRANT` |
| `roles[].grants[].on` | one of `database`, `schema`, `table`, `sequence`, `all_tables_in_schema`, `all_sequences_in_schema` |
| `roles[].creates_objects_in` | schemas this role creates objects in; derives `ALTER DEFAULT PRIVILEGES FOR ROLE` |

The full field reference, the privilege matrix per target, engine and
PostgreSQL version, and the validation rules are in
[docs/declaration.md](docs/declaration.md).

### Why `creates_objects_in`

`ALTER DEFAULT PRIVILEGES` only applies to objects created by the role named in
`FOR ROLE`, and getting that role wrong is how tables created by a migration
role end up without the grants everyone expected. Declaring who creates objects
lets pgroledef derive every `FOR ROLE` clause, so the mistake cannot be
expressed; the derivation is spelled out in
[docs/declaration.md](docs/declaration.md#creates_objects_in).

## How it works

Every run evaluates the jsonnet, validates it offline, reads the live catalog,
diffs the two and, for `apply`, runs the resulting SQL. The plan is derived
from the catalog on every run, never from a state file, so a partially applied
run is finished by running again.

For every role declared in the file, pgroledef reconciles:

- existence and `LOGIN` / `NOLOGIN`
- role memberships (`GRANT role TO role`); Aurora IAM authentication is plain
  membership in `rds_iam`, and on `dsql` the `AWS IAM GRANT` mappings
- privileges on databases, schemas, tables and sequences, in every database
  not matched by `policy.unmanaged_databases`; undeclared privileges are revoked
- default privileges where the declared role is the creator or the grantee

Privileges a role holds as the object's owner are left alone. Roles that exist
on the server but are not declared are not touched (yet).

`plan` shows the diff shaped like the declaration, then the SQL it will run:

```text
~ role "migrator"
  ~ login:     false -> true
  ~ member_of: [grp_viewer] -> [grp_viewer, rds_iam]

+ role "worker"
  + login:     true
  + grants on TABLE app.public.jobs:
      + INSERT
      + SELECT

SQL:
  -- cluster
  ALTER ROLE "migrator" WITH LOGIN;
  CREATE ROLE "worker" WITH LOGIN;
  GRANT "rds_iam" TO "migrator";
  -- app
  GRANT INSERT, SELECT ON TABLE "public"."jobs" TO "worker";

Plan: 4 statement(s), 0 destructive.
```

Destructive statements (REVOKE / NOLOGIN) are shown in red, and each REVOKE
carries a comment saying why it is there. Reading the diff in full, and how colour is
decided, is in [docs/plan-output.md](docs/plan-output.md).

## Documentation

- [How it works](docs/how-it-works.md) — the reconciliation model, authority
  boundaries, destructive statements, transactions and re-runs
- [Declaration format](docs/declaration.md) — every field, defaults per
  engine, the privilege matrix, validation rules, jsonnet idioms
- [Commands](docs/commands.md) — every flag, connection precedence, the
  password prompt, `plan --out`, environment variables, exit codes
- [Plan output](docs/plan-output.md) — reading the diff and the SQL, colour
- [AWS IAM authentication](docs/aws-iam-auth.md) — `--auth rds-iam` / `dsql`
  / `dsql-admin`, TLS and the RDS CA bundle
- [Aurora DSQL](docs/aurora-dsql.md) — what DSQL constrains, one transaction
  per statement, the borrowed membership
- [Supported PostgreSQL versions](docs/postgres-versions.md) — 16, 17, 18 and
  `target.postgres_version`
- [Development](docs/development.md) — local databases, tests, lint, golden
  files, releases

## License

MIT. See [LICENSE](LICENSE).
