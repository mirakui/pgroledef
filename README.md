# pgroledef

Declarative, authoritative management of PostgreSQL roles, memberships, grants
and default privileges for Aurora PostgreSQL (Aurora DSQL support is planned).
Declarations are written in jsonnet; `pgroledef` evaluates them, validates them
strictly, diffs them against the live catalog and applies the resulting SQL.

Think `psqldef` for roles: schema is psqldef's job, roles are pgroledef's.

## Status

Early development. Current milestone: `render` / `validate` / `plan` / `apply`
against Aurora-compatible PostgreSQL, exercised in CI on PostgreSQL 16, 17 and 18.

Out of scope for now: passwords, database/schema creation, IAM policies
(`rds-db:connect`), Aurora DSQL, dropping undeclared roles.

## Quick start

```bash
mise install
mise run db:up                                   # PostgreSQL 16, 17 and 18 with an Aurora-like fixture
export PGROLEDEF_DSN=postgres://postgres:postgres@localhost:55417/postgres

go run ./cmd/pgroledef validate -f examples/shopfront.jsonnet --ext-str env=staging
go run ./cmd/pgroledef render   -f examples/shopfront.jsonnet --ext-str env=staging
go run ./cmd/pgroledef plan     -f examples/shopfront.jsonnet --ext-str env=staging
go run ./cmd/pgroledef apply    -f examples/shopfront.jsonnet --ext-str env=staging
```

`plan` exits 2 when there is a diff, 0 when the database already matches.
`apply` refuses plans containing REVOKE / NOLOGIN unless `--allow-destroy` is given.

## Supported PostgreSQL versions

PostgreSQL 16, 17 and 18 (and the Aurora PostgreSQL versions based on them).
`plan` and `apply` read `server_version_num` and refuse anything older than 16.

A declaration may pin the major version it was written for:

```jsonnet
target: { engine: 'aurora-postgresql', identifier: 'staging-shopfront', postgres_version: 17 },
```

When pinned, `validate` rejects — offline, without a connection — privileges the
version does not have, and `plan` / `apply` refuse a server whose major version
differs. When omitted, the same checks run at `plan` / `apply` time against the
version the server reports.

The only privilege that currently differs between the supported versions is
`MAINTAIN` on tables, which PostgreSQL 17 introduced.

## Plan output

When there is a diff, `plan` (and `apply`, before the confirmation prompt)
prints it twice: first as a diff shaped like the declaration, one block per
role, then as the SQL that will be executed.

```text
~ role "grp_viewer"
  - grants on TABLE app.public.orders:
      - DELETE
  + default privileges FOR ROLE migrator IN SCHEMA app.public ON TABLES TO grp_viewer:
      + SELECT

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
  + ALTER ROLE "migrator" WITH LOGIN;
  + CREATE ROLE "worker" WITH LOGIN;
  + GRANT "rds_iam" TO "migrator";
  -- app
  + GRANT INSERT, SELECT ON TABLE "public"."jobs" TO "worker";
  - REVOKE DELETE ON TABLE "public"."orders" FROM "grp_viewer";  -- privilege not declared
  + ALTER DEFAULT PRIVILEGES FOR ROLE "migrator" IN SCHEMA "public" GRANT SELECT ON TABLES TO "grp_viewer";

Plan: 6 statement(s), 1 destructive.
```

Reading the diff:

- `+ role "x"` the role will be created, `~ role "x"` an existing role changes.
  Roles appear in declaration order; unchanged roles are not printed.
- `~ login: false -> true` and `~ member_of: [a] -> [a, b]` show the whole
  before and after value of a scalar or list attribute.
- A privilege line names the target (`grants on TABLE app.public.orders`, or
  `default privileges FOR ROLE ... IN SCHEMA ... ON TABLES TO ...`), followed by
  the privileges being added (`+`) and removed (`-`). The line's own mark is `+`
  when only privileges are added, `-` when only removed, `~` when both.
- Targets in the diff are fully qualified as `database.schema.relation`, matching
  the identifiers used in the declaration; the SQL below uses quoted PostgreSQL
  identifiers relative to the database each statement runs in.
- Schema-wide grants are rendered as one `ALL TABLES IN SCHEMA app.public` entry
  when the privilege is missing on every relation, as in the SQL.
- Within a role, privilege lines run from the widest target to the narrowest
  (database, schema, `ALL ... IN SCHEMA`, relation), with default privileges last.

In the SQL section, statements are grouped by the database they run in
(`cluster` means the connector's default database), `-` marks a destructive
statement (REVOKE / NOLOGIN) and the trailing `--` comment says why it is there.

When nothing differs, the output is a single line:

```text
No changes. The database matches the declaration.
```

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

### Why `creates_objects_in`

`ALTER DEFAULT PRIVILEGES` only applies to objects created by the role named in
`FOR ROLE`. Writing that by hand is how tables created by a migration role end
up without the grants everyone expected. Declaring who creates objects lets
pgroledef derive every `FOR ROLE` clause from the schema-wide grants of every
other role, so the mistake cannot be expressed. `render` shows the derived
entries under each grantee's `default_privileges`.

## What is reconciled

For every role declared in the file:

- existence and `LOGIN` / `NOLOGIN`
- role memberships (`GRANT role TO role`); Aurora IAM authentication is plain membership in `rds_iam`
- privileges on databases, schemas, tables and sequences, in every database
  not matched by `policy.unmanaged_databases`; undeclared privileges are revoked
- default privileges where the declared role is the creator or the grantee

Privileges a role holds as the object's owner are left alone. Roles that exist
on the server but are not declared are not touched (yet).

## Development

```bash
mise run db:up                # pg16, pg17, pg18 on ports 55416 / 55417 / 55418
mise run test:17              # tests against one version (also test:16, test:18)
mise run test:all             # tests against all three
mise run lint
go test ./internal/config -update   # refresh golden files after reviewing the diff
```

Conventions and the pitfalls worth knowing before changing anything are in
[AGENTS.md](AGENTS.md).

## License

MIT. See [LICENSE](LICENSE).
