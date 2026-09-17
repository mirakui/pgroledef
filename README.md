# pgroledef

Declarative, authoritative management of PostgreSQL roles, memberships, grants
and default privileges for Aurora PostgreSQL (Aurora DSQL support is planned).
Declarations are written in jsonnet; `pgroledef` evaluates them, validates them
strictly, diffs them against the live catalog and applies the resulting SQL.

Think `psqldef` for roles: schema is psqldef's job, roles are pgroledef's.

## Status

Early development. Current milestone: `render` / `validate` / `plan` / `apply`
against Aurora-compatible PostgreSQL, exercised locally on PostgreSQL 17.

Out of scope for now: passwords, database/schema creation, IAM policies
(`rds-db:connect`), Aurora DSQL, dropping undeclared roles.

## Quick start

```bash
mise install
mise run db:up                                   # PostgreSQL 17 with an Aurora-like fixture
export PGROLEDEF_DSN=postgres://postgres:postgres@localhost:55439/postgres

go run ./cmd/pgroledef validate -f examples/shopfront.jsonnet --ext-str env=staging
go run ./cmd/pgroledef render   -f examples/shopfront.jsonnet --ext-str env=staging
go run ./cmd/pgroledef plan     -f examples/shopfront.jsonnet --ext-str env=staging
go run ./cmd/pgroledef apply    -f examples/shopfront.jsonnet --ext-str env=staging
```

`plan` exits 2 when there is a diff, 0 when the database already matches.
`apply` refuses plans containing REVOKE / NOLOGIN unless `--allow-destroy` is given.

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
mise run db:up
PGROLEDEF_TEST_DSN=postgres://postgres:postgres@localhost:55439/postgres mise run test
mise run lint
go test ./internal/config -update   # refresh golden files after reviewing the diff
```
