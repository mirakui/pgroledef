# Declaration format

A declaration is a jsonnet file that evaluates to the canonical JSON document
described here. pgroledef decodes it strictly (an unknown field anywhere is an
error), validates it offline, and only then connects. `render` prints the
normalized document; `validate` prints a one-line summary or every problem it
found, not just the first.

```jsonnet
{
  version: 1,
  target: { engine: 'aurora-postgresql', identifier: 'staging-shopfront' },
  policy: {},
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
      name: 'migrator',
      login: true,
      member_of: ['grp_viewer', 'rds_iam'],
      creates_objects_in: ['app.public'],
    },
  ],
}
```

Everything a role can do lives under that role: its memberships, its grants and
the default privileges it receives. Object names never appear as keys, so a
role's whole footprint is one block, and removing the block removes the
footprint.

## Top level

| key | type | required | meaning |
|---|---|---|---|
| `version` | int | yes | must be `1` |
| `target` | object | yes | which engine, and optionally which PostgreSQL major, the file is written for |
| `policy` | object | no | how far pgroledef's authority reaches; omitted or `{}` means the engine defaults |
| `roles` | array | no | the roles to reconcile, in the order the diff will print them; an empty list is valid and reconciles nothing |

## `target`

| key | type | required | meaning |
|---|---|---|---|
| `engine` | `'aurora-postgresql'` \| `'dsql'` | yes | selects the SQL dialect, the policy defaults, the default `--auth` mode and the validation rules below |
| `identifier` | string | yes | a free-form name for the cluster (`'staging-shopfront'`); it is not used to connect |
| `postgres_version` | `16` \| `17` \| `18` | no | pins the major version; `aurora-postgresql` only. See [Supported PostgreSQL versions](postgres-versions.md) |

## `policy`

Every field is optional. A field that is omitted takes the default for the
engine; a field that is given replaces the default entirely (the lists are not
merged). Patterns are shell globs matched against the whole name.

| key | type | `aurora-postgresql` default | `dsql` default |
|---|---|---|---|
| `authoritative` | bool | `true` | `true` |
| `protected_roles` | array of globs | `['postgres', 'rdsadmin', 'rds_*', 'pg_*', 'admin']` | `['admin', 'dbowner', 'pg_*', 'awsdsql_*']` |
| `unmanaged_databases` | array of globs | `['postgres', 'rdsadmin', 'template*']` | none (`render` prints `null`) |

- `protected_roles`: a declared role whose name matches is rejected by
  `validate`. These are the engine's own roles and the user pgroledef itself
  connects as; see [How it works](how-it-works.md#protected-roles) for why the
  executing user belongs here.
- `unmanaged_databases`: a grant whose database matches is rejected by
  `validate`, and `plan` does not read privileges from those databases, so
  nothing in them is ever revoked. A `default_privileges` entry whose
  `in_schema` is in such a database is not rejected today; `plan` would then
  propose the same `ALTER DEFAULT PRIVILEGES` on every run, so keep them out.
- `authoritative`: reserved. pgroledef is always authoritative today: undeclared
  privileges and memberships of a declared role are revoked. The field is
  accepted so a future additive mode has a place to live, but `false` does not
  change behaviour yet.

## `roles[]`

| key | type | default | meaning |
|---|---|---|---|
| `name` | string | required | must match `^[a-z_][a-z0-9_]*$`; unique within the file |
| `login` | bool | `false` | `LOGIN` vs `NOLOGIN` |
| `member_of` | array of role names | `[]` | `GRANT <role> TO <name>`; every entry must be declared in the same file, except `rds_iam` |
| `iam_principals` | array of IAM role ARNs | `[]` | `dsql` only: `AWS IAM GRANT <name> TO '<arn>'`; requires `login: true` |
| `creates_objects_in` | array of `db.schema` | `[]` | this role creates the objects in these schemas; drives `ALTER DEFAULT PRIVILEGES FOR ROLE <name>` (see below) |
| `grants` | array of grant | `[]` | privileges this role holds |
| `default_privileges` | array of default privilege | `[]` | default privileges this role receives; normally derived, may be declared explicitly |
| `settings` | map of string to string | `{}` | reserved for `ALTER ROLE ... SET`; accepted by the schema but **not reconciled yet** |

`rds_iam` is the Aurora-provided role that enables IAM database
authentication. It may be named in `member_of` without being declared, only on
`aurora-postgresql`, and only on a role with `login: true`. On `dsql` the
equivalent is `iam_principals`; see [Aurora DSQL](aurora-dsql.md).

### Grants

```jsonnet
{ on: { all_tables_in_schema: 'app.public' }, privileges: ['SELECT', 'INSERT'] }
```

`on` names exactly one target. Identifiers are `database`, `database.schema`
or `database.schema.relation`, always fully qualified, because a declaration
may span several databases of one cluster.

| target key | value | privilege kind |
|---|---|---|
| `database` | `db` | database |
| `schema` | `db.schema` | schema |
| `all_tables_in_schema` | `db.schema` | tables |
| `all_sequences_in_schema` | `db.schema` | sequences |
| `table` | `db.schema.name` | tables |
| `sequence` | `db.schema.name` | sequences |

`all_tables_in_schema` and `all_sequences_in_schema` mean every relation that
exists in the schema when `plan` runs. Objects created afterwards are covered
only by default privileges, which is what `creates_objects_in` is for.

Two grants under one role may not name the same target; merge the privileges
into one entry instead.

### Privileges

| kind | privileges |
|---|---|
| database | `CONNECT`, `CREATE`, `TEMPORARY` |
| schema | `USAGE`, `CREATE` |
| tables | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, `MAINTAIN` |
| sequences | `USAGE`, `SELECT`, `UPDATE` |

There is no `ALL`; spell the list out. A privilege that is not applicable to
the target's kind is rejected. Two further filters apply:

- **Engine.** `dsql` accepts only `SELECT`, `INSERT`, `UPDATE`, `DELETE`,
  `USAGE`, `CREATE` and `TRIGGER`. `TRUNCATE` and `REFERENCES` are rejected by
  the server even though an owner's own ACL carries them, and there is no
  `GRANT ... ON DATABASE`, so the database privileges have no target.
- **PostgreSQL major.** `MAINTAIN` exists from PostgreSQL 17. With
  `target.postgres_version` set, `validate` rejects it offline on 16; without
  it, `plan` and `apply` reject it against a 16 server.

### Default privileges

```jsonnet
{ for_role: 'migrator', in_schema: 'app.public', on: 'tables', privileges: ['SELECT'] }
```

| key | value | meaning |
|---|---|---|
| `for_role` | a declared role | the creator: `ALTER DEFAULT PRIVILEGES FOR ROLE <for_role>` |
| `in_schema` | `db.schema` | `IN SCHEMA` |
| `on` | `'tables'` \| `'sequences'` | `ON TABLES` / `ON SEQUENCES` |
| `privileges` | array | the tables or sequences list above |

The grantee is the enclosing role. Explicit entries are rarely needed: declare
`creates_objects_in` on the creator instead and let pgroledef derive them.

### `creates_objects_in`

`ALTER DEFAULT PRIVILEGES` only applies to objects created by the role named in
`FOR ROLE`. Writing that by hand is how tables created by a migration role end
up without the grants everyone expected. Declaring who creates objects lets
pgroledef derive every `FOR ROLE` clause, so the mistake cannot be expressed.

For every role `C` with `S` in `creates_objects_in`, every
`all_tables_in_schema: S` grant held by any role `G` becomes

```jsonnet
// under G
{ for_role: 'C', in_schema: 'S', on: 'tables', privileges: <the grant's privileges> }
```

and likewise `all_sequences_in_schema` → `on: 'sequences'`. `render` shows the
derived entries under each grantee's `default_privileges`. An explicit entry
with the same `for_role` / `in_schema` / `on` is allowed only if it lists the
same privileges; otherwise `validate` reports a conflict rather than guessing
which one wins.

## Validation rules

`validate` (and every other command, before it does anything else) checks all
of these. An unknown field is reported first and alone, because decoding stops
there; every other rule is accumulated and reported together. Most rules are
pinned by a case under `testdata/invalid/`; the table names it where one exists.

| rule | test case |
|---|---|
| unknown field anywhere in the document | `unknown-field` |
| `version` is 1; `target.engine` is one of the two engines; `target.identifier` is set | — |
| `target.postgres_version` is 16, 17 or 18 | `unsupported-postgres-version` |
| `target.postgres_version` is not set on `dsql` | `dsql-postgres-version` |
| every role has a `name`; names are unique and match the pattern | `missing-role-name`, `duplicate-role` |
| no declared role matches `policy.protected_roles` | `protected-role` |
| `member_of` names declared roles (or `rds_iam`); a role is not a member of itself | `undeclared-member` |
| `rds_iam` is `aurora-postgresql` only and requires `login: true` | `dsql-rds-iam`, `iam-without-login` |
| `iam_principals` is `dsql` only, holds IAM role ARNs, and requires `login: true` | `aurora-principals`, `principals-without-login` |
| a grant names exactly one target | `two-targets` |
| identifiers are `db.schema` / `db.schema.name` | — |
| no grant touches a database in `policy.unmanaged_databases` | `unmanaged-database` |
| `privileges` is non-empty, known, applicable to the kind, and free of duplicates | `empty-privileges`, `privilege-typo`, `privilege-not-applicable` |
| the privilege is supported by the engine | `dsql-unsupported-privilege` |
| the privilege exists in the pinned major | `maintain-requires-pg17` |
| `dsql`: no `on: { database: ... }`; every identifier is in `postgres` | `dsql-database-grant`, `dsql-other-database` |
| one grant per target per role | `duplicate-grant` |
| `default_privileges.for_role` is declared; `on` is `tables` or `sequences`; no duplicates | `default-privilege-undeclared-creator` |
| an explicit default privilege agrees with the derived one | `default-privilege-conflict` |

## Writing declarations in jsonnet

The file is ordinary jsonnet, so the usual tools apply. Idioms that pay off,
most of them shown by the two files under [`examples/`](../examples/):

- **External variables** for the environment:
  `local env = std.extVar('env');` with `--ext-str env=staging` on the command
  line, used both in `target.identifier` and to pick schema or database names.
- **Shared grant lists** when two roles must be identical, such as the two
  users of an alternating-user password rotation:
  `local workerGrants = [...]` used by both.
- **Conditional roles**: `roles: [...] + (if env == 'production' then [...] else [])`.
- **Helper functions** for repeated shapes, such as
  `local iamRole(name) = 'arn:aws:iam::' + account + ':role/' + name;`.
- **Imports** with `import 'common.libsonnet'` and `-J` for the search path,
  when several clusters share role definitions (not shown in the examples).

[`examples/shopfront.jsonnet`](../examples/shopfront.jsonnet) targets Aurora
PostgreSQL; [`examples/shopfront-dsql.jsonnet`](../examples/shopfront-dsql.jsonnet)
is the same application on Aurora DSQL, and the header comment lists what had to
change.
