# How it works

pgroledef treats the declaration as the single source of truth for the roles
it names, and the live catalog as the state to be corrected. Every run is the
same five steps; steps 3 and 5 are the only ones that talk to the database,
and `plan` never reaches step 5.

1. **Evaluate** the jsonnet with the `--ext-str` variables and `-J` paths.
2. **Decode and validate** the result offline: unknown fields, unknown
   privileges, undeclared roles and engine-specific mistakes are all reported
   before any connection is made. `creates_objects_in` is expanded into
   `default_privileges` here, so the planner only ever sees the explicit form.
3. **Read the catalog**: `pg_roles`, `pg_auth_members`, the ACLs of every
   database, schema, table and sequence in every managed database, and
   `pg_default_acl`. On `dsql` the IAM mappings are read too.
4. **Diff** the two, pure and deterministic: the same declaration against the
   same catalog always produces the same statements in the same order.
5. **Apply** the statements, or just print them for `plan`.

`plan` and `apply` share steps 1 to 4, so what `apply` executes is exactly what
`plan` showed.

## What is reconciled

For every role declared in the file:

- existence and `LOGIN` / `NOLOGIN`
- role memberships (`GRANT role TO role`); Aurora IAM authentication is plain
  membership in `rds_iam`, and on `dsql` the `AWS IAM GRANT` mappings
- privileges on databases, schemas, tables and sequences, in every database
  not matched by `policy.unmanaged_databases`; undeclared privileges are
  revoked
- default privileges where the declared role is the creator or the grantee

Two things are deliberately left alone:

- **Privileges a role holds as the owner** of an object are not reconciled.
  Ownership is the schema's business, not the role file's, and an owner can
  regrant itself anything anyway.
- **Roles that exist on the server but are not declared.** They are neither
  dropped nor altered. Dropping undeclared roles is out of scope for now.

Passwords, database and schema creation, and the IAM policies that let a
principal connect (`rds-db:connect`, `dsql:DbConnect`) are also out of scope;
see [Status](../README.md#status) in the README.

## Authoritative within a role

"Authoritative" means: for a declared role, the declaration is complete. A
privilege the role holds on the server but the file does not mention is
revoked, and a membership the file does not list is revoked. This is what makes
the file trustworthy as documentation, and it is also what makes the first
`plan` against an existing cluster worth reading carefully: everything granted
by hand shows up as a REVOKE.

The boundary of that authority is set by `policy`:

- `unmanaged_databases` (default `postgres`, `rdsadmin`, `template*` on
  Aurora): privileges inside these databases are neither read nor revoked.
- `protected_roles`: these roles may not be declared, so pgroledef never
  reconciles them. The one thing it does touch is the executing user's own
  membership in a managed role, described under
  [Protected roles](#protected-roles).

### Protected roles

The defaults cover the engine's own roles (`rdsadmin`, `rds_*`, `pg_*`,
`admin`, `dbowner`, `awsdsql_*`) and the conventional superuser (`postgres`);
the exact lists are under [Declaration format](declaration.md#policy). The user
pgroledef connects as should be in this list too, and normally is: it is
either `postgres`/`admin` or a role named by the pattern. Its memberships are
therefore not declared anywhere, so an inheriting membership it holds in a
managed role is proposed for revocation on either engine (a superuser is
exempt). It needs `--allow-destroy` like any other revoke, unless the plan
still uses that membership for an `ALTER DEFAULT PRIVILEGES` statement, in
which case it counts as returning a borrow. On `dsql` that is how a borrow left
behind by a failed `apply` is returned, described under
[Aurora DSQL](aurora-dsql.md).

## Destructive statements

A `REVOKE` or an `ALTER ROLE ... NOLOGIN` is marked destructive. `plan` prints
it in red, gives each REVOKE a trailing comment saying why it is there
(`-- privilege not declared`, `-- membership not declared`), counts it in the
summary line, and `apply` refuses the whole plan unless `--allow-destroy` is
given. The refusal happens before the confirmation prompt, so it cannot be
waved through. The one exception is a statement that only hands back a
membership pgroledef borrowed itself; see [Aurora DSQL](aurora-dsql.md).

Creating a role, granting a privilege or a membership, and
`ALTER ROLE ... LOGIN` are not destructive: they widen access, and the diff
makes that visible, but they cannot lock anyone out.

## Transactions and re-runs

On Aurora PostgreSQL the statements for each database run in one transaction,
so a failure rolls that database back. Statements that must run in the
connector's default database (`CREATE ROLE`, memberships, `ALTER ROLE`) are
grouped under `cluster` and run first.

On Aurora DSQL a transaction takes one DDL statement, and every statement
pgroledef emits is DDL there, so each runs on its own and a failure leaves the
statements before it in place. `plan` prints a note saying so.

Either way, the plan is derived from the live catalog, never from a state
file. Re-running after a partial failure produces a plan for exactly the
remaining statements, and re-running after success produces
`No changes. The database matches the declaration.` There is nothing to
import, lock or migrate.

## Default privileges and `creates_objects_in`

A schema-wide grant (`all_tables_in_schema`) covers the tables that exist when
`plan` runs. Tables created later are covered only if a matching
`ALTER DEFAULT PRIVILEGES FOR ROLE <creator>` exists, and it has to name the
role that will create them. pgroledef derives those statements from
`creates_objects_in`: declare which roles create objects in which schemas,
and every other role's schema-wide grant on that schema becomes a default
privilege for that creator. The mechanics are in
[Declaration format](declaration.md#creates_objects_in).

`ALTER DEFAULT PRIVILEGES FOR ROLE x` requires the executing user to be an
inheriting member of `x`. When it is not, the plan wraps the statement in a
`GRANT x TO CURRENT_USER WITH INHERIT TRUE` and a matching `REVOKE`, both
marked `temporary` in the SQL section. On Aurora the three run in one
transaction, so the borrow cannot outlive the run. On DSQL they cannot, and a
failure in between leaves the borrow in place; see [Aurora DSQL](aurora-dsql.md)
for how the next `plan` detects and returns it.
