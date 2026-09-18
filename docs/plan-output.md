# Plan output

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
  ALTER ROLE "migrator" WITH LOGIN;
  CREATE ROLE "worker" WITH LOGIN;
  GRANT "rds_iam" TO "migrator";
  -- app
  GRANT INSERT, SELECT ON TABLE "public"."jobs" TO "worker";
  REVOKE DELETE ON TABLE "public"."orders" FROM "grp_viewer";  -- privilege not declared
  ALTER DEFAULT PRIVILEGES FOR ROLE "migrator" IN SCHEMA "public" GRANT SELECT ON TABLES TO "grp_viewer";

Plan: 6 statement(s), 1 destructive.
```

Reading the diff:

- `+ role "x"` the role will be created, `~ role "x"` an existing role changes.
  Roles appear in declaration order; unchanged roles are not printed.
- `~ login: false -> true` and `~ member_of: [a] -> [a, b]` show the whole
  before and after value of a scalar or list attribute;
  on `dsql`, `iam_principals` is shown the same way, and the SQL section
  carries the matching `AWS IAM GRANT` / `AWS IAM REVOKE`.
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
(`cluster` means the connector's default database), and each statement is
printed as it will be executed, without a diff mark. Destructive statements
(REVOKE / NOLOGIN) are shown in red; the REVOKEs carry a trailing `--` comment
saying why they are there (`-- privilege not declared`, `-- membership not
declared`).

When nothing differs, the output is a single line:

```text
No changes. The database matches the declaration.
```

## Colour

On a terminal both sections are coloured the way `terraform plan` colours its
own: green for what is added, red for what is removed or destructive, yellow for
an in-place change, bold for the role and section headings, and dim for the
`--` comments. The text itself is the same either way, so stripping the colour
gives back exactly the output shown above.

Colour is off when the output is not a terminal (a pipe, a file, CI logs), when
`NO_COLOR` is set to anything non-empty, when `TERM=dumb`, or when `plan` /
`apply` is given `--no-color`. To keep the colour through a pipe anyway — a CI
log viewer that renders ANSI, say — set `FORCE_COLOR=1` or `CLICOLOR_FORCE=1`;
`--no-color`, `NO_COLOR` and `TERM=dumb` still win over both.
