# AGENTS.md

Guidelines for AI agents working on this repository. See `README.md` for what
pgroledef does and how to use it.

## Stack

Go (version pinned in `mise.toml`), jsonnet declarations, pgx for PostgreSQL.
Stdlib `testing` only — no testify, no logging library, no codegen.

## Commands

```bash
mise install
mise run db:up      # PostgreSQL 16 / 17 / 18 on ports 55416 / 55417 / 55418
mise run test       # unit tests (integration tests skip without PGROLEDEF_TEST_DSN)
mise run test:all   # integration tests against all three majors
mise run lint       # golangci-lint run ./...
gofmt -l .          # must print nothing
```

Run `mise run test` and `mise run lint` before handing work back. Run
`mise run test:all` when touching `internal/catalog` or `internal/plan`.

## Layout

- `cmd/pgroledef` — cobra CLI (`render`, `validate`, `plan`, `apply`)
- `internal/config` — the canonical model, strict decoding, offline validation
- `internal/catalog` — reads actual state from the PostgreSQL catalogs
- `internal/plan` — `Diff` (pure), `Build` (does I/O), `Apply`, diff rendering
- `internal/jsonnetx` — go-jsonnet wrapper
- `internal/termcolor` — the ANSI palette and the TTY / environment decision
- `testdata/golden` — byte-compared render output; `testdata/invalid` — `.jsonnet` + `.want` pairs

## Conventions

- Wrap errors with `fmt.Errorf(... %w ...)`. Validation accumulates every
  problem into `*config.ValidationError` rather than returning the first one.
- No logging. Write to `cmd.OutOrStdout()` or an injected `io.Writer`.
- Sort everything before emitting it — plan output and golden files are compared
  byte-for-byte.
- Quote SQL identifiers with `pgx.Identifier{...}.Sanitize()`. Never concatenate
  raw identifiers into SQL.
- Tests are external packages (`package config_test`), table-driven where there
  are several cases, and document expectations with got/want messages.

## Git

- Write commit messages, PR titles and PR descriptions in English, matching the
  rest of the repository. Commit messages follow Conventional Commits.

## Gotchas

- Golden files: refresh with `go test ./internal/config -update` after reviewing
  the diff. Never hand-edit `testdata/golden/*.json`.
- `diff_display_test.go` pins the exact diff text, and README's "Plan output"
  section shows the same output. Changing `WriteDiff` means updating both.
  Colour must only wrap that text: the coloured test strips the escapes and
  compares against the same string, so never fold styling into the wording.
- Every `testdata/invalid/*.jsonnet` needs a sibling `.want` (substring match).
- The supported-version matrix lives in four places that must stay in sync:
  `internal/config/types.go`, `docker-compose.yml`, `.github/workflows/ci.yml`
  and the `test:NN` tasks in `mise.toml`. `MAINTAIN` is PG 17+ only.
- `plan` exits 2 when there is a diff — that is the contract, not a bug.
- Keep `DisallowUnknownFields()`: typos in declarations must fail before we connect.
- Scratch scripts go in `.cctmp/scratch/` (gitignored).

## Engine differences

`internal/plan/dialect.go` is the one place engine differences live. Anything
that branches on `config.EngineDSQL` outside it (or outside
`internal/config/validate.go`, which rejects declarations the engine cannot
express) is a smell.

Facts measured on a real DSQL cluster, not taken from the AWS docs, which
disagree with the server on several of them:

- `CREATE ROLE`, `GRANT`, `REVOKE`, `ALTER DEFAULT PRIVILEGES` and
  `AWS IAM GRANT` are all DDL, and a transaction takes one DDL statement, so
  `apply` is not atomic there.
- `aclexplode()`, `pg_get_userbyid()`, `pg_default_acl` and `pg_database` all
  work, so the catalog queries are shared with Aurora.
- Sequences are visible as `pg_class.relkind = 'S'`; `pg_sequences` is absent.
- The predefined roles are `admin`, `dbowner` (the only superuser) and
  `pg_dsql_diagnostic`, plus PostgreSQL's own `pg_*` roles.
