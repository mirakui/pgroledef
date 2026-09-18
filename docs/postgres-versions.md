# Supported PostgreSQL versions

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
