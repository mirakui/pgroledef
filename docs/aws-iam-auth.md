# Connecting with AWS IAM authentication

`plan` and `apply` take `--auth` to authenticate with an IAM token instead of a
password. A fresh token is signed for every connection, so the 15-minute token
lifetime never has to be managed.

| `--auth` | Signs | Needs |
|---|---|---|
| `password` (default on `aurora-postgresql`) | nothing; the password comes from the DSN, `PG*`, or [the prompt](commands.md#the-password) | — |
| `rds-iam` | an Aurora PostgreSQL IAM database authentication token | `rds-db:connect` on `dbuser:<cluster-resource-id>/<role>`, and the role must be a member of `rds_iam` |
| `dsql-admin` (default on `dsql`) | an Aurora DSQL token for `admin` | `dsql:DbConnectAdmin` |
| `dsql` | an Aurora DSQL token for a custom role | `dsql:DbConnect` |

Credentials and the region come from the standard AWS SDK chain;
`--region` overrides the resolved region.

The database user has to be named explicitly, with `-U` or in the DSN or
`PGUSER`: pgx would
otherwise fall back to the OS username, and a token signed for the wrong role
comes back from the server as an opaque PAM failure.

IAM authentication is rejected over a plaintext connection, so unless the DSN
(or `PGSSLMODE`) pins an `sslmode`, the connection is upgraded to the equivalent
of `verify-full` and the plaintext attempts are dropped (other hosts in a
multi-host DSN are kept). Pinning an `sslmode` yourself leaves the verification
level alone; `--sslrootcert` is installed as the CA either way. Aurora's
certificates chain to the RDS CA rather than a public root, so pass the bundle;
`rds-iam` refuses to connect without it unless you pinned `sslmode` yourself:

```bash
curl -o global-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem

export PGROLEDEF_DSN="postgres://shopfront_migrator@mycluster.cluster-abc.ap-northeast-1.rds.amazonaws.com:5432/shopfront"
pgroledef plan -f roles.jsonnet --auth rds-iam --sslrootcert global-bundle.pem

# the same connection, without a DSN
pgroledef plan -f roles.jsonnet --auth rds-iam --sslrootcert global-bundle.pem \
  -h mycluster.cluster-abc.ap-northeast-1.rds.amazonaws.com -p 5432 \
  -U shopfront_migrator -d shopfront
```

Aurora DSQL chains to a public root, so no bundle is needed:

```bash
export PGROLEDEF_DSN="postgres://admin@<cluster-id>.dsql.ap-northeast-1.on.aws:5432/postgres"
pgroledef plan -f roles.jsonnet --auth dsql-admin

# or: pgroledef plan -f roles.jsonnet --auth dsql-admin \
#       -h <cluster-id>.dsql.ap-northeast-1.on.aws -U admin -d postgres
```

The RDS token is signed against `host:port` of the real cluster endpoint, so a
CNAME in front of it produces a token the server rejects.
