# Development

```bash
mise run db:up                # pg16, pg17, pg18 on ports 55416 / 55417 / 55418
mise run test:17              # tests against one version (also test:16, test:18)
mise run test:all             # tests against all three
mise run lint
go test ./internal/config -update   # refresh golden files after reviewing the diff
```

Conventions and the pitfalls worth knowing before changing anything are in
[AGENTS.md](../AGENTS.md).

## Release

Releases are cut by pushing a SemVer tag with a `v` prefix; the `release`
workflow then cross-compiles with [GoReleaser](https://goreleaser.com/) and
uploads the archives and `checksums.txt` to the GitHub release.

```bash
git tag -a v0.1.0 -m v0.1.0
git push origin v0.1.0
```

`.goreleaser.yaml` is exercised on every pull request by the `release-dryrun`
CI job, so configuration mistakes surface before a tag is pushed. To reproduce
that locally:

```bash
go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=publish
```
