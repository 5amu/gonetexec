# AGENTS

## Build, Lint, Test (CI truth)
- Lint: `golangci-lint run --timeout 5m` (via golangci-lint-action).
- Build: `go build .` from `cmd/gnx/` (CLI entrypoint).
- Test: `go test ./...` (CI sets `GITHUB_TOKEN` env).
- Mod hygiene in CI before build/test: `go clean -modcache` then `go mod tidy`.

## Entrypoints and naming
- CLI main is `cmd/gnx/` and the built binary is `gnx` (see `.goreleaser.yml`).
- Module path is `github.com/5amu/gonetexec` even though README and binary use “goad”.

## Release
- Tagged pushes run GoReleaser (`goreleaser release --clean`) using `.goreleaser.yml`.
- GoReleaser builds from `./cmd/gnx/` with `CGO_ENABLED=1` and `-trimpath`/`-s -w` ldflags.
