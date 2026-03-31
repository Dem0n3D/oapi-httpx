# oapi-httpx

Reusable HTTP helpers for Go services built around OpenAPI and `oapi-codegen`.

## Module

```txt
github.com/Dem0n3D/oapi-httpx
```

## Packages

- `middleware`: CORS and OpenAPI validation middleware
- `requestctx`: request-scoped context helpers and metadata middleware
- `render`: JSON response helpers
- `security`: bearer token extraction, scope helpers, auth flow helpers

## Local development

While the module is developed in the same workspace as a service, use a local replace:

```go
require github.com/Dem0n3D/oapi-httpx v0.0.0

replace github.com/Dem0n3D/oapi-httpx => ../oapi-httpx
```

After publishing a tag, the `replace` directive can be removed.

## Releases

Releases are published by GitHub Actions with `go-semantic-release`.

- push commits to `main` using Conventional Commits (`feat:`, `fix:`, `perf:`, `BREAKING CHANGE:`)
- the workflow runs tests, calculates the next version and creates a GitHub Release with generated notes
