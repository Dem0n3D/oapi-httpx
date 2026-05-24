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
- `lockboxenv`: Yandex Lockbox payload loader for environment variables

## Yandex Lockbox Environment Variables

`lockboxenv` can load a Lockbox secret payload and export its entries as
process environment variables before the service config is parsed:

```go
result, err := lockboxenv.LoadFromEnvironment(ctx)
if err != nil {
	return err
}
log.Printf("loaded lockbox env keys: %v", result.LoadedKeys)
```

It reads these environment variables:

- `LOCKBOX_SECRET_ID_ENV`: Lockbox secret id. If empty, loading is skipped.
- `LOCKBOX_SECRET_VERSION_ID_ENV`: optional Lockbox secret version id.
- `YC_IAM_TOKEN`: optional IAM token. If empty, the loader requests a token
  from the Yandex Cloud metadata service.

Existing environment variables are not overwritten by default. Use
`lockboxenv.Load` with `OverwriteExisting: true` if a service needs different
behavior.

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
