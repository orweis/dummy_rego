# dummy_rego

A small [Open Policy Agent](https://www.openpolicyagent.org/) (Rego) policy for
[Envoy external authorization](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/external_auth.proto)
(ext_authz), deny by default.

> **Demo only - not for production.** One rule allows everything for the static
> header `Authorization: Basic charlie`. See [SECURITY.md](SECURITY.md).

## Behavior

Package `envoy.http.public`, decision `allow` (boolean, default `false`):

| Request | Result |
|---|---|
| `GET /` | allow |
| `GET /?x=1`, `GET /other`, `POST /`, anything else | deny |
| Header `authorization` == `Basic charlie` (exact) | allow (any method/path) |

Paths are compared verbatim; Envoy's path includes the query string. Path-based
rules rely on Envoy path normalization (`normalize_path`, `merge_slashes`).

The OPA-Envoy plugin's default decision path is `envoy/authz/allow`; to use this
policy set the plugin's `path` to `envoy/http/public/allow`.

## Requirements

OPA **1.0 or newer** (Rego v1 syntax). See the migration note below.

## Usage

```sh
opa test -v .        # run tests
opa fmt --list --fail .
opa check --strict .
opa eval -d envoy.rego -i input.json 'data.envoy.http.public.allow'
```

## Migration from 0.x (breaking, v1.0.0)

The policy now uses Rego v1 syntax and no longer loads on OPA 0.x without
`--v0-compatible`. Upgrade OPA to 1.0+, or pin the earlier revision
(`c6c329f`). Policy behavior is unchanged. See [CHANGELOG.md](CHANGELOG.md).

## License

No license file is present; all rights are reserved by default until the owner
chooses one.
