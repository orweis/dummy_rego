# Changelog

## 1.0.0 - 2026-11-20

### Breaking
- Policy migrated to Rego v1 syntax (`default allow := false`, `allow if { ... }`).
  It now requires **OPA 1.0 or newer**; OPA 0.x (without `--v0-compatible`) will
  reject it. Decision path and behavior are unchanged. For OPA 0.x, use the
  pre-1.0 revision (commit `c6c329f`).

### Added
- `envoy_test.rego` test suite (`opa test`), GitHub Actions CI, Dependabot for actions.
- README, SECURITY.md, `.gitignore`.

### Security
- Documented that the `Basic charlie` rule is an insecure demo credential granting
  full access. Behavior is intentionally preserved (not removed) to avoid a silent
  change; do not deploy this policy as-is.

## 0.1.0
- Initial import (Rego pre-1.0 syntax).
