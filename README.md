# Spekto

<p align="center">
  <img src="docs/images/spekto_circular.png" alt="Spekto logo" width="220" />
</p>

Spekto is a Go CLI for API security scanning across REST, GraphQL, and gRPC.

Current repository scope:

- `cmd/spekto` — `discover` and `scan` entry points
- `internal/protocol/rest` — ingests Swagger `2.0` and OpenAPI `3.0.x`, `3.1.x`, `3.2.x`
- `internal/protocol/graphql` — ingests SDL and standard introspection JSON
- `internal/protocol/grpc` — ingests `.proto`, descriptor sets, and reflection
- `internal/inventory` — merges spec, traffic, active, and manual sources into one canonical inventory; normalizes dynamic path segments from observed traffic
- `internal/seed` — generates request candidates from inventory metadata and operator hints; persists successful requests as seeds
- `internal/executor` — executes inventory-backed REST, GraphQL, and unary gRPC requests; writes evidence bundles with coverage diagnostics
- `internal/rules` — rule engine with 38 security rules across REST, GraphQL, and gRPC; injection, TLS, and disclosure checks; stateful authorization via `--stateful`
- `internal/report` — SARIF 2.1.0 output, coverage summary JSON, and human-readable stderr summary

Current runtime limits:

- gRPC execution is unary only; streaming gRPC methods are skipped
- stateful checks (BOLA001, BFLA001) require `--stateful` and at least two configured auth contexts

## Build

```bash
go build -o spekto ./cmd/spekto
```

Release builds set the version with ldflags:

```bash
go build -trimpath -ldflags="-s -w -X main.version=v1.1" -o spekto ./cmd/spekto
```

## Install

From source:

```bash
go install github.com/Shasheen8/Spekto/cmd/spekto@latest
```

From a release archive:

```bash
version=v1.1
curl -fsSL "https://github.com/Shasheen8/Spekto/releases/download/${version}/spekto_${version}_linux_amd64.tar.gz" -o spekto.tar.gz
curl -fsSL "https://github.com/Shasheen8/Spekto/releases/download/${version}/checksums.txt" -o checksums.txt
grep " spekto_${version}_linux_amd64.tar.gz$" checksums.txt | sha256sum -c -
tar -xzf spekto.tar.gz
install -m 0755 "spekto_${version}_linux_amd64/spekto" /usr/local/bin/spekto
```

## Commands

### `version`

Print the Spekto version. Local builds print `dev`; release builds set this at
build time.

```bash
./spekto version
./spekto --version
```

### `discover spec`

Build canonical inventory from protocol-native inputs. Discovery writes the
inventory JSON artifact and prints a complete operation list to stderr by
default, including method counts and each operation's documented response
status codes, so operators can immediately see every endpoint Spekto found.

Flags:

- `--openapi`
- `--graphql-schema`
- `--proto`
- `--proto-import-path`
- `--descriptor-set`
- `--grpc-reflection`
- `--out`

Example:

```bash
./spekto discover spec --openapi openapi.yaml --graphql-schema schema.graphql --descriptor-set api.pb --out inventory.json
```

### `discover traffic`

Build canonical inventory from observed traffic. Numeric and UUID path segments
are automatically normalized (`/users/42` → `/users/{id}`) so multiple observations
of the same operation collapse to one record.

Flags:

- `--har`
- `--postman`
- `--access-log`
- `--out`

Example:

```bash
./spekto discover traffic --har traffic.har --postman collection.json --access-log access.jsonl --out observed.json
```

### `discover manual`

Build canonical inventory from curated YAML or JSON seeds.

Flags:

- `--seed`
- `--out`

Example:

```bash
./spekto discover manual --seed manual-endpoints.yaml --out manual.json
```

### `discover active`

Run bounded active discovery against common spec and GraphQL paths.

Flags:

- `--base-url`
- `--grpc-reflection`
- `--out`

Example:

```bash
./spekto discover active --base-url https://api.example.com --grpc-reflection grpc.example.com:443 --out active.json
```

### `discover merge`

Merge existing canonical inventory files.

Flags:

- `--inventory`
- `--out`

Example:

```bash
./spekto discover merge --inventory spec.json --inventory observed.json --inventory manual.json --out merged.json
```

### `scan`

Execute scoped requests, capture seeds, and run security rules.

Flags:

- `--config`
- `--inventory` — canonical inventory JSON file path; advanced/reproducible path
- `--openapi` — OpenAPI or Swagger file path; runs discovery before scanning
- `--graphql-schema` — GraphQL SDL or introspection JSON file path
- `--proto`
- `--proto-import-path`
- `--descriptor-set`
- `--grpc-reflection`
- `--out-dir` — default artifact directory for scan outputs; defaults to `spekto-artifacts` when scanning from spec inputs
- `--target` — target name to include (repeatable)
- `--exclude-target` — target name to exclude (repeatable)
- `--auth-context` — auth context name to include (repeatable)
- `--operation` — operation ID or locator substring to include (repeatable)
- `--tag` — tag to include, OR logic (repeatable)
- `--concurrency`
- `--request-budget`
- `--timeout`
- `--body-capture` — `redacted` (default) or `full`
- `--follow-redirects`
- `--allow-write` — allow mutating seed requests; default scans skip `POST`, `PUT`, `PATCH`, `DELETE`
- `--allow-unsafe-rules` — allow destructive, crash, and resource-exhaustion probes
- `--allow-live-ssrf` — allow live cloud metadata SSRF probes
- `--seed-store` — path to seed store JSON; captures successful requests
- `--findings-out` — path to findings JSON; otherwise findings are shown in the stderr summary only
- `--no-rules` — skip rule-based scanning after seeding
- `--stateful` — enable stateful authorization checks (BOLA001, BFLA001); requires ≥2 auth contexts
- `--allow-write-stateful` — include mutating methods in stateful checks (use with caution)
- `--sarif-out` — output path for SARIF findings (for GitHub Advanced Security)
- `--coverage-out` — output path for coverage summary JSON
- `--dry-run` — print what would be scanned without sending any requests
- `--out`

`scan` always prints a human-readable summary to stderr with seeded coverage, findings, skipped-rule state, and artifact paths. Use `--findings-out` when CI needs machine-readable findings JSON.

Example:

```bash
./spekto scan \
  --config spekto.yaml \
  --openapi openapi.yaml \
  --out-dir spekto-artifacts
```

Advanced/reproducible two-step flow:

```bash
./spekto discover spec --openapi openapi.yaml --out inventory.json
./spekto scan \
  --config spekto.yaml \
  --inventory inventory.json \
  --target rest-prod \
  --auth-context prod-bearer \
  --operation GET:/v1/models \
  --seed-store seeds.json \
  --findings-out findings.json \
  --out evidence.json
```

Minimal config:

```yaml
targets:
  - name: rest-prod
    protocol: rest
    base_url: https://api.example.com
  - name: graphql-prod
    protocol: graphql
    endpoint: https://api.example.com/graphql
  - name: grpc-prod
    protocol: grpc
    endpoint: grpc.example.com:443

auth_contexts:
  - name: prod-bearer
    bearer_token_env: PROD_TOKEN

scan:
  safety_level: read_only
  allow_write: false
  allow_unsafe_rules: false
  allow_live_ssrf: false
  body_capture: redacted
  follow_redirects: false
  concurrency: 4
  request_budget: 200
  timeout: 5s
  retries: 1
  rate_limit: 5
  max_response_bytes: 65536
  # Restrict scanning to approved hostnames. Supports wildcards (*.example.com).
  # When set, any target whose host is not in this list is rejected before
  # any requests are sent.
  target_allowlist:
    - api.together.ai
    - api.together.xyz

# Operator-provided seed values (optional).
# path_params and query_params are matched by exact parameter name.
# constants act as a fallback pool across all parameter locations,
# including GraphQL argument names.
resource_hints:
  path_params:
    model_id: "meta-llama/Llama-3.3-70B-Instruct-Turbo"
  constants:
    org_id: "org_abc123"

output:
  seed_store_path: seeds.json
  findings_path: findings.json
  sarif_path: findings.sarif
  coverage_path: coverage.json
```

A full production config template is available at [`spekto.example.yaml`](spekto.example.yaml).

By default, Spekto is read-only: mutating seed requests are skipped, unsafe rule probes are disabled, live metadata SSRF payloads are disabled, and evidence/findings output is redacted with bounded body snippets. Use the explicit opt-in flags above only against approved test targets.

## GitHub Actions

Downstream repositories should use the short scan form in CI:

```bash
spekto scan --config spekto.yaml --openapi openapi.yaml
```

That command runs discovery in-process, writes default artifacts to
`spekto-artifacts/`, and keeps `--inventory` available for advanced workflows
that need a precomputed canonical inventory.

The reusable workflow should pass secrets through environment variables and
avoid printing generated config files. Bearer tokens are typically exposed as
`PROD_BEARER_TOKEN` and referenced from `spekto.yaml` with `bearer_token_env`.

Example downstream workflow:

```yaml
name: Spekto API Security

on:
  workflow_dispatch:
  pull_request:

jobs:
  scan:
    uses: Shasheen8/Spekto/.github/workflows/spekto-reusable.yml@v1.1
    with:
      spekto_version: v1.1
      openapi: openapi.yaml
      target_name: rest-prod
      protocol: rest
      base_url: https://api.example.com
      operation: ''
      no_rules: false
      upload_sarif: true
    secrets:
      bearer_token: ${{ secrets.PROD_BEARER_TOKEN }}
```

## Pre-flight check

Before a production scan, use `--dry-run` to verify configuration without sending requests:

```bash
./spekto scan --config spekto.yaml --openapi openapi.yaml --dry-run
```

## Local Validation

Before release or PR review, run:

```bash
go test ./...
go vet ./...
go test -race ./...
go test -cover ./...
govulncheck ./... # optional, when installed
```

## Security Rules

`scan` runs security rules automatically after seeding. Use `--no-rules` to skip.

| ID | Rule | Protocols |
|---|---|---|
| AUTH001 | Authentication bypass | REST, GraphQL |
| AUTH002 | Invalid authentication accepted | REST, GraphQL |
| JWT001 | JWT `alg=none` | REST, GraphQL |
| JWT002 | JWT null signature | REST, GraphQL |
| JWT003 | JWT blank HMAC secret | REST, GraphQL |
| JWT004 | JWT weak HMAC secret (13 common values) | REST, GraphQL |
| JWT005 | JWT signature accepted after KID mutation | REST, GraphQL |
| JWT006 | JWT signature not verified | REST, GraphQL |
| HDR001 | Security headers (HSTS, CSP, X-Frame-Options) | REST, GraphQL |
| HDR002 | CORS misconfiguration | REST, GraphQL |
| HDR003 | TRACE/TRACK method enabled | REST, GraphQL |
| HDR004 | HTTP method override | REST only |
| HDR005 | IP source bypass | REST, GraphQL |
| PARAM001 | Privilege escalation via query parameter | REST only |
| BODY001 | Mass assignment | REST only |
| GQL001 | GraphQL introspection without authentication | GraphQL only |
| GQL002 | GraphQL authentication bypass | GraphQL only |
| GQL003 | GraphQL batch query abuse | GraphQL only |
| GRPC001 | gRPC method accessible without authentication | gRPC only |
| GRPC002 | gRPC method accepts invalid auth metadata | gRPC only |
| GRPC003 | gRPC server reflection exposed without authentication | gRPC only |
| GRPC004 | gRPC error response leaks internal details | gRPC only |
| BOLA001 | Broken Object Level Authorization (cross-context read) | REST (`--stateful`) |
| BFLA001 | Broken Function Level Authorization (cross-context write) | REST (`--stateful --allow-write-stateful`) |
| INJ001 | Server error on null/invalid input | REST |
| INJ002 | SQL injection | REST |
| INJ003 | NoSQL injection | REST |
| INJ004 | Command injection | REST |
| INJ005 | Path traversal | REST |
| INJ006 | SSRF | REST |
| SEC001 | Default credentials | REST (basic auth) |
| SEC002 | Server crash on malformed input | REST |
| SEC003 | PII / sensitive data disclosure | REST, GraphQL |
| SEC004 | Resource exhaustion / algorithmic complexity | REST |
| TLS001 | Weak TLS version (1.0 or 1.1) | HTTPS endpoints |
| TLS002 | Broken or risky cipher suite | HTTPS endpoints |
| TLS003 | Expired TLS certificate | HTTPS endpoints |
| TLS004 | Invalid TLS certificate chain | HTTPS endpoints |

## Inputs

- Swagger `2.0`
- OpenAPI `3.0.x`, `3.1.x`, `3.2.x`
- GraphQL SDL
- GraphQL introspection JSON
- `.proto` files
- descriptor sets
- gRPC reflection targets
- HAR
- Postman collections
- JSON or JSONL access-log extracts
- manual YAML or JSON seed files

## Outputs

`discover` writes canonical inventory JSON with stable operation IDs, protocol
locators, provenance flags, confidence scores, auth hints, schema references,
protocol-specific metadata, and derived signals (`specified_but_unseen`,
`observed_but_undocumented`).

`scan` writes structured artifacts when paths are configured:

**Evidence bundle** (`--out`):
- target and protocol per result
- operation ID and locator
- selected auth context
- full request and response evidence (headers, body, timing)
- schema gaps — parameter names where only a type fallback was used
- summary and coverage report with per-result block reason classification

**Findings** (`--findings-out`, optional):
- rule ID, severity, and confidence
- OWASP API Top 10 category and CWE
- seed evidence (the baseline request that succeeded)
- probe evidence (the mutated request that triggered the finding)
- remediation guidance
- summary by severity and rule

A human-readable summary is always printed to stderr after a scan showing coverage %, per-protocol counts, skipped-rule state, findings, artifact paths, and schema gap hints.

When `--seed-store` is set, successful requests are persisted keyed by (operation, auth context). The store is additive — re-running a scan updates only records that succeed.

**Coverage summary** (`--coverage-out`) contains per-protocol and per-auth-context breakdowns and a deduplicated schema gap list.

**SARIF** (`--sarif-out`) is a SARIF 2.1.0 document accepted by GitHub Advanced Security for display in the Security tab. Upload it as a code-scanning artifact from the GHA workflow.

## Safety Defaults

- no brute-force path spraying
- active HTTP discovery is limited to common spec and GraphQL entrypoints
- gRPC active discovery only uses explicit reflection targets
- HTTP redirects are disabled by default
- HTTP retries are limited to safe methods (GET, HEAD, OPTIONS)
- response bodies are size-bounded (default 64 KB)
- request execution uses bounded worker pools and optional rate limiting
- credentials are redacted from headers, cookies, and API-key query params in all evidence
- rule probe budget is capped per seed (default 50 probes)

## Development

```bash
go test ./...
go vet ./...
```
