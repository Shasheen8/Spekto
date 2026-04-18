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
- `internal/rules` — rule engine with 18 security rules across REST and GraphQL

Current runtime limits:

- gRPC execution is unary only; streaming gRPC methods are skipped
- stateful authorization checks (BOLA, BFLA) are Phase 7

## Build

```bash
go build -o spekto ./cmd/spekto
```

## Commands

### `discover spec`

Build canonical inventory from protocol-native inputs.

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
- `--inventory`
- `--target` — target name to include (repeatable)
- `--exclude-target` — target name to exclude (repeatable)
- `--auth-context` — auth context name to include (repeatable)
- `--operation` — operation ID or locator substring to include (repeatable)
- `--tag` — tag to include, OR logic (repeatable)
- `--concurrency`
- `--request-budget`
- `--timeout`
- `--follow-redirects`
- `--seed-store` — path to seed store JSON; captures successful requests
- `--findings-out` — path to findings JSON; defaults to stderr summary when bundle goes to stdout
- `--no-rules` — skip rule-based scanning after seeding
- `--out`

Example:

```bash
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
  concurrency: 4
  request_budget: 200
  timeout: 5s
  retries: 1
  rate_limit: 5
  max_response_bytes: 65536

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
| JWT005 | JWT KID injection | REST, GraphQL |
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

`scan` writes two outputs:

**Evidence bundle** (`--out`):
- target and protocol per result
- operation ID and locator
- selected auth context
- full request and response evidence (headers, body, timing)
- schema gaps — parameter names where only a type fallback was used
- summary and coverage report with per-result block reason classification

**Findings** (`--findings-out`):
- rule ID, severity, and confidence
- OWASP API Top 10 category and CWE
- seed evidence (the baseline request that succeeded)
- probe evidence (the mutated request that triggered the finding)
- remediation guidance
- summary by severity and rule

When `--seed-store` is set, successful requests are persisted keyed by (operation, auth context). The store is additive — re-running a scan updates only records that succeed.

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
