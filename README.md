# Spekto

<p align="center">
  <img src="docs/images/spekto_circular.png" alt="Spekto logo" width="220" />
</p>

<p align="center">
  <a href="https://github.com/Shasheen8/Spekto/actions/workflows/ci.yml"><img src="https://github.com/Shasheen8/Spekto/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://go.dev/dl/"><img src="https://img.shields.io/badge/Go-1.26.2-00ADD8?logo=go&logoColor=white" alt="Go 1.26.2"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License"></a>
  <a href="https://github.com/Shasheen8/Spekto/releases"><img src="https://img.shields.io/badge/Release-v1.x-blue" alt="Release"></a>
</p>

Spec-first API security scanner for REST, GraphQL, and gRPC. Spekto turns specs and observed traffic into a canonical API inventory, seeds safe requests, runs security probes, and emits CLI summaries, evidence, findings, coverage, and SARIF.

## Features

- OpenAPI/Swagger, GraphQL SDL/introspection, `.proto`, descriptor sets, gRPC reflection, HAR, Postman, access logs, and manual seeds.
- Full operation inventory with method counts, response statuses, auth hints, source provenance, and runtime/spec drift signals.
- Read-only defaults: mutating requests, unsafe probes, live metadata SSRF, redirects, and unbounded bodies are off by default.
- Security checks for auth bypass, JWT, CORS, headers, injection, SSRF, BOLA/BFLA, disclosure, TLS, GraphQL, and gRPC.
- CI-ready artifacts under `spekto-artifacts/`: `inventory.json`, `evidence.json`, `coverage.json`, `findings.json`, and `spekto.sarif`.

## Quick Start

```bash
go install github.com/Shasheen8/Spekto/cmd/spekto@latest
```

> [!NOTE]
> The example config uses VAmPI as the public vulnerable testbed.

Use [`spekto.example.yaml`](spekto.example.yaml) as the starting config.

Run:

```bash
spekto scan \
  --config spekto.yaml \
  --openapi ../VAmPI/openapi_specs/openapi3.yml \
  --out-dir spekto-artifacts
```

## Output

```text
Spekto discovery complete
Inventory  14 operations
  rest:     14

Methods
  METHOD    COUNT
  ───────────────
  GET       8
  POST      3
  PUT       2
  DELETE    1

Operations
  PROTOCOL  OPERATION                      AUTH         STATUS       CONFIDENCE  SIGNALS
  ─────────────────────────────────────────────────────────────────────────────────────────────
  rest      GET:/books/v1                  unspecified  200          0.90        in_spec_not_seen_runtime
  rest      GET:/books/v1/{book_title}     required     200,401,404  0.90        in_spec_not_seen_runtime
  rest      POST:/books/v1                 required     200,400,401  0.90        in_spec_not_seen_runtime

Spekto scan complete
Coverage  7/14 operations seeded (50%)
  rest:     7/14
  Blocked   bad_status:1  network_error:6

Findings  159 total
  Severity  CRITICAL:14  HIGH:131  LOW:14

  SEVERITY    RULE            FINDING                                         OPERATION               ENDPOINT
  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  CRITICAL    JWT001          JWT algorithm confusion: alg=none accepted      GET:/books/v1           http://127.0.0.1:5002/books/v1
  HIGH        AUTH001         Authentication bypass                           GET:/users/v1           http://127.0.0.1:5002/users/v1
  HIGH        HDR005          IP-based authentication bypass via              GET:/                   http://127.0.0.1:5002/
                              X-Forwarded-For
  ... 134 more findings omitted (HIGH:120  LOW:14); see findings JSON or SARIF for full details

Artifacts
  coverage:  spekto-artifacts/coverage.json
  evidence:  spekto-artifacts/evidence.json
  findings:  spekto-artifacts/findings.json
  inventory: spekto-artifacts/inventory.json
  sarif:     spekto-artifacts/spekto.sarif
```

Signal labels:

- `in_spec_not_seen_runtime`: listed in the spec, not observed from traffic/manual/runtime inputs.
- `observed_not_in_spec`: observed at runtime or from traffic, missing from the spec.
- `AUTH unspecified`: the source did not clearly declare whether auth is required.
- `CONFIDENCE`: discovery confidence for the operation, not vulnerability confidence.

## GitHub Actions

Use the reusable workflow from downstream repositories:

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
      target_name: rest-api
      protocol: rest
      base_url: https://api.example.com
      upload_sarif: true
    secrets:
      bearer_token: ${{ secrets.SPEKTO_BEARER_TOKEN }}
```

The workflow downloads the pinned release, verifies checksums, writes a temporary `spekto.yaml`, runs:

```bash
spekto scan --config spekto.yaml --openapi openapi.yaml --out-dir spekto-artifacts
```

and uploads `spekto-artifacts/`. If SARIF upload is enabled, findings appear in GitHub code scanning.

## Commands

```bash
spekto version
spekto --version
```

```bash
spekto scan \
  --config spekto.yaml \
  --openapi openapi.yaml

spekto scan \
  --config spekto.yaml \
  --openapi openapi.yaml \
  --dry-run

spekto scan \
  --config spekto.yaml \
  --inventory inventory.json
```

Common scan flags:

| Flag | Purpose |
|------|---------|
| `--config` | Spekto YAML config |
| `--openapi`, `--graphql-schema`, `--proto`, `--descriptor-set`, `--grpc-reflection` | Spec inputs; discovery runs before scanning |
| `--inventory` | Prebuilt canonical inventory |
| `--out-dir` | Artifact directory; defaults to `spekto-artifacts` for spec-input scans |
| `--target`, `--exclude-target`, `--auth-context`, `--operation`, `--tag` | Scope controls |
| `--request-budget`, `--timeout`, `--body-capture` | Runtime controls |
| `--dry-run`, `--no-rules` | Pre-flight / seed-only modes |
| `--allow-write`, `--allow-unsafe-rules`, `--allow-live-ssrf` | Explicit unsafe opt-ins |
| `--stateful`, `--allow-write-stateful` | BOLA/BFLA checks |
| `--out`, `--coverage-out`, `--findings-out`, `--sarif-out`, `--seed-store` | Explicit artifact paths |

```bash
spekto discover spec --openapi openapi.yaml --out inventory.json

spekto discover traffic --har traffic.har --postman collection.json --access-log access.jsonl --out observed.json

spekto discover manual --seed manual-endpoints.yaml --out manual.json

spekto discover active --base-url http://127.0.0.1:5002 --out active.json

spekto discover merge --inventory spec.json --inventory observed.json --inventory manual.json --out merged.json
```

## Reports

| Artifact | Purpose |
|----------|---------|
| `inventory.json` | Canonical API inventory with provenance, auth hints, response statuses, and drift signals |
| `evidence.json` | Redacted request/response evidence and coverage diagnostics |
| `coverage.json` | Per-protocol, per-auth-context, and block-reason coverage summary |
| `findings.json` | Full findings with severity, confidence, evidence, OWASP/CWE metadata, and remediation |
| `spekto.sarif` | SARIF 2.1.0 for GitHub code scanning |

> [!NOTE]
> Artifacts are redacted by default, but can still include endpoint names, parameters, status codes, and security context.

## Safety

> [!WARNING]
> Only scan APIs you own or have explicit permission to test. Spekto sends real requests; even read-only requests can trigger logs, rate limits, alerts, or application side effects.

- Read-only by default; `POST`, `PUT`, `PATCH`, and `DELETE` seeds require `--allow-write`.
- Destructive probes require `--allow-unsafe-rules`.
- Live cloud metadata SSRF probes require `--allow-live-ssrf`.
- Target allowlists reject unapproved hosts before requests are sent.
- Redirects are off by default, retries only apply to safe methods, and response bodies are bounded.

## Rule Coverage

<details>
<summary>Rule catalog</summary>

| ID | Rule | Protocols |
|---|---|---|
| AUTH001 | Authentication bypass | REST, GraphQL |
| AUTH002 | Invalid authentication accepted | REST, GraphQL |
| JWT001 | JWT `alg=none` | REST, GraphQL |
| JWT002 | JWT null signature | REST, GraphQL |
| JWT003 | JWT blank HMAC secret | REST, GraphQL |
| JWT004 | JWT weak HMAC secret | REST, GraphQL |
| JWT005 | JWT signature accepted after KID mutation | REST, GraphQL |
| JWT006 | JWT signature not verified | REST, GraphQL |
| HDR001 | Security headers | REST, GraphQL |
| HDR002 | CORS misconfiguration | REST, GraphQL |
| HDR003 | TRACE/TRACK method enabled | REST, GraphQL |
| HDR004 | HTTP method override | REST |
| HDR005 | IP source bypass | REST, GraphQL |
| PARAM001 | Privilege escalation via query parameter | REST |
| BODY001 | Mass assignment | REST |
| GQL001 | GraphQL introspection without authentication | GraphQL |
| GQL002 | GraphQL authentication bypass | GraphQL |
| GQL003 | GraphQL batch query abuse | GraphQL |
| GRPC001 | gRPC method accessible without authentication | gRPC |
| GRPC002 | gRPC method accepts invalid auth metadata | gRPC |
| GRPC003 | gRPC server reflection exposed without authentication | gRPC |
| GRPC004 | gRPC error response leaks internal details | gRPC |
| BOLA001 | Broken Object Level Authorization | REST (`--stateful`) |
| BFLA001 | Broken Function Level Authorization | REST (`--stateful --allow-write-stateful`) |
| INJ001 | Server error on null/invalid input | REST |
| INJ002 | SQL injection | REST |
| INJ003 | NoSQL injection | REST |
| INJ004 | Command injection | REST |
| INJ005 | Path traversal | REST |
| INJ006 | SSRF | REST |
| SEC001 | Default credentials | REST basic auth |
| SEC002 | Server crash on malformed input | REST |
| SEC003 | PII / sensitive data disclosure | REST, GraphQL |
| SEC004 | Resource exhaustion / algorithmic complexity | REST |
| TLS001 | Weak TLS version | HTTPS |
| TLS002 | Broken or risky cipher suite | HTTPS |
| TLS003 | Expired TLS certificate | HTTPS |
| TLS004 | Invalid TLS certificate chain | HTTPS |

</details>

## Protocol Support

| Protocol | Inputs | Limits |
|----------|--------|--------|
| REST | Swagger `2.0`, OpenAPI `3.x`, HAR, Postman, access logs, manual seeds | Mutating methods skipped by default |
| GraphQL | SDL, introspection JSON | HTTP-backed execution |
| gRPC | `.proto`, descriptor sets, reflection | Unary execution only; streaming methods are skipped |

## Development

```bash
go test ./...
go vet ./...
go test -race ./...
govulncheck ./...
go build -trimpath -o spekto ./cmd/spekto
```

## License

MIT. See [LICENSE](LICENSE).
