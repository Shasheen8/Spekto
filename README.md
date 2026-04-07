# Spekto

<p align="center">
  <img src="docs/images/spekto_circular.png" alt="Spekto logo" width="220" />
</p>

Spekto is a Go CLI for API inventory and bounded protocol execution.

Current repository scope:

- `cmd/spekto` provides `discover` and `scan`
- `internal/protocol/rest` ingests Swagger `2.0` and OpenAPI `3.0.x`, `3.1.x`, and `3.2.x`
- `internal/protocol/graphql` ingests SDL and standard introspection JSON
- `internal/protocol/grpc` ingests `.proto`, descriptor sets, and reflection
- `internal/inventory` merges spec, traffic, active, and manual sources into one canonical inventory
- `internal/executor` executes inventory-backed `REST`, `GraphQL`, and unary `gRPC` requests and writes one evidence bundle format

Current runtime limits:

- `scan` is an execution core, not a vulnerability engine yet
- `gRPC` execution is unary only
- streaming `gRPC` methods are skipped

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

Build canonical inventory from observed traffic.

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

Run bounded active discovery.

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

Execute scoped requests from a canonical inventory using config-defined targets and auth contexts.

Flags:

- `--config`
- `--inventory`
- `--target`
- `--exclude-target`
- `--auth-context`
- `--concurrency`
- `--request-budget`
- `--timeout`
- `--follow-redirects`
- `--out`

Example:

```bash
./spekto scan --config spekto.yaml --inventory inventory.json --target rest-prod --auth-context prod-bearer --out evidence.json
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
    bearer_token_env: TOGETHER_TOKEN

scan:
  concurrency: 4
  request_budget: 200
  timeout: 5s
  retries: 1
  rate_limit: 5
  max_response_bytes: 65536
```

## Inputs

Spekto currently accepts:

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

`discover` writes canonical inventory JSON with:

- stable operation IDs
- protocol locators
- provenance flags
- confidence
- auth hints
- schema references
- protocol-specific metadata
- derived signals such as `specified_but_unseen` and `observed_but_undocumented`

`scan` writes evidence bundle JSON with:

- target and protocol
- operation ID and locator
- selected auth context
- request evidence
- response evidence
- summary by target and protocol

## Safety Defaults

- no brute-force path spraying
- active HTTP discovery is limited to common spec and GraphQL entrypoints
- gRPC active discovery only uses explicit reflection targets
- HTTP redirects are disabled by default
- HTTP retries are limited to safe methods
- response bodies are size-bounded
- request execution uses worker limits and optional rate limiting
- credentials are redacted from headers, cookies, and API-key query params

## Development

```bash
go test ./...
go vet ./...
```
