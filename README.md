# Spekto

<p align="center">
  <img src="docs/images/spekto_circular.png" alt="Spekto logo" width="220" />
</p>

Spec-first API security in Go.

Spekto builds a canonical API inventory across `REST`, `GraphQL`, and `gRPC`, using specs, traffic artifacts, curated seeds, and safe active discovery. It is designed for local CLI use and for automation in CI or GitHub Actions.

## What It Does

Spekto is built around one inventory model that can:

- ingest OpenAPI, Swagger, GraphQL SDL or introspection, gRPC proto, descriptor sets, and gRPC reflection
- ingest HAR, Postman collections, and JSON or JSONL access-log extracts
- ingest curated YAML or JSON seed files
- run bounded active discovery for common spec and GraphQL entrypoints plus explicit gRPC reflection targets
- merge overlapping sources into one canonical inventory
- preserve provenance and confidence for each discovered operation
- execute inventory-backed requests across `REST`, `GraphQL`, and unary `gRPC`
- emit one evidence bundle format for CLI and CI runs

## Build

```bash
go build -o spekto ./cmd/spekto
```

Or run a command directly:

```bash
go run ./cmd/spekto discover spec --openapi openapi.yaml
```

## Commands

- `spekto discover spec`
- `spekto discover traffic`
- `spekto discover manual`
- `spekto discover active`
- `spekto discover merge`
- `spekto scan`

### `discover spec`

Build inventory from protocol-native specification inputs.

Supported flags:

- `--openapi`
- `--graphql-schema`
- `--proto`
- `--proto-import-path`
- `--descriptor-set`
- `--grpc-reflection`
- `--out`

Example:

```bash
./spekto discover spec \
  --openapi openapi.yaml \
  --graphql-schema schema.graphql \
  --descriptor-set api.pb \
  --out inventory.json
```

### `discover traffic`

Build inventory from observed traffic artifacts.

Supported flags:

- `--har`
- `--postman`
- `--access-log`
- `--out`

Example:

```bash
./spekto discover traffic \
  --har traffic.har \
  --postman collection.json \
  --access-log access.jsonl \
  --out observed.json
```

### `discover manual`

Build inventory from curated endpoint seeds.

Supported flags:

- `--seed`
- `--out`

Example:

```bash
./spekto discover manual \
  --seed manual-endpoints.yaml \
  --out manual.json
```

### `discover active`

Run bounded active discovery against safe targets.

Supported flags:

- `--base-url`
- `--grpc-reflection`
- `--out`

Example:

```bash
./spekto discover active \
  --base-url https://api.example.com \
  --grpc-reflection grpc.example.com:443 \
  --out active.json
```

### `discover merge`

Merge previously generated canonical inventory files.

Supported flags:

- `--inventory`
- `--out`

Example:

```bash
./spekto discover merge \
  --inventory spec.json \
  --inventory observed.json \
  --inventory manual.json \
  --out merged.json
```

## Supported Inputs

### REST

- Swagger `2.0`
- OpenAPI `3.0.x`
- OpenAPI `3.1.x`
- OpenAPI `3.2.x`

### GraphQL

- SDL
- standard introspection JSON

### gRPC

- `.proto` files
- descriptor sets
- server reflection

### Traffic and Curated Sources

- HAR
- Postman collections
- JSON or JSONL access-log extracts
- manual YAML or JSON seed files

## Output

Spekto emits:

- canonical inventory JSON for discovery workflows
- evidence bundle JSON for scan workflows

Each operation includes:

- stable operation ID
- protocol and locator
- provenance flags
- confidence score
- auth hints
- schema references
- protocol-specific metadata
- derived inventory signals

Current derived signals include:

- `specified_but_unseen`
- `observed_but_undocumented`

Scan results include:

- target and protocol
- operation ID and locator
- selected auth context
- request evidence with redacted headers
- response evidence with truncation flags
- bundle summary by target and protocol

## `scan`

Execute scoped requests from a canonical inventory using a config file.

Supported flags:

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
./spekto scan \
  --config spekto.yaml \
  --inventory inventory.json \
  --target rest-prod \
  --auth-context prod-bearer \
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
    bearer_token_env: TOGETHER_TOKEN

scan:
  concurrency: 4
  request_budget: 200
  timeout: 5s
  retries: 1
  rate_limit: 5
  max_response_bytes: 65536
```

## Safety Model

Spekto keeps discovery and execution bounded by default:

- no broad brute-force path spraying
- active HTTP probing only checks common spec and GraphQL entrypoints
- gRPC active discovery only uses reflection targets you pass explicitly
- inventory generation is read-only
- request execution uses timeouts, bounded response reads, and worker limits
- HTTP redirects are disabled by default
- HTTP retries are limited to safe methods
- scan output redacts credentials from headers, cookies, and API-key query params
- gRPC execution is limited to unary methods in the current runtime

## Why Spekto

Most API tools are either spec parsers or payload runners. Spekto is meant to bridge the gap: build one inventory from what is documented, what is observed, and what is actually exposed, then use that inventory as the basis for later security checks.

## Development

Run the test suite:

```bash
go test ./...
```
