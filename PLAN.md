# Spekto Plan

## Planning Notes

- Use an external scanner's documentation support matrix before inferring scope from CLI entrypoints or package layout.
- Prefer a full phased roadmap with explicit tasks and subtasks for non-trivial security tooling.
- Keep planning consolidated in this single `PLAN.md` unless execution tracking is explicitly requested.
- Update `PLAN.md` after every push so task status stays aligned with the latest shipped state.

## Phase Status

| Phase | Description | Status |
|---|---|---|
| 0 | Scope and design contract | ✅ Complete |
| 1 | Canonical endpoint inventory | ✅ Complete |
| 2 | Auth, sessions, and execution core | ✅ Complete |
| 3 | Seed generation and coverage diagnostics | ✅ Complete |
| 4 | REST vertical slice — 15 security rules | ✅ Complete |
| 5 | GraphQL coverage — 3 GraphQL rules, argument hints | ✅ Complete |
| 6 | gRPC coverage — 4 gRPC rules | ✅ Complete |
| 7 | Stateful authorization — BOLA001, BFLA001 | ✅ Complete |
| 8 | Reporting, coverage, operator UX | ✅ Complete |
| 9 | Validation and hardening | ✅ Complete |

## Objective

Build `Spekto` as a Go API security scanner that works in two operating modes:

- `CLI mode` for local development, focused debugging, manual validation, and targeted scans
- `GitHub Actions mode` for production-safe automated execution, scheduled coverage, scoped pull-request checks, and artifact publishing

The scanner must support `REST`, `GraphQL`, and `gRPC`, with spec-first coverage and discovery-assisted inventory expansion. The tool should be general-purpose, but the first real deployment target is Together production in a tightly controlled, safe configuration.

## Product Principles

- Spec-first, not spec-only
- Successful coverage before deep mutation
- Read-only by default
- Stateful authorization checks only after seed quality is proven
- Shared inventory and rule engine across protocols
- CLI-first architecture with CI and GitHub Actions as execution surfaces, not a separate product
- Reproducible findings with request and response evidence
- Clear coverage accounting so “no findings” is never mistaken for “no risk”

## Operating Model

### Local CLI

Primary use cases:
- inspect inventory
- validate auth setup
- debug a single endpoint or small slice
- run protocol-specific scans
- replay findings

Initial commands:
- `spekto discover`
- `spekto inventory`
- `spekto scan`
- `spekto report`
- `spekto replay`

### GitHub Actions

Primary use cases:
- scheduled scans against approved production-safe targets
- narrow scoped scans on config or spec changes
- artifact publishing for JSON, SARIF, HAR-like evidence, and coverage summaries
- policy gating based on severity, confidence, or coverage regressions

Initial workflow modes:
- scheduled nightly or weekly inventory-plus-scan runs
- manual dispatch for targeted scans
- pull request validation for specs, configs, and rule changes

## Architecture Direction

### Core Components

- `inventory engine`
  - merges specs, introspection, reflection, traffic artifacts, active discovery, and manual endpoint lists
- `external discovery provider bridge`
  - runs out-of-process runtime discovery tools such as `Vespasian`, retains their raw capture artifacts, and feeds generated specs into the inventory engine
- `auth engine`
  - supports bearer tokens, headers, cookies, API keys, basic auth, mTLS, and named auth contexts
- `executor`
  - protocol-neutral orchestration plus protocol-specific transport adapters
- `seed engine`
  - generates valid requests from schemas, examples, and observed traffic
- `rule engine`
  - runs stateless and stateful checks using successful seeds
- `reporting engine`
  - emits human output, JSON, SARIF, and coverage summaries

### Protocol Strategy

- `REST`
  - ingest OpenAPI 3.x and Swagger 2.0
  - detect and support `2.0`, `3.0.x`, `3.1.x`, and `3.2.x`
  - support external refs
  - derive requests from schemas, examples, and observed traffic
- `GraphQL`
  - ingest introspection JSON or SDL
  - generate concrete operations from schema roots
  - support resource reuse across queries and mutations
- `gRPC`
  - ingest reflection, proto files, or descriptor sets
  - support unary first, then streaming
  - inject auth metadata and capture replayable evidence

## Endpoint Discovery Strategy

Endpoint discovery should be a dedicated product capability, exposed through a first-class `discover` command.

### Discovery Goals

- find endpoints and RPCs across `REST`, `GraphQL`, and `gRPC`
- classify where each operation came from
- assign confidence and auth hints
- produce a canonical inventory for `scan` to consume
- highlight inventory gaps before vulnerability checks begin

### Discovery Sources

- `spec-derived`
  - OpenAPI 3.x
  - Swagger 2.0
  - GraphQL introspection or SDL
  - gRPC reflection, proto files, and descriptor sets
- `external-runtime-derived`
  - browser-captured runtime traffic from an out-of-process discovery provider such as `Vespasian`
  - inferred OpenAPI generated from observed `REST` traffic
  - inferred GraphQL SDL generated from observed `GraphQL` traffic
  - retained raw `capture.json` sidecar artifacts for provenance, debugging, and re-generation
- `traffic-derived`
  - HAR
  - Postman
  - access or gateway logs
  - previously successful requests
- `active-discovery-derived`
  - common spec locations
  - common GraphQL paths
  - gRPC reflection probing
  - health, version, and well-known routes
- `manual-derived`
  - curated endpoint inventories
  - exported docs
  - YAML or JSON seed files

### External Runtime Discovery Integration

`Vespasian` is the first planned external runtime discovery provider.

v1 integration shape:

- run `Vespasian` out-of-process against approved web entrypoints
- keep the provider's `capture.json` artifact for provenance and later re-generation
- ingest generated `OpenAPI` and `GraphQL SDL` through Spekto's existing `discover spec` contract
- merge provider-derived inventory with native spec, traffic, active, manual, and `gRPC` sources
- treat provider output as supplemental discovery, not a replacement for canonical inventory merge logic
- defer direct ingestion of provider-native capture format until the artifact bridge proves stable

### Discovery Command Shape

Primary command:
- `spekto discover`

Suggested subcommands:
- `spekto discover spec`
- `spekto discover traffic`
- `spekto discover active`
- `spekto discover merge`

The command should also support a single merged invocation, for example:

```bash
spekto discover \
  --openapi openapi.yaml \
  --graphql-introspection schema.json \
  --grpc-reflection api.example.com:443 \
  --har traffic.har \
  --postman collection.json \
  --out inventory.json
```

### Discovery Output

Every operation in the discovered inventory should record:

- protocol
- method or RPC
- path or service/method
- source
- confidence
- auth hints
- schema quality
- inventory status

Each operation should be classified as one or more of:

- `specified`
- `observed`
- `actively_discovered`
- `manual`

And the merged inventory should highlight:

- `specified but unseen`
- `observed but undocumented`
- `discovered but low-confidence`
- `blocked by missing auth hints`

### Discovery Safety Model

- default to safe discovery
- avoid brute-force endpoint spraying by default
- rate-limit active discovery
- prefer `GET`, `HEAD`, `OPTIONS`, introspection, and reflection
- require explicit opt-in for more aggressive probing
- treat browser-driven runtime discovery as a separate mode from low-noise active probing
- require explicit allowlisted entrypoints, bounded crawl depth, bounded page count, and explicit auth/header injection for production runtime discovery
- retain generated specs and raw capture sidecars per run so inventory changes can be explained and regenerated
- do not couple production runtime discovery to private-network probing or in-process browser execution by default

### Relationship to Scanning

- `discover` builds and normalizes the endpoint map
- `scan` consumes the discovered inventory plus auth contexts and successful seeds
- GitHub Actions can run `discover` first, diff inventory changes, and then decide whether a scan should run
- external runtime discovery runs before or alongside `discover spec`, but Spekto's merged canonical inventory remains the system of record

## OpenAPI Version Support Strategy

OpenAPI handling should be explicitly version-aware.

### Supported Families

- `Swagger 2.0`
- `OpenAPI 3.0.x`
- `OpenAPI 3.1.x`
- `OpenAPI 3.2.x`

### Version Handling Rules

- detect the declared spec version from the document root
- preserve the exact version in inventory and reports
- normalize parser behavior by spec family, not every patch version
- support patch releases within a family without treating them as separate products
- warn when a document is newer than the parser's fully supported family
- attempt partial inventory extraction when full parsing is not yet available and the fallback is safe

### Discovery Behavior

When `discover` finds a spec URL, it should:

1. fetch the document
2. detect the declared version
3. route to the correct parser or normalizer
4. record exact version and support level in the inventory
5. emit a clear warning if support is partial

### Reporting Behavior

Every spec-derived inventory source should include:

- declared OpenAPI or Swagger version
- parser family used
- support level
  - `full`
  - `partial`
  - `unsupported`
- parsing warnings

## Phase 0: Scope and Design Contract

### Status

- [x] Phase 0 complete

### Goal

Define the product boundary so the first implementation does not sprawl.

### Decisions

#### v1 scope

- [x] Define v1 scope

- `REST` is the first-class v1 protocol.
  - required inputs: OpenAPI or Swagger
  - optional enrichment: HAR and observed HTTP traffic
- `GraphQL` is included in v1, but only for schema-aware inventory and a narrow initial rule set.
  - required inputs: introspection JSON or SDL
- `gRPC` is included in v1, but only for unary coverage.
  - required inputs: reflection, proto files, or descriptor sets
- `CLI` is the primary execution surface.
- `GitHub Actions` is the primary production execution surface.
  - no separate service or daemon is part of v1

#### explicit non-goals

- [x] Define explicit non-goals

- no browser crawling
- no SOAP
- no WebSockets
- no mutation-heavy destructive checks by default
- no autonomous credential harvesting
- no streaming gRPC in the first delivery slice
- no broad endpoint brute forcing as a default discovery strategy

#### v1 command contract

- [x] Define v1 command contract

The initial CLI surface is:

- `spekto discover`
- `spekto inventory`
- `spekto scan`
- `spekto report`
- `spekto replay`

Command intent:

- `discover`
  - ingest and merge endpoint sources into canonical inventory
- `inventory`
  - inspect, filter, diff, and export the canonical inventory
- `scan`
  - run rules against discovered inventory using configured auth contexts
- `report`
  - render or transform prior scan outputs
- `replay`
  - rerun a captured finding or request sequence for validation

#### v1 config contract

- [x] Define v1 config contract

Use a single file-based config as the source of truth, with environment variables and CLI flags as overrides.

Preferred format:
- YAML

Override precedence:
1. CLI flags
2. environment variables
3. config file

The first config schema should include:

- target definitions
  - base URL or endpoint
  - protocol
  - allowed discovery modes
- inventory sources
  - OpenAPI or Swagger paths or URLs
  - GraphQL schema or introspection paths or URLs
  - gRPC reflection endpoints, proto paths, descriptor-set paths
  - HAR, Postman, and log inputs
- auth contexts
  - named contexts
  - headers
  - bearer tokens
  - cookies
  - API keys
  - mTLS references
- scan policy
  - enabled rules
  - disabled rules
  - safety level
  - request budget
  - concurrency
  - timeouts
- output configuration
  - JSON path
  - SARIF path
  - evidence path
  - coverage summary path

#### v1 package contract

- [x] Define v1 package contract

Keep top-level packages minimal:

- `cmd/spekto`
- `internal/config`
- `internal/inventory`
- `internal/auth`
- `internal/executor`
- `internal/protocol/rest`
- `internal/protocol/graphql`
- `internal/protocol/grpc`
- `internal/rules`
- `internal/report`

No new top-level packages without a concrete boundary that cannot fit under `internal`.

#### v1 success criteria

- [x] Define v1 success criteria

Coverage and correctness:

- `REST`
  - for a spec-backed target, achieve successful seeded coverage on at least 70% of non-deprecated operations that are in scope and not blocked by missing credentials or known unsafe policies
- `GraphQL`
  - generate inventory from schema and achieve successful seeded coverage for at least one query root and one mutation root when both exist
- `gRPC`
  - ingest unary methods from reflection or descriptors and achieve successful seeded coverage for at least one unary method on a validation target

Finding quality:

- every reported finding must include:
  - rule ID
  - target operation
  - auth context used
  - request and response evidence
  - reproduction guidance
- v1 should optimize for high-confidence findings over broad low-confidence coverage
- no rule should ship without fixture-backed tests and at least one integration validation path

Operational safety:

- read-only mode is the default
- bounded worker pools only
- explicit request budgets per run
- explicit timeouts per request and per scan
- active discovery must be allowlist-friendly and low-noise

#### v1 rule set

- [x] Define v1 rule set

The first required rule set is:

- authentication bypass
- invalid auth accepted
- JWT `alg=none`
- JWT blank secret
- JWT weak secret
- JWT null signature
- JWT signature not verified
- JWT KID injection
- security headers and core HTTP misconfiguration
  - CORS absent or permissive
  - HSTS missing
  - CSP missing
  - frame protections missing
  - TRACE or TRACK enabled
  - method override enabled

#### GitHub Actions contract

- [x] Define GitHub Actions contract

The first production workflow shape is:

- scheduled non-blocking scans on approved low-risk targets
- manual dispatch for targeted scans
- pull request validation for parser, config, and rule changes

GitHub Actions v1 outputs:

- JSON report artifact
- SARIF artifact
- coverage summary artifact
- retained evidence bundle for validated findings

### Phase 0 handoff to Phase 1

- [x] Lock Phase 1 handoff assumptions

Phase 1 should begin with these assumptions fixed:

- the canonical inventory is the system boundary between `discover` and `scan`
- version-aware REST spec parsing is mandatory
- discovery is multi-source and merge-based
- auth contexts are named reusable inputs, not ad hoc flags per rule
- CLI and GitHub Actions use the same config and the same execution engine

### Exit Criteria

- one agreed config format
- one agreed CLI shape
- one agreed v1 rule set
- one agreed definition of successful coverage
- one agreed package boundary for Phase 1 implementation

## Phase 1: Canonical Endpoint Inventory

### Status

- [x] Phase 1 complete

- [x] Task 1.1: Canonical operation model
- [x] Task 1.2: REST ingestion contract and initial implementation
- [x] Task 1.3: GraphQL ingestion initial implementation
- [x] Task 1.4: gRPC ingestion initial implementation
- [x] Task 1.5: Supplemental sources initial implementation
- [x] Task 1.6: `discover spec` initial command
- [x] Task 1.7: Merge and dedupe initial implementation
- [x] Task 1.8: Traffic-derived path normalization

### Goal

Create a single operation inventory model shared across REST, GraphQL, and gRPC.

### Task 1.1: Canonical Operation Model

- [x] Define inventory unit
- [x] Define required fields
- [x] Define protocol-specific fields
- [x] Define ID strategy
- [x] Define provenance model
- [x] Define confidence model
- [x] Define auth hints model
- [x] Define scan readiness state
- [x] Define serialization contract

#### Objective

Define one inventory record shape that every discovery source can populate and every later phase can consume.

#### Inventory unit

The canonical unit is an `operation`.

An operation means:

- one REST method on one normalized path
- one GraphQL root operation shape
- one gRPC service and method pair

It is not:

- a whole service
- a raw URL string without protocol semantics
- a single observed request instance

Observed requests should enrich an operation, not replace it.

#### Required fields

Every operation record must contain:

- `id`
  - stable deterministic identifier
- `protocol`
  - `rest`
  - `graphql`
  - `grpc`
- `family`
  - coarse grouping used by inventory and reporting
  - examples: `http`, `graphql`, `grpc`
- `locator`
  - protocol-specific address of the operation
  - REST: normalized path plus method
  - GraphQL: root type plus operation name or generated signature
  - gRPC: fully qualified service and method
- `display_name`
  - human-readable operation label
- `targets`
  - one or more concrete target endpoints or base URLs where this operation may exist
- `source_refs`
  - references to the discovery sources that produced the record
- `provenance`
  - summarized source classification
- `confidence`
  - normalized confidence score from `0.0` to `1.0`
- `auth_hints`
  - likely auth requirements and available auth metadata
- `schema_refs`
  - request and response schema references where available
- `examples`
  - extracted valid examples and observed seed candidates
- `tags`
  - spec tags, service labels, ownership labels, and operator labels
- `status`
  - inventory state and later scan readiness

#### Protocol-specific fields

REST operations must also contain:

- `method`
- `normalized_path`
- `original_path`
- `path_params`
- `query_params`
- `header_params`
- `cookie_params`
- `request_body`
- `response_map`
- `server_candidates`

GraphQL operations must also contain:

- `root_kind`
  - `query`
  - `mutation`
  - `subscription`
- `operation_name`
- `argument_map`
- `selection_hints`
- `type_dependencies`

gRPC operations must also contain:

- `package`
- `service`
- `rpc`
- `streaming_mode`
  - `unary`
  - `client_stream`
  - `server_stream`
  - `bidi_stream`
- `request_message`
- `response_message`

#### ID strategy

The operation ID must be deterministic and source-independent.

Recommended ID inputs:

- protocol
- canonical locator
- normalized method or RPC signature

Examples:

- REST: `rest:GET:/v1/models/{model_id}`
- GraphQL: `graphql:query:GetModel(id:ID!)`
- gRPC: `grpc:openai.models.v1.ModelService/GetModel`

Do not include:

- hostnames
- credentials
- source file paths
- query string example values

Those belong in source metadata, not identity.

#### Provenance model

Each operation should track both raw provenance and merged provenance.

Raw provenance entries should include:

- source type
  - `spec`
  - `traffic`
  - `active`
  - `manual`
- source location
  - file path
  - URL
  - reflection endpoint
  - log import
- parser family used
- parser warnings
- timestamp of ingestion

Merged provenance should answer:

- was this operation `specified`
- was this operation `observed`
- was this operation `actively_discovered`
- was this operation `manually_seeded`

#### Confidence model

Confidence should be source-driven and monotonic.

Suggested scoring:

- spec plus observed: `1.0`
- spec only: `0.9`
- observed only with repeated sightings: `0.8`
- reflection or introspection only: `0.8`
- active discovery only: `0.5`
- manual seed only without corroboration: `0.4`

Confidence should increase when multiple sources agree and decrease when normalization is partial or parsing has warnings.

#### Auth hints model

The canonical record should not store secrets, but it should store auth expectations and compatible auth contexts.

Fields should include:

- `requires_auth`
  - `yes`
  - `no`
  - `unknown`
- `auth_schemes`
  - bearer
  - api_key_header
  - api_key_query
  - basic
  - cookie
  - mtls
- `auth_context_candidates`
  - names of configured contexts likely to apply
- `auth_source`
  - where the hint came from
  - spec
  - observed traffic
  - operator input

#### Scan readiness state

Inventory status should separate discovery from execution readiness.

Recommended values:

- `discovered`
- `normalized`
- `seedable`
- `blocked_missing_schema`
- `blocked_missing_auth`
- `blocked_unsupported_protocol_feature`

#### Serialization contract

The inventory should serialize to JSON first.

Requirements:

- stable field names
- explicit protocol fields
- explicit nullability for absent schema or auth info
- no secrets in serialized inventory
- deterministic ordering for diff-friendly output

### Task 1.2: REST Ingestion Contract

- [x] Support OpenAPI 3.x ingestion
- [x] Support Swagger 2.0 ingestion
- [x] Detect exact OpenAPI or Swagger version
- [x] Normalize by supported spec family
- [x] Extract operations into canonical inventory records
- [x] Extract request and response schema refs
- [x] Extract auth hints
- [x] Preserve declared version and parser support level
- [x] Resolve external refs robustly across local and remote documents
- [x] Emit partial-support warnings from real parser edge cases

#### Objective

Define the exact behavior for ingesting OpenAPI and Swagger documents into the canonical operation model.

#### Supported inputs

- local files
- HTTPS URLs
- HTTP URLs only when explicitly allowed
- documents with external refs
- JSON or YAML encodings

Supported spec families:

- `Swagger 2.0`
- `OpenAPI 3.0.x`
- `OpenAPI 3.1.x`
- `OpenAPI 3.2.x`

#### Ingestion pipeline

The REST ingestion pipeline should run in this order:

1. fetch or read document
2. detect exact declared version
3. choose parser family
4. resolve refs
5. normalize servers and base paths
6. enumerate operations
7. extract request and response schemas
8. extract auth schemes and per-operation overrides
9. extract examples, enums, defaults, and tags
10. emit canonical operation records plus parser warnings

#### Version handling rules

- preserve the exact declared version
- normalize internal behavior by supported family
- accept patch releases within a supported family
- warn on partial support rather than silently downgrading
- if parsing cannot fully succeed, extract whatever is safe and mark support level as `partial`

#### External reference rules

- support local and remote refs
- detect ref cycles and fail clearly
- cache resolved refs per document load
- preserve the original ref path in source metadata
- if some refs fail, continue partial extraction only when operation boundaries remain unambiguous

#### Server and base URL normalization

Normalize concrete targets separately from operation identity.

Rules:

- collect every declared server candidate
- resolve relative server URLs against the spec location when possible
- normalize duplicate servers
- preserve templated variables and defaults
- never bake hostnames into operation IDs

For Swagger 2.0:

- normalize `schemes`, `host`, and `basePath` into server candidates

For OpenAPI 3.x:

- normalize `servers`
- support per-path and per-operation server overrides

#### Operation extraction rules

For each REST operation, extract:

- method
- original path
- normalized path
- operation ID if present
- summary and description
- deprecated flag
- tags
- parameters grouped by location
- request body schemas and media types
- response status map
- content types accepted and produced

Normalization rules:

- preserve the original path for reporting
- normalize path templates into a canonical form
- keep path parameter names stable
- merge inherited path-level parameters with operation-level parameters
- preserve deprecation status in the canonical record

#### Schema extraction rules

The ingestion layer must extract enough structure for later seed generation.

Required extraction:

- request body schema refs
- response schema refs by status code
- parameter type, format, enum, default, and requiredness
- example values and named examples
- nullable and optional semantics where supported by the spec family

If multiple media types exist:

- prefer JSON-compatible types first
- preserve the full media type map
- mark unsupported media types for later handling instead of dropping them silently

#### Auth extraction rules

Extract both global and operation-specific auth requirements.

Required behavior:

- parse security scheme definitions
- parse global security requirements
- parse per-operation security overrides
- identify anonymous-allowed overrides
- map recognized schemes into canonical auth hints

Unknown or custom auth schemes should be preserved as opaque metadata rather than discarded.

#### Warning and support model

Every ingested document should emit:

- `declared_version`
- `parser_family`
- `support_level`
  - `full`
  - `partial`
  - `unsupported`
- `warnings`

Warnings should include cases such as:

- unsupported newer spec family
- unresolved refs
- invalid parameter inheritance
- unsupported media types
- ambiguous server variables

#### Output of Task 1.2

- [x] Produce canonical REST operation records with normalized metadata

Task 1.2 is complete when REST ingestion can produce canonical operation records with:

- stable IDs
- normalized paths
- server candidates
- request and response schema refs
- parameter metadata
- auth hints
- exact spec version and support level
- parser warnings suitable for CLI and GitHub Actions output

### Task 1.3: GraphQL Ingestion

- [x] Support introspection JSON
- [x] Support SDL
- [x] Extract root operations and argument graphs
- [x] Emit canonical GraphQL operation records
- [x] Attach richer selection hints for later seed generation

### Task 1.4: gRPC Ingestion

- [x] Support server reflection
- [x] Support proto files
- [x] Support descriptor sets
- [x] Extract services, methods, streaming modes, and message schemas

### Task 1.5: Supplemental Sources

- [x] HAR
- [x] Postman
- [x] access-log or gateway-log extracts
- [x] manual YAML or JSON endpoint seeds
- [x] manual endpoint lists such as exported Notion data

### Task 1.6: `discover` Command

- [x] `discover spec`
- [x] `discover traffic`
- [x] `discover active`
- [x] `discover merge`
- [x] inventory export for later `scan` runs

### Task 1.7: Merge and Dedupe

- [x] collapse duplicates
- [x] preserve provenance
- [x] mark `specified but unseen`
- [x] mark `observed but undocumented`

### Task 1.8: Traffic-Derived Path Normalization

- [x] normalize dynamic path segments in traffic sources (UUIDs, integers → `{id}`)
- [x] collapse multiple traffic observations of the same operation into one canonical record
- [x] preserve original path as `OriginalPath` and extracted values as path param examples
- [x] apply normalization consistently across HAR, Postman, and access log parsers

#### Approach

Borrowed the core insight from Vespasian's discovery philosophy — not a file import bridge,
but the underlying principle: traffic observations of different specific IDs should collapse
to one operation with a parameterized path, not N separate operations.

`/v1/users/42` and `/v1/users/87` both normalize to `/v1/users/{id}` with `42` stored
as a path parameter example. This improves operation deduplication, seed generation quality,
and coverage accounting across all traffic sources.

#### Implementation

- `NormalizeTrafficPath` in `internal/inventory/types.go` — detects UUID and integer path
  segments, replaces with `{id}` / `{id2}` placeholders, returns extracted `ParameterMeta`
  and `ParameterValue` examples
- Applied in `har.go`, `postman.go`, `accesslog.go` — spec-derived paths are untouched
- `MergeInventories` in `merge.go` — convenience wrapper for full inventory merges

### Exit Criteria

- [x] one merged inventory report
- [x] one stable inventory serialization format
- [x] one dedupe strategy that works across multiple sources

## Phase 2: Auth, Sessions, and Execution Core

### Status

- [x] Phase 2 complete

### Goal

Build a safe, reusable execution layer for both CLI and GitHub Actions.

### Tasks

- [x] Build config loading and target selection
  - [x] file config
  - [x] environment overrides
  - [x] CLI overrides
  - [x] include and exclude filters
- [x] Build auth abstractions
  - [x] bearer tokens
  - [x] static headers
  - [x] cookies
  - [x] API keys
  - [x] basic auth
  - [x] mTLS
  - [x] named auth contexts and roles
  - [x] operator-provided login flows
- [x] Build request execution
  - [x] retry policy
  - [x] retries limited to safe HTTP methods
  - [x] timeout policy
  - [x] transport security defaults
  - [x] explicit plaintext opt-in for local or test gRPC targets
  - [x] redirect policy
  - [x] bounded worker pools
  - [x] rate limiting
  - [x] response size budgets
  - [x] request correlation IDs
  - [x] secret redaction
  - [x] evidence capture
- [x] Build protocol adapters
  - [x] REST adapter
  - [x] GraphQL adapter
  - [x] gRPC adapter

### Exit Criteria

- [x] one executor that can run scoped requests across all three protocols
- [x] one auth model that supports multiple named contexts
- [x] one evidence bundle format used everywhere
- [x] scan results treat only 2xx and 3xx HTTP responses as success

## Phase 3: Successful Coverage and Seed Generation

### Status

- [x] Phase 3 complete

### Goal

Generate valid, authenticated requests before attempting deeper mutation rules.

### Tasks

- [x] Build candidate request generation
  - [x] use examples (spec and observed traffic via HAR/Postman)
  - [x] use enums and defaults
  - [x] use observed traffic payloads
  - [x] type/format fallbacks with schema gap tracking
- [x] Build seed persistence
  - [x] store successful requests by operation and auth context
  - [x] store provenance for each seed (CapturedAt, Source, Target, AuthContextName)
- [x] Build resource hinting
  - [x] operator-provided constants (apply across all parameter locations)
  - [x] path parameter hints
  - [x] query parameter hints
- [x] Build diagnostics
  - [x] explain why an endpoint never reached success
  - [x] classify by: auth_missing, budget_exceeded, streaming_unsupported, schema_gap, bad_status, network_error

### Implementation Notes

- `internal/seed/generator.go` — `GenerateRESTCandidate` resolves values by priority: resource hint > inventory example > default > enum[0] > type/format fallback
- `internal/seed/store.go` — `Store` type with load/save/add/lookup; one record per (operation, auth context) pair
- `internal/config/config.go` — `ResourceHints` struct (path_params, query_params, constants); `SeedStorePath` in OutputConfig
- `internal/executor/bundle.go` — `CoverageReport` with per-result `CoverageEntry` and `ByReason` counts
- `cmd/spekto/main.go` — `--seed-store` flag; `captureSeeds` captures successful results after scan
- Optional query params are only included when a concrete value exists (avoids spurious 400s from type fallbacks)
- Schema gaps propagate from `Candidate` → `HTTPRequest` → `Result` → `CoverageEntry`
- `HTTPResult.RequestBody` and `HTTPResult.RequestContentType` capture the outgoing payload so evidence and seed records are complete

### Exit Criteria

- [x] successful seed capture for at least one representative target per protocol
- [x] coverage diagnostics that explain blocked endpoints clearly

## Phase 4: REST Vertical Slice

### Status

- [x] Phase 4.1: Rule engine and orchestration
- [x] Phase 4.2: First REST rule set
- [x] Phase 4.3: Mutation strategies and targeted operation scoping

### Goal

Deliver the first useful production-ready scanner slice on REST.

### Tasks

- [x] Build REST orchestration
  - [x] Rule interface, Finding, Probe, FindingSet types (`internal/rules/types.go`)
  - [x] `rules.Scan()` orchestration — seeds → probes → findings (`internal/rules/scan.go`)
  - [x] Pre-resolved auth registry threaded from main.go to avoid double login-flow execution
  - [x] `--findings-out` and `--no-rules` flags on `spekto scan`
  - [x] `findings_path` in OutputConfig with `SPEKTO_OUTPUT_FINDINGS` env override
- [x] Implement first REST rules
  - [x] AUTH001: authentication bypass — strip auth, check if 2xx
  - [x] AUTH002: invalid auth accepted — garbage bearer token, check if 2xx
  - [x] JWT001: `alg=none` — empty signature, algorithm confusion
  - [x] JWT002: null signature — empty signature segment, original header/payload
  - [x] JWT003: blank secret — HMAC-SHA256 with empty key
  - [x] JWT004: weak secret — HMAC-SHA256 with 13 common secrets
  - [x] JWT005: KID injection — path traversal and SQL payloads in kid header
  - [x] JWT006: signature not verified — corrupted non-empty signature, distinct from null sig
  - [x] HDR001: security headers — HSTS (HTTPS only), CSP, X-Frame-Options
  - [x] HDR002: CORS misconfiguration — reflected origin, wildcard, credentials escalation
  - [x] HDR003: TRACE/TRACK enabled — both methods probed, message/http content-type check
  - [x] HDR004: method override — X-HTTP-Method-Override/X-Method-Override/X-HTTP-Method
- [x] Build mutation strategies
  - [x] HDR005: IP source bypass — X-Forwarded-For/X-Real-IP/X-Client-IP without auth
  - [x] PARAM001: privilege escalation params — admin=true/role=admin/debug=true without auth
  - [x] BODY001: mass assignment — inject role/is_admin/admin/superuser into JSON body; compares probe response against seed baseline to avoid pre-existing field false positives
  - path parameter mutation — deferred to Phase 7 (BOLA/IDOR)
- [x] Targeted operation scoping
  - [x] `--operation` flag — match by operation ID or locator substring
  - [x] `--tag` flag — match by tag, OR logic across multiple values
  - [x] `ScanOptions.IncludeOperations` and `ScanOptions.IncludeTags` in executor

### Implementation Notes

- `internal/rules/` — Rule interface, auth.go, jwt.go, headers.go, registry.go, scan.go
- `executor.ScanOptions.Registry` — pre-resolved auth registry; when set, executor skips internal construction
- Import cycle avoided: Bundle carries no `[]Finding`; findings are a separate output file
- Rules run only against REST seeds (`seed.Protocol == "rest"`)
- Probes per seed capped at 50 by default (~39 probes with JWT auth, ~20 without)
- JWT rules skip non-JWT tokens (opaque API keys, etc.)
- `buildJWTProbe` takes a `variant` string so multi-probe rules (JWT004 weak secrets, JWT005 KID payloads) each get a unique correlation ID
- BODY001 uses an ordered field list for deterministic findings; seed response is parsed as baseline — only flags fields that are new or changed to the injected value
- SecurityHeaders checks HSTS only for HTTPS endpoints
- CORS probe sends a dedicated evil.spekto.example.com origin and only flags reflected origins
- `--operation` and `--tag` filtering cascades naturally to rule scan (rules only see seeds from filtered operations)

### Exit Criteria

- [x] one stable REST scan flow
- [x] replayable findings for the first rule set
- [x] targeted CLI runs for a single endpoint, tag, or service

## Phase 5: GraphQL Coverage

### Status

- [x] Phase 5 complete

### Goal

Move GraphQL from endpoint checking to schema-aware operation coverage.

### Tasks

- [x] Build valid argument generation
  - [x] Resource hints by argument name resolve via `constants` map
  - [x] `ID!` arguments use UUID placeholder instead of "sample" to pass format validation
  - [x] `quoteGraphQLValue` wraps hint values correctly for string/ID vs numeric/boolean types
- [x] Build first GraphQL rules
  - [x] GQL001: Introspection accessible without auth — sends `{__schema{queryType{name}}}` unauthenticated
  - [x] GQL002: GraphQL auth bypass — strips auth, rejects error-only responses as proper rejections
  - [x] GQL003: Batch query abuse — sends 10-element batch, flags JSON array response
  - [x] Existing HTTP rules (auth bypass, JWT, CORS, headers, TRACE, IP bypass) now apply to GraphQL seeds
  - [x] REST-only rules (method override, mass assignment, privilege params) skip GraphQL via protocol guard
- [x] Resource hints for argument generation threaded through `ScanOptions` → `scanGraphQLTarget` → `buildGraphQLRequests` → `graphqlQuery`
- [ ] Build resource reuse (chain IDs, compare field visibility across auth contexts) — deferred to Phase 7

### Implementation Notes

- `internal/rules/graphql.go` — GQL001, GQL002, GQL003
- `internal/executor/adapter_http.go` — `graphqlArgValue` resolves by hint name; `graphqlLiteral` uses UUID for ID type; `quoteGraphQLValue` escapes backslash before quote to prevent double-escaping
- GQL002 uses JSON-aware null check (`gqlResponseDataIsNull`) to correctly treat `{"data":null,"errors":[...]}` as an auth rejection, not a bypass
- `rules.Scan` now processes REST and GraphQL seeds; gRPC remains separate
- GraphQL-specific rules guard on `seed.Protocol != inventory.ProtocolGraphQL`
- REST-only rules guard on `seed.Protocol != inventory.ProtocolREST`

### Exit Criteria

- [x] schema-aware GraphQL operation generation (argument types resolved with resource hints)
- [x] valid seed generation for queries and mutations (UUID IDs, proper type literals)
- [x] at least one role-aware GraphQL access check (GQL002: authenticated vs unauthenticated comparison)

## Phase 6: gRPC Coverage

### Status

- [x] Phase 6 complete

### Goal

Add real gRPC security coverage on top of the existing gRPC execution infrastructure.

### Tasks

- [x] Reflection-based inventory (Phase 1 — already complete)
- [x] Proto and descriptor ingestion (Phase 1 — already complete)
- [x] Unary invocation and evidence capture (Phase 2 — already complete)
- [x] Add gRPC security checks
  - [x] GRPC001: unauthenticated method access
  - [x] GRPC002: invalid auth metadata accepted
  - [x] GRPC003: server reflection accessible without authentication
  - [x] GRPC004: error response leaks internal implementation details
- Streaming gRPC — deferred (unary stability established)

### Implementation Notes

- `executor.ProbeGRPCMethod` — single deadline covers dial + reflection resolution + invocation; `extraMeta` applied as outgoing metadata
- `executor.ProbeGRPCReflection` — accepts explicit `timeout` parameter; single deadline covers dial + `ListServices`
- `rules.GRPCScan` — separate orchestrator; deduplicates GRPC001/002 per `operationID` and GRPC003 per endpoint to avoid redundant probes when multiple auth contexts seed the same method
- GRPC004 is a static check on existing evidence (no probe); runs on all gRPC results including failures
- GRPC001/002 require the seed to have used auth (nothing to bypass otherwise)

### Exit Criteria

- [x] gRPC security rules running against unary methods
- [x] reflection and descriptor support (Phase 1)
- [x] replayable gRPC evidence in reports (Phase 2)

## Phase 7: Stateful Authorization

### Status

- [x] Phase 7 complete

### Goal

Deliver the checks that matter most beyond basic auth bypass.

### Tasks

- [x] Build multi-context execution — probe the same operation with every alternative auth context in the registry
- [x] Implement first stateful rules
  - [x] BOLA001: Broken Object Level Authorization — cross-context read access
  - [x] BFLA001: Broken Function Level Authorization — cross-context write access (opt-in)
  - private field access — deferred to Phase 8 (requires response field comparison)
  - mass assignment candidates — partially covered by BODY001 (Phase 4)
- [x] Build safety controls
  - [x] read-only default — write checks disabled unless `--allow-write-stateful` is passed
  - [x] explicit opt-in — stateful checks disabled unless `--stateful` is passed
  - [x] probe budget cap — default 100 cross-context probes per scan, configurable
  - [x] per-operation deduplication — same (operationID, altAuthContext) pair not probed twice

### Implementation Notes

- `internal/rules/stateful.go` — `StatefulScan` orchestrates cross-context HTTP probes via `executor.ExecuteHTTP`
- Requires ≥2 auth contexts in the registry; silently skips if only one context is configured
- Confidence is Medium for both rules — the scanner cannot determine whether two auth contexts should have different access rights; that is the operator's responsibility
- Configure distinct named auth contexts (e.g. `admin` and `user`) to produce actionable findings
- `--stateful` flag enables the check; `--allow-write-stateful` adds write operations

### Exit Criteria

- [x] at least one reliable cross-role authorization check per protocol where applicable (REST BOLA/BFLA)
- [x] no unbounded request expansion (budget cap + deduplication)

## Phase 8: Reporting, Coverage, and Operator UX

### Status

- [x] Phase 8 complete

### Goal

Make the tool operationally useful in both CLI and GitHub Actions.

### Tasks

- [x] Build the finding model
  - [x] rule ID, severity, confidence, OWASP/CWE, evidence, reproduction
- [x] Build the coverage model
  - [x] total inventory by source and protocol (BundleSummary)
  - [x] blocked and skipped counts with reasons (CoverageReport)
  - [x] successful coverage by auth context (AuthBreakdown in CoverageSummary)
  - [x] schema gap list per operation (deduplicated in CoverageSummary)
- [x] Build output formats
  - [x] JSON (evidence bundle + findings)
  - [x] human CLI report (`report.PrintSummary` → stderr after every scan)
  - [x] SARIF (`--sarif-out` / `output.sarif_path`) for GitHub Advanced Security
  - [x] coverage summary JSON (`--coverage-out` / `output.coverage_path`)
- [x] Build operator diagnostics
  - [x] why an endpoint was skipped (block reason in CoverageEntry)
  - [x] schema gaps tracked per result + deduplicated in coverage summary
  - [x] per-auth-context coverage in CoverageSummary.ByAuthContext

### Implementation Notes

- `internal/report/sarif.go` — SARIF 2.1.0; rules deduped and sorted; CVSS-like score strings for GitHub severity mapping
- `internal/report/coverage.go` — `BuildCoverageSummary` derives per-protocol and per-auth breakdowns from bundle results; schema gaps deduplicated by operation
- `internal/report/text.go` — `PrintSummary` writes to stderr always; shows coverage %, per-protocol counts, block reasons, findings by severity, and schema gap hint
- New scan flags: `--sarif-out`, `--coverage-out`; both also read from `output.sarif_path` / `output.coverage_path` in config

### Exit Criteria

- [x] CLI output good enough for manual triage (text summary on stderr after every scan)
- [x] machine output good enough for CI and GHA ingestion (SARIF + coverage JSON)

## Phase 9: Validation and Hardening

### Status

- [x] Phase 9 complete

### Goal

Validate the scanner, then make it safe enough for recurring production use.

### Tasks

- [x] Harden operator safety
  - [x] `scan.target_allowlist` — hostname allowlist with wildcard support (`*.example.com`); rejects non-allowlisted targets before any requests are sent
  - [x] `--dry-run` flag — prints targets, inventory summary, auth contexts, and rule status without executing requests
  - [x] Secret redaction — already in place (Phase 2): Authorization, Cookie, X-Api-Key headers redacted in all evidence
  - [x] Artifact permissions — all output files written at 0600
- [x] GitHub Actions rollout
  - [x] `.github/workflows/spekto-scan.yml` — scheduled (weekly) + manual dispatch workflow; uses env vars for dispatch inputs to prevent injection
  - [x] `spekto.example.yaml` — production config template with allowlist, resource hints, and auth context structure for Together AI
- [x] Harden documentation
  - [x] Concise README with rule catalog and safety defaults
  - [x] Config reference in README (all scan flags and config keys)
  - [x] `--dry-run` for pre-flight validation
- [ ] External validation targets (operational, not code)
  - `mayhem-demo`, `vulnapi` labs — to be run manually against shipped binary
- [ ] Benchmarks — to be defined from real scan runs

### Implementation Notes

- `internal/config/config.go` — `ScanPolicy.TargetAllowlist []string`
- `internal/executor/scan.go` — `validateTargetAllowlist`, `targetHost`, `hostAllowed`; checked before scan begins
- `cmd/spekto/main.go` — `--dry-run`, `--stateful`, `--allow-write-stateful` guards; `printDryRun` outputs plan to stderr
- `.gitignore` — fixed `coverage.*` glob that was incorrectly matching `internal/report/coverage.go`

### Exit Criteria

- [x] repeatable scans in GitHub Actions (workflow file shipped)
- [x] stable artifacts and policy gates (allowlist + dry-run)
- [x] documented safe rollout path for Together production (`spekto.example.yaml`)

## GitHub Actions Rollout Plan

### Step 1: Non-blocking scheduled scans

- run inventory and low-risk rules on approved targets
- upload JSON, SARIF, and coverage artifacts
- review signal quality without gating merges

### Step 2: Manual dispatch scans

- allow operators to target one service, one spec, or one endpoint group
- use this for debugging auth and coverage problems

### Step 3: Pull request validation

- validate specs, config, and rules
- run fixtures and integration targets
- fail only on regressions in parser stability, rule correctness, or safety controls

### Step 4: Policy-gated scheduled scans

- gate on new high-confidence findings
- gate on sharp successful-coverage regressions
- do not gate on low-confidence or unactionable findings

## Immediate Decisions Needed

- which Together targets are safe for the first scheduled scans
- which auth contexts can be used in automation
- which inventory sources are actually available today
- which findings should block in GitHub Actions, if any
- whether SARIF is sufficient or a custom artifact viewer is needed
- which production web entrypoints are safe `Vespasian` crawl targets
- which auth headers or runtime auth contexts may be injected into browser-driven discovery
- how long `capture.json` sidecar artifacts should be retained in CI or scheduled runs
- whether `SOAP` and `WSDL` stay out of Spekto's canonical inventory for v1

## First Build Recommendation

Start with:
- REST
- OpenAPI and HAR ingestion
- `Vespasian`-generated `OpenAPI` and `GraphQL SDL` as supplemental production discovery inputs
- static auth contexts
- retained `capture.json` sidecar artifacts for provenance and re-generation
- successful seed generation
- authentication and JWT rule set
- security header and HTTP misconfiguration checks
- JSON and SARIF reporting
- manual CLI plus non-blocking GitHub Actions scheduled runs

Do not start with:
- broad active endpoint brute forcing
- high-risk mutation flows
- streaming gRPC
- full stateful authz across every target
- in-process embedding of `Vespasian`'s browser stack into Spekto
- direct ingestion of provider-native capture format before the spec bridge is proven
- `SOAP` inventory unification in the first delivery slice

That sequence gets to a usable scanner quickly without baking in the wrong abstractions.
