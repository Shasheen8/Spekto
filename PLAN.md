# Spekto Plan

## Planning Notes

- Use an external scanner's documentation support matrix before inferring scope from CLI entrypoints or package layout.
- Prefer a full phased roadmap with explicit tasks and subtasks for non-trivial security tooling.
- Keep planning consolidated in this single `PLAN.md` unless execution tracking is explicitly requested.
- Update `PLAN.md` after every push so task status stays aligned with the latest shipped state.

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

- [x] Task 1.1: Canonical operation model
- [x] Task 1.2: REST ingestion contract and initial implementation
- [x] Task 1.3: GraphQL ingestion initial implementation
- [x] Task 1.4: gRPC ingestion initial implementation
- [x] Task 1.5: Supplemental sources initial implementation
- [x] Task 1.6: `discover spec` initial command
- [x] Task 1.7: Merge and dedupe initial implementation
- [ ] Task 1.8: External runtime discovery provider bridge

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

### Task 1.8: External Runtime Discovery Provider Bridge

- [ ] define the provider artifact contract
- [ ] support `Vespasian`-generated `OpenAPI` as a first-class supplemental discovery input
- [ ] support `Vespasian`-generated `GraphQL SDL` as a first-class supplemental discovery input
- [ ] retain provider `capture.json` as a sidecar artifact linked to each discovery run
- [ ] preserve provider provenance through Spekto inventory merge and later coverage reporting
- [ ] defer direct provider-capture ingestion until the artifact bridge is validated on real targets

### Exit Criteria

- one merged inventory report
- one stable inventory serialization format
- one dedupe strategy that works across multiple sources

## Phase 2: Auth, Sessions, and Execution Core

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

### Goal

Deliver the first useful production-ready scanner slice on REST.

### Tasks

- Build REST orchestration
  - inventory -> auth -> seed -> mutate -> report
- Implement first REST rules
  - authentication bypass
  - invalid auth accepted
  - JWT `alg=none`
  - JWT blank secret
  - JWT weak secret
  - JWT null signature
  - JWT signature not verified
  - JWT KID injection
  - security header checks
  - CORS absent or permissive
  - TRACE or TRACK enabled
  - method override enabled
- Build mutation strategies
  - query parameter mutation
  - path parameter mutation
  - header mutation
  - JSON body mutation

### Exit Criteria

- one stable REST scan flow
- replayable findings for the first rule set
- targeted CLI runs for a single endpoint, tag, or service

## Phase 5: GraphQL Coverage

### Goal

Move GraphQL from endpoint checking to schema-aware operation coverage.

### Tasks

- Build concrete operation generation from schema
- Build valid argument generation
- Build first GraphQL rules
  - introspection enabled
  - authentication bypass
  - misconfiguration rules that apply to HTTP transport
- Build resource reuse
  - chain IDs from list or create responses into follow-up operations
  - compare field visibility across auth contexts

### Exit Criteria

- schema-aware GraphQL operation generation
- valid seed generation for queries and mutations
- at least one role-aware GraphQL access check

## Phase 6: gRPC Coverage

### Goal

Add real gRPC support instead of treating it as an afterthought.

### Tasks

- Build reflection-based inventory
- Build proto and descriptor ingestion
- Build unary invocation and evidence capture
- Add initial gRPC checks
  - unauthenticated method access
  - metadata auth handling issues
  - reflection exposure classification
  - error detail leakage
- Add streaming support only after unary stability

### Exit Criteria

- one stable unary gRPC scan path
- reflection and descriptor support
- replayable gRPC evidence in reports

## Phase 7: Stateful Authorization

### Goal

Deliver the checks that matter most beyond basic auth bypass.

### Tasks

- Build resource extraction and linking
  - IDs from responses
  - tenant identifiers
  - ownership hints
- Build multi-context execution
  - anonymous
  - low privilege
  - high privilege
- Implement first stateful rules
  - BOLA
  - BFLA
  - private field access
  - mass assignment candidates
- Build safety controls
  - read-only default
  - explicit opt-in for higher-risk checks
  - request budgets
  - concurrency caps

### Exit Criteria

- at least one reliable cross-role authorization check per protocol where applicable
- no unbounded request expansion

## Phase 8: Reporting, Coverage, and Operator UX

### Goal

Make the tool operationally useful in both CLI and GitHub Actions.

### Tasks

- Build the finding model
  - rule ID
  - severity
  - confidence
  - OWASP and CWE mapping
  - evidence bundle
  - reproduction guidance
- Build the coverage model
  - total inventory by source and protocol
  - successful coverage by auth context
  - blocked and skipped counts with reasons
  - undocumented discovered endpoints
- Build output formats
  - human CLI report
  - JSON
  - SARIF
  - coverage summary
- Build operator diagnostics
  - why an endpoint was skipped
  - why success was not achieved
  - which auth context failed
  - which hints or examples are missing

### Exit Criteria

- CLI output good enough for manual triage
- machine output good enough for CI and GHA ingestion

## Phase 9: Validation and Hardening

### Goal

Validate the scanner, then make it safe enough for recurring production use.

### Tasks

- Build the validation target set
  - `mayhem-demo`
  - `vulnapi` labs where useful
  - safe internal targets
  - auth-heavy targets
- Define benchmarks
  - time to first successful seed
  - successful coverage percentage
  - finding replay rate
  - false-positive review rate
- Harden operator safety
  - target allowlists
  - method safety policy
  - secret redaction
  - artifact retention hygiene
- Harden documentation
  - concise README
  - config reference
  - rule catalog
  - coverage troubleshooting guide

### Exit Criteria

- repeatable scans in GitHub Actions
- stable artifacts and policy gates
- documented safe rollout path for Together production

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
