# Security model and workplace adoption

## Purpose

This document describes Switchboard's current security boundary, its known
limitations, and the work required to introduce it safely in a workplace.

Switchboard is a private capability gateway. It presents one curated MCP
endpoint backed by independently secured MCP servers and application APIs.
Switchboard owns transport, capability composition, discovery, and API
adaptation. Upstream applications remain responsible for business rules,
authorization, confirmation workflows, auditing, and durable state.

```text
MCP client
   | HTTPS and client authentication
   v
Corporate ingress or reverse proxy
   | loopback or protected service traffic
   v
Switchboard
   | identity-to-profile policy and capability routing
   | separate downstream credentials
   v
Upstream MCP server or application API
   | application authorization, validation, audit, and state
```

## Current security model

### Client authentication and sessions

- HTTP deployments can use a legacy shared bearer credential on `/mcp`.
- The preferred `/mcp/sessions` endpoint supports a distinct bearer credential
  for each client installation. Client tokens must contain at least 32 bytes.
- The same endpoint can instead validate short-lived, audience-bound JWT access
  tokens from a configured OAuth/OIDC issuer. It publishes RFC 9728 protected
  resource metadata for MCP client discovery.
- Authentication is checked on every request using constant-time digest
  comparison for static tokens or issuer/JWKS validation for OAuth tokens.
- Each MCP session is bound to the authenticated client identity. A session ID
  presented by another identity is rejected.
- Session creation is limited globally and per client. Sessions expire after an
  idle timeout and after an absolute 24-hour lifetime.
- Session requests are limited to 1 MiB.
- Cross-origin protection and an explicit trusted-origin list protect HTTP
  transport. A deployment behind a loopback reverse proxy must ensure that
  untrusted clients cannot reach the loopback listener directly.

### Capability authorization

Operator configuration maps each authenticated client to:

- an allowed profile;
- a discovery permission;
- an execution permission; and
- a session activation permission.

These permissions default to false. The policy is supplied by the operator and
cannot be selected through MCP tool arguments.

Profiles limit which capabilities a client may discover and execute. Session
activation can reduce the active tool surface, but it cannot add a capability
outside the client's profile. Disabling a capability is synchronized with
in-flight calls, and stale client-side tool definitions cannot be used to bypass
the disabled state.

The `capability_execute` compatibility tool is narrower than native tool
execution. It accepts only selected remote MCP tools that are explicitly
annotated read-only and non-destructive, validates arguments against the
discovered schema, and rejects unresolved external schema references. The
caller cannot supply an arbitrary upstream endpoint or upstream tool name.

### Upstream connections and secrets

- Upstream endpoints and credentials are operator-controlled, not supplied by
  MCP callers.
- Capability manifests reference environment variables rather than containing
  credential values.
- Remote MCP connections support static authorization headers or OAuth client
  credentials. OAuth token endpoints must use HTTPS.
- Inbound client credentials are not passed through to downstream services.
  Switchboard obtains or injects a separate credential for each upstream.
- Normal TLS verification applies unless an operator explicitly enables
  `insecure_skip_verify` for a capability.
- Remote MCP tool allowlists can restrict the tools imported from an upstream.
- Annotation override rules fail startup when a selected upstream tool is
  unclassified or ambiguously classified.
- REST path arguments are URL-escaped, REST redirects are rejected, calls have
  bounded timeouts, and upstream responses are limited to 8 MiB.

### Runtime containment

The supplied systemd deployment runs as an unprivileged `switchboard` account
and enables filesystem, device, namespace, kernel, privilege, and executable
memory restrictions. Configuration and secret environment files are installed
as root-owned, group-readable mode `0640` files.

## Trust boundaries and limitations

Switchboard is a meaningful security boundary, but it is not a complete
workplace authorization system.

### Shared downstream identity

Upstream MCP sessions and credentials are shared by the gateway. The individual
Switchboard client identity is not currently forwarded to upstream
applications. The upstream normally sees the Switchboard service identity, not
the employee or agent that initiated the call.

This is acceptable for a deliberately scoped read-only service account. It is
not sufficient when an upstream must make user-specific authorization decisions
or produce individual attribution.

### Coarse execution permission

Profiles authorize capabilities. A client without an explicit tool policy can
call all native tools registered by an active capability, including mutating or
destructive tools. An optional versioned tool policy restricts a client to exact
operator-selected tool names; omitted tools deny by default.

MCP behavior annotations such as read-only, destructive, and idempotent are
primarily metadata for clients. They are not a universal authorization or
confirmation mechanism. Upstream applications must continue enforcing revision
checks, plan identifiers, authorization, explicit confirmation, and rollback
rules.

### Legacy endpoint

If the legacy `/mcp` bearer endpoint remains enabled, its holder receives the
static deployment profile rather than the finer per-client session policy. It
should be retired after clients migrate to authenticated sessions.

### Transport and content risks

- TLS termination is external to the Switchboard process in the supplied
  deployment, so the reverse proxy and isolation of the loopback listener are
  part of the security boundary.
- REST, remote MCP, and OAuth token redirects are rejected so configured
  credentials cannot be reapplied to an unintended redirect destination.
- Responses are size-bounded but are not semantically sanitized. Tool output can
  still contain malicious instructions or prompt injection.
- Optional rate and concurrency limits apply across every session owned by an
  identity and can be tightened for exact tools.
- Compromise of the Switchboard process exposes the upstream credentials loaded
  by that deployment. Separate deployments and narrowly scoped credentials may
  be appropriate for especially sensitive trust domains.
- Native and compatibility calls have a structured local gateway audit trail,
  but upstream correlation and SIEM export are not yet implemented.

## Workplace readiness gap analysis

| Area | Current state | Workplace requirement |
| --- | --- | --- |
| Client authentication | Static bearer migration path plus OAuth/OIDC JWT validation | Approved issuer configuration, client interoperability, and token-lifetime policy |
| Authorization | Subject/group/scope mapping to profiles, capability decisions, and exact tool overrides | Corporate mapping ownership and policy lifecycle |
| Upstream identity | Shared credential per upstream | Explicit service identity, delegated identity, or signed caller identity |
| Approvals | Client UI and upstream workflows | Server-side enforcement for consequential operations |
| Auditing | All gateway tool calls with identity and gateway correlation IDs | Policy-versioned SIEM export and upstream correlation IDs |
| Network controls | Optional HTTPS destination/CIDR enforcement, DNS-safe dialing, bounds, and redirect rejection | Reviewed production values plus infrastructure firewall enforcement |
| Secrets | Protected environment file | Corporate secret manager and automated rotation |
| Operations | In-memory sessions, optional identity/tool limits, and low-cardinality metrics | Alerting, runbooks, circuit breakers, and an explicit HA model |
| Governance | Manifests and profiles in configuration | Ownership, review, classification, change control, and incident response |

## Required workplace work

### 1. Define the initial use case

Start with two or three read-only capabilities that access non-sensitive or
appropriately classified internal data. For every capability, document:

- intended users and business purpose;
- exposed data classification;
- upstream owner;
- upstream authorization and audit behavior;
- credential scope;
- maximum plausible impact of gateway, credential, or agent compromise; and
- rollback and incident contacts.

Do not include production mutations in the first pilot.

### 2. Integrate corporate identity

Replace static inbound bearer credentials with the corporate identity provider:

- implement OAuth 2.1 protected-resource and authorization-server discovery;
- validate token issuer, signature, expiry, audience, and intended resource;
- map groups, roles, or scopes to Switchboard policy;
- use short-lived credentials with revocation; and
- assign a distinct server-derived identity to each user, workload, or agent
  installation.

Switchboard now implements the resource-server portion of this flow for HTTP
sessions. It discovers one configured issuer, validates JWT signature, issuer,
expiry, and exact audience, requires global and policy-specific scopes, maps
immutable subjects and exact groups to gateway policies, publishes RFC 9728
metadata, and returns OAuth challenges. Ambiguous mappings fail closed. Static
session credentials require an explicit migration switch once OAuth is enabled;
the legacy bearer endpoint is retired separately by removing its environment
variable.

Identity-provider policies can optionally use composed mode for group-based
entitlements. All entitlements share one operator-defined superset profile and
reference explicit tool policies. Matching grants combine deterministically;
deny and approval requirements take precedence over allow, limits only become
stricter, and the effective-policy hash is bound to sessions and audit. The
default exclusive mode continues to reject multiple matching policies. See
[Group entitlements and private MCP gateways](group-entitlements.md).

For Pocket ID 2.14, require the signed protected-header `typ: at+jwt` using
`oauth.jwt_type`. These access tokens do not contain the older
`type=access-token` payload claim. The type check runs after signature
verification so an ID token cannot be relabeled as an API access token.
Pocket ID also emits requested group memberships through UserInfo rather than
its API access token, so configure `oauth.group_source: userinfo`; Switchboard
requires the UserInfo subject to match the validated access-token subject.

JWT validation is local and does not introspect each request. Individual token
revocation therefore relies on short access-token expiry unless the issuer
removes the signing key.

The remaining rollout work is to assign and test the staged Rendercase and
Tintwire groups, finish installed-client migration, restrict direct upstream
routes, and disable both static-token migration paths. Pocket ID is the first
tested provider, but the gateway configuration and validation are not
Pocket-ID-specific.

The MCP authorization specification requires audience-bound tokens and forbids
passing an inbound MCP token through to another service. Switchboard's use of
separate downstream credentials is consistent with the latter requirement.

Reference: <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>

Cloudflare Access can be configured as an additional identity source at an
Access-protected ingress. Switchboard validates the edge assertion's signature,
issuer, audience, expiry, application-token type, stable subject, email, and
groups before applying the same versioned gateway policies. OAuth and Access
credentials on the same request are rejected. This does not turn a downstream
service identity into delegated user identity by itself. For an upstream that
explicitly trusts Switchboard's service-client subject, a reserved per-call
header may carry the already-verified OAuth subject. The upstream must resolve
that subject to an existing principal and retain all ownership and authorization
checks. Switchboard never forwards its inbound audience-bound token downstream.

### 3. Select a downstream identity model

Choose one model explicitly for every upstream:

1. A shared, least-privilege service identity for safe reads.
2. A delegated user token for user-specific authorization.
3. A signed caller identity that the upstream independently authenticates and
   authorizes.
4. A separate Switchboard deployment and credential for a sensitive team or
   trust domain.

Never forward the inbound Switchboard access token as an upstream access token.

### 4. Add capability and tool policy

Introduce an operator-owned policy layer capable of decisions such as:

```text
engineering-read:
  inventory_list: allow
  deployment_status: allow
  deployment_restart: deny

platform-operators:
  deployment_restart: require_approval
  deployment_delete: deny
```

Policy should default to deny for mutating, destructive, unannotated, newly
discovered, or ambiguously classified tools. Tool annotations may inform policy
but must not be its sole source of truth.

Switchboard now supports optional, versioned per-client tool policies with exact
`allow`, `deny`, and `require_approval` decisions. Missing tools deny by default,
and stale explicit entries fail startup. The remaining workplace work is mapping
corporate groups or workloads to those policies, managing their review lifecycle,
and connecting `require_approval` to an authoritative approval workflow.

### 5. Enforce consequential-action approval

High-impact operations need a server-side control that cannot be bypassed by a
client that ignores annotations. Prefer an upstream plan/confirm design:

1. The caller requests a plan or dry run.
2. The authoritative application validates the current revision and returns a
   short-lived, operation-bound plan identifier.
3. An approved actor confirms that exact plan.
4. The upstream executes and records the result.

Human approval, separation of duties, expiry, replay protection, and rollback
requirements should follow the affected system's existing control framework.

### 6. Complete auditing

Record every authorization decision and tool invocation with:

- authenticated identity;
- profile, identity policy, and tool-policy version;
- capability and exact tool;
- allow, deny, or approval-required decision;
- outcome and latency; and
- gateway and upstream correlation identifiers.

Arguments, results, and error strings should be excluded by default or subjected
to explicit field-level redaction. Export events to the corporate SIEM while
retaining the upstream application's audit log as the authoritative business
record.

### 7. Harden networking and secrets

Before production:

- keep redirects rejected for REST, remote MCP, and OAuth token connections;
- restrict egress to reviewed destinations, ports, and protocols;
- defend against DNS rebinding, loopback/link-local access, and cloud metadata
  endpoints;
- require valid TLS; Switchboard rejects `insecure_skip_verify` unconditionally;
- consider mutual TLS between gateway and sensitive upstreams;
- store credentials in the approved secret manager or workload identity system;
- automate rotation without distributing downstream credentials to clients; and
- deploy behind the approved ingress, WAF, and network segmentation.

Switchboard requires an egress policy with HTTPS, exact
destination `host:port` entries, and approved result CIDRs. It rejects a DNS
answer if any address falls outside the policy and dials a validated address
directly, preventing a second resolver lookup from rebinding the connection.
TLS verification cannot be disabled, and the policy prohibits environment proxy routing.
Production still needs organization-reviewed destinations and CIDRs plus
independent network-layer enforcement.

### 8. Add production operations

At minimum, provide:

- per-identity and per-tool rate limits;
- concurrency limits, upstream timeouts, and circuit breakers;
- metrics and alerts for authentication failures, policy denials, latency,
  upstream errors, capacity pressure, and unusual tool use;
- graceful credential and policy reload, or a documented restart process;
- a deliberate high-availability design, using sticky routing or a shared
  session model if sessions must survive instance failure;
- signed artifacts, SBOMs, vulnerability scans, release provenance, and a
  controlled deployment pipeline;
- a threat model, security-reporting procedure, incident runbook, and disaster
  recovery procedure; and
- regular access, manifest, upstream, and credential reviews.

Switchboard now supports token-bucket rate limits and non-blocking concurrency
limits per authenticated identity, shared across all of its sessions, with
optional stricter limits on exact tools. Rejections are audited and never reach
the upstream. These process-local controls still require alerting and a
distributed design before a multi-instance deployment can enforce global limits.
The `/metrics` endpoint reports authentication, UserInfo, and authorization
failures; capacity pressure; active sessions; tool decisions, outcomes, counts,
and duration; and a numeric effective-policy hash for each composed component
set. It does not use identity or payload labels. Install
[`monitoring/switchboard.rules.yml`](../monitoring/switchboard.rules.yml) to
alert on repeated authentication failures, UserInfo failures, and changes to an
existing component set's effective hash. Protect and scrape the endpoint, and
set retention and notification routing in the organization's monitoring system.

### 9. Address model and MCP-specific threats

- Treat upstream tool descriptions, schemas, annotations, and results as
  untrusted input.
- Require operator review for new tools and material schema or annotation
  changes.
- Use explicit tool allowlists for sensitive upstreams.
- Ensure retrieved content cannot silently expand authorization.
- Test prompt injection, tool poisoning, confused-deputy behavior, credential
  theft, replay, cross-session access, and cross-identity access.
- Preserve the client's own write-approval controls as defense in depth, while
  keeping authoritative enforcement at Switchboard or the upstream application.

## Organizational prerequisites

Before bringing personally developed code into a company:

- obtain approval to introduce it;
- establish copyright and ownership of existing and future work;
- confirm whether development continues publicly, in an internal fork, or both;
- review the MIT license and all third-party dependency obligations;
- identify a company service owner and operational support model;
- complete architecture, privacy, legal, and security reviews appropriate to the
  affected data; and
- agree on vulnerability handling and disclosure responsibilities.

## Recommended pilot

The first milestone should contain:

- one corporate identity provider integration;
- one read-only profile;
- two reviewed upstream services;
- individual caller identities;
- complete gateway and upstream auditing;
- least-privilege downstream credentials;
- outbound network restrictions; and
- no mutating or destructive tools.

```text
Corporate identity provider
          | short-lived OAuth access token
          v
Corporate ingress or WAF
          v
Switchboard ------ policy and audit ------ SIEM
     |
     +-- read-only service identity ------ Inventory API
     +-- delegated identity -------------- User-scoped application
     +-- plan/confirm workflow ----------- Infrastructure service (later phase)
```

Suggested rollout stages:

1. Complete the security architecture and data-classification review.
2. Test with synthetic upstreams and adversarial fixtures.
3. Run a read-only pilot with a small technical user group.
4. Review audit records, usability, failure modes, and operational load.
5. Add narrowly scoped, idempotent mutations only after policy and approval
   enforcement is verified.
6. Introduce high-impact operations only after the responsible upstream owners
   approve their authoritative plan/confirm and audit workflows.

## Public release consideration

Public release is not required for an internal pilot. If Switchboard is later
published, position it as a small, auditable, self-hosted capability gateway
rather than an enterprise authorization platform. Before publication:

- retain redirect-rejection regression coverage for every credentialed HTTP client;
- add a public threat model and `SECURITY.md`;
- document the authentication and authorization limitations prominently;
- provide a generic production deployment example; and
- publish only a freshly audited source snapshot, never the original private
  Git history.

See [privacy-release.md](privacy-release.md) for the repository's existing
publication gate.

## Related repository documentation

- [README](../README.md)
- [Dynamic MCP discovery](dynamic-mcp.md)
- [Pocket ID OAuth setup](pocket-id.md)
- [Group entitlements and private MCP gateways](group-entitlements.md)
- [Rollout notes](rollout.md)
- [Privacy release gate](privacy-release.md)
- [Review archives](releases.md)
