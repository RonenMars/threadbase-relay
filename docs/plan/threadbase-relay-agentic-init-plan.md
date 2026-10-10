# Threadbase Relay — Implementation Mission

You are implementing **Threadbase Relay**, an optional hosted transport layer for the Threadbase ecosystem.

Your job is not merely to add a proxy. You must design and implement a production-oriented relay architecture that gives Threadbase zero-configuration remote connectivity while preserving its existing local-first and fully self-hosted modes.

Work autonomously, but do not make irreversible architectural decisions silently. Investigate first, document decisions, implement incrementally, validate each phase, and stop at explicit human-review gates where requested.

---

# 1. Primary Product Goal

Today Threadbase mobile connects directly to a user-owned `tb-streamer`.

Remote connectivity may require the user to configure infrastructure such as:

- Cloudflare Tunnel
- Tailscale
- reverse proxies
- router/NAT configuration
- another manually exposed public endpoint

Introduce an optional hosted service:

```text
threadbase-relay
```

that allows:

```text
Threadbase Mobile
        │
        │ outbound connection
        ▼
Threadbase Relay
        │
        │ persistent outbound streamer connection
        ▼
tb-streamer
        │
        ▼
Claude Code / Codex
```

The desired user experience is approximately:

```text
install tb-streamer
pair mobile
remote access works
```

with no requirement to configure Cloudflare, Tailscale, NAT, DNS, or TLS infrastructure.

---

# 2. Preserve Existing Threadbase Modes

The relay MUST be optional.

Threadbase must continue supporting the existing topology:

```text
Mobile ─────► Streamer
```

using:

- LAN
- localhost where applicable
- Tailscale
- Cloudflare Tunnel
- manually configured HTTPS endpoints
- any other existing supported direct transport

The relay must be an additional transport:

```text
Mobile ─────► Relay ─────► Streamer
```

Do not turn the hosted relay into a dependency of `tb-streamer`.

A relay outage must never make the local streamer unhealthy or prevent direct access.

Conceptually:

```text
tb-streamer
├── local REST/WS server        independent
├── provider/session engine     independent
├── scanner/cache               independent
└── relay connector             optional
```

---

# 3. Critical Architectural Principle

Treat the relay as:

> A transport service, not the Threadbase backend.

Do NOT redesign Threadbase around a SaaS/cloud-owned state model.

The relay should not become the canonical owner of:

- sessions
- projects
- conversation history
- prompts
- agent output
- repositories
- filesystem state
- Claude/Codex state

The streamer remains authoritative.

Prefer:

```text
mobile
   │
   │ encrypted application traffic
   ▼
relay
   │
   │ opaque transport
   ▼
streamer
```

over:

```text
mobile
   │
   ▼
cloud backend
├── users
├── projects
├── sessions
├── messages
└── streamer state
```

---

# 4. Security Invariants

Treat the following as non-negotiable design constraints.

## 4.1 Relay must remain cryptographically blind

Threadbase already has an E2EE transport design involving streamer identity, Noise/X25519 and ChaCha20-Poly1305.

Investigate the actual current implementation before changing anything.

The relay MUST NOT possess sufficient key material to decrypt application payloads.

The relay may know operational metadata such as:

- streamer/relay identity
- connection state
- IP addresses
- timestamps
- bytes transferred
- protocol version
- frame size
- transport health

It must not need access to:

- prompts
- terminal output
- conversation history
- source code
- Claude/Codex responses
- API credentials
- device credentials
- uploaded file contents where avoidable

Do not weaken existing Threadbase E2EE merely to make relay implementation easier.

---

## 4.2 Streamer authorization remains authoritative

The relay is a router.

It must not become the final authorization boundary for mobile operations.

Existing device credentials, scopes, pairing state, E2EE identity verification, and authorization should continue terminating at the streamer wherever possible.

Desired defense in depth:

```text
Mobile
   │
   ▼
Relay
   │
   │ routes only
   ▼
Streamer
   │
   └── authenticates and authorizes mobile/device request
```

Even if the relay routes traffic incorrectly, another user's streamer must reject that traffic.

---

## 4.3 Tenant isolation

Prevent traffic from different users, streamers, devices, connections, or logical streams from ever mixing.

Do not route based solely on:

```text
sessionId
```

or any other application-level ID that may collide.

Design an explicit routing namespace such as:

```text
authenticatedStreamerIdentity
    + relayConnectionId
    + logicalStreamId
```

or a stronger equivalent.

A public relay locator such as:

```text
relayId
```

must be treated as a locator, not proof of authorization.

Write tests specifically designed to prove that:

- user A cannot access streamer B
- streamer A cannot impersonate streamer B
- device A cannot accidentally receive device B's traffic
- identical session IDs across streamers cannot collide
- reused logical stream IDs across different relay connections cannot collide
- stale connections cannot receive traffic after reconnection/re-registration

Include adversarial tests rather than only happy-path tests.

---

## 4.4 Streamer authentication to relay

A process must not be able to simply claim:

```text
I am streamer XYZ
```

Investigate whether the existing Threadbase streamer identity key can authenticate the streamer to the relay.

Prefer challenge-response using the existing streamer identity over inventing another permanent shared secret, provided this is compatible with the current crypto architecture.

Example conceptually:

```text
relay -> random challenge
streamer -> signature/proof using streamer identity
relay -> verify against registered identity
```

Do not duplicate identity systems without a strong reason.

Document whichever model you choose.

---

# 5. Investigate Before Implementing

Before writing production code:

## 5.1 Inspect the current repositories

At minimum inspect:

- `RonenMars/threadbase`
- `RonenMars/threadbase-streamer`
- `RonenMars/threadbase-mobile`

Also inspect relevant current documentation/specs relating to:

- E2EE
- pairing
- streamer identity
- device credentials
- WebSocket transport
- authenticated REST requests
- remote-access tunnels
- push notifications
- multi-server behavior
- uploads
- protocol/version negotiation

Find the exact current implementation.

Do not rely on assumptions from old documentation if code disagrees.

---

# 6. Produce a Design Document Before Coding

After the investigation, write a design document containing:

## Current architecture

Document:

```text
mobile → streamer
```

including:

- REST flow
- WebSocket flow
- pairing
- E2EE
- credentials
- server identity
- push
- upload behavior

## Proposed architecture

Include a diagram for:

```text
mobile → relay → streamer
```

and coexistence with:

```text
mobile → streamer
```

## Trust boundaries

Explicitly describe:

- what mobile trusts
- what streamer trusts
- what relay trusts
- what relay can observe
- what relay cannot decrypt
- what happens if the relay is malicious
- what happens if routing is wrong

## Threat model

At minimum cover:

- cross-tenant routing
- relay ID enumeration
- forged streamer registration
- stolen relay credentials
- replay
- stale connection takeover
- MITM by relay
- corrupted/malformed frames
- resource exhaustion
- giant frames
- reconnect storms
- denial of service
- unauthorized logical-stream creation

## Protocol

Specify all relay frames/messages.

Keep the protocol deliberately small.

A conceptual example is:

```ts
type RelayFrame =
  | OpenFrame
  | DataFrame
  | EndFrame
  | ResetFrame
  | PingFrame
  | PongFrame;
```

Do not treat this exact shape as mandatory.

Define:

- version
- connection identity
- stream ID
- frame type
- payload length
- sequencing if needed
- close/reset behavior
- errors
- limits

## Failure semantics

Define clear machine-readable states for:

- streamer offline
- streamer reconnecting
- relay unavailable
- relay authentication failure
- unsupported relay protocol
- mobile authorization failure
- stream reset
- timeout
- relay overload
- rate limit

Avoid collapsing everything into generic `502` / `network error`.

---

# 7. Decide Relay Transport Architecture

Evaluate at least these approaches:

### A. Raw multiplexed transport

One persistent streamer → relay connection carrying logical streams.

Example:

```text
streamer relay connection
├── stream A: REST request
├── stream B: REST request
├── stream C: WS session
└── stream D: upload
```

### B. Existing protocol proxying

Expose a relay URL that appears similar to a streamer URL:

```text
https://relay.threadbase.sh/r/<relay-id>/...
```

while forwarding requests over the persistent streamer tunnel.

### C. Hybrid

Separate control plane from byte transport.

Compare the approaches for:

- implementation complexity
- HTTP semantics
- WebSocket support
- uploads
- streaming responses
- backpressure
- reconnect behavior
- security
- compatibility with current mobile code
- future extensibility

Choose the smallest robust design.

Document why.

---

# 8. Direct + Relay Coexistence

Design for a server record to eventually support both:

```text
directUrl
relayDescriptor
```

where reasonable.

The architecture should allow future behavior such as:

```text
direct connection available?
    yes → direct
    no  → relay
```

Do NOT implement automatic path switching unless it is safe and fits the current phase.

But do not design the storage/protocol in a way that makes this unnecessarily difficult later.

Important:

- same streamer identity
- same paired device identity
- same authorization
- same E2EE security relationship
- no re-pairing merely because transport changes

---

# 9. Relay Registration / Pairing UX

Design how relay information becomes associated with a streamer.

Investigate the current QR payload.

A future relay-capable QR may conceptually include:

```text
relay base URL
relay locator
streamer public identity
pairing material
protocol version
```

The streamer public identity must remain the streamer's identity.

Do not substitute a relay identity for the streamer's E2EE identity.

The user should still be cryptographically pairing with their streamer, not trusting Threadbase Relay to impersonate it.

---

# 10. Multiple Streamers and Multiple Clients

Do not assume:

```text
1 user = 1 streamer
```

Threadbase already supports multiple servers.

Support:

```text
one user / installation
├── work MacBook
├── personal MacBook
├── Linux box
└── Windows machine
```

Also support multiple clients connecting to the same streamer:

```text
streamer
├── iPhone
├── Android
├── desktop client
└── future web client
```

Each connection must remain isolated.

---

# 11. Backpressure and Memory Safety

Design bounded buffering from the beginning.

Terminal output and other streams may be fast while a mobile device may be slow.

Explicitly define:

- maximum relay frame size
- maximum concurrent logical streams
- max buffered bytes per logical stream
- max buffered bytes per streamer
- max buffered bytes per relay connection
- backpressure mechanism
- behavior when limits are reached
- slow-consumer behavior
- timeout behavior

Unbounded queues are not acceptable.

Test backpressure with synthetic high-throughput terminal traffic.

---

# 12. Resource Abuse Protection

Because `threadbase-relay` will be Internet-facing, design protection for:

- excessive connection attempts
- thousands of logical streams
- giant payloads
- bandwidth abuse
- reconnect storms
- idle connections
- malformed frames
- relay-ID enumeration
- deliberate CPU/memory exhaustion

At minimum plan:

```text
connection rate limits
connections per streamer
streams per connection
frame-size limits
buffer limits
idle timeouts
authentication throttling
bandwidth/accounting hooks
```

Do not overbuild billing or subscription systems.

Just create the boundaries required to operate a public relay safely.

---

# 13. Version Negotiation

Do not couple relay compatibility solely to application release numbers.

The initial protocol must explicitly negotiate something like:

```text
relayProtocolVersion
capabilities
```

Potential capabilities may include:

```text
http
websocket
binary
uploads
```

Only add capability flags that are useful now.

Do not create speculative complexity.

---

# 14. Observability Without Content Leakage

We need enough telemetry to debug:

```text
"relay doesn't work"
```

without logging sensitive content.

Allowed examples:

```text
streamer abc connected
connection xyz authenticated
logical stream 42 opened
transport = websocket
17 KB upstream
31 KB downstream
closed = timeout
```

Do not log:

```text
prompt text
terminal output
conversation messages
source files
device credentials
authorization headers
encrypted key material
plaintext request bodies
```

Review every relay log statement with this requirement in mind.

Provide metrics for:

- connected streamers
- connected clients
- active logical streams
- bytes relayed
- reconnect rate
- rejected authentication attempts
- rate-limit events
- stream resets
- relay latency if meaningful

Use pseudonymous identifiers where possible.

---

# 15. Suggested Repository Shape

Investigate whether a new repository is best.

The expected architecture is likely:

```text
threadbase-relay/
```

containing:

```text
src/
  server/
  auth/
  protocol/
  connections/
  streams/
  limits/
  metrics/
  config/
tests/
```

Do not create this structure mechanically if the implementation suggests something cleaner.

The service should remain small and transport-focused.

---

# 16. Streamer Integration

Add an optional relay connector to `threadbase-streamer`.

The streamer should:

1. retain its current local HTTP/WS server
2. establish an outbound authenticated connection to relay when enabled
3. register its relay identity
4. receive logical-stream open requests
5. proxy those streams into the existing local API/WS handling
6. reconnect with bounded exponential backoff
7. expose relay connection state through diagnostics
8. remain healthy if relay is unavailable

Relay connection failure must not terminate the streamer.

Possible status:

```text
disabled
connecting
connected
reconnecting
authentication_failed
unsupported_protocol
```

---

# 17. Mobile Integration

Minimize divergence between direct and relay transport.

Investigate whether the current centralized authenticated request and WS layers can provide a transport abstraction such as:

```text
DirectTransport
RelayTransport
```

or another structure.

Do not duplicate the Threadbase API client.

The same higher-level operations should work through either path.

Examples:

- list sessions
- load conversations
- send prompt
- subscribe to terminal
- start/resume session
- approve permission
- uploads
- diagnostics

Where something cannot safely support relay in v1, fail explicitly and document it rather than silently degrading.

---

# 18. Phase the Work

Do NOT implement everything in one huge change.

Create reviewable, testable phases.

A suggested sequence:

## Phase 0 — Architecture and protocol

Deliver:

- repository investigation
- design document
- threat model
- relay protocol spec
- isolation model
- ADRs for major decisions
- implementation breakdown

No production behavior change.

HUMAN REVIEW GATE.

---

## Phase 1 — Relay skeleton

Implement:

- new relay service
- config
- health endpoint
- protocol versioning
- authenticated streamer connection
- connection registry
- hard tenant isolation
- unit tests

No mobile traffic yet.

Validate streamer A and B cannot impersonate/collide.

---

## Phase 2 — Streamer tunnel

Implement:

- optional relay connector
- persistent outbound connection
- authentication
- reconnect/backoff
- diagnostics
- connection lifecycle

Relay outage must not affect direct mode.

Validate:

```text
kill relay
→ streamer continues working directly
→ connector reconnects when relay returns
```

---

## Phase 3 — One relayed HTTP operation

Choose a harmless read-only API request.

Route:

```text
mobile/test client
→ relay
→ streamer
→ relay
→ client
```

Do not broaden scope yet.

Prove E2EE remains intact through the relay.

Capture traffic at the relay and verify it does not expose Threadbase application plaintext.

---

## Phase 4 — Generic HTTP relay

Add:

- method
- path
- headers as required
- streaming body
- streaming response
- cancellation
- timeout
- bounded buffering

Reuse existing streamer authorization.

---

## Phase 5 — WebSocket transport

Support Threadbase's existing live session socket.

Validate:

- terminal streaming
- prompts
- permission flows
- reconnect
- stream reset
- mobile background/foreground

Exercise high-volume terminal traffic.

---

## Phase 6 — Mobile UX / pairing

Add relay-aware pairing and server configuration.

Maintain:

- direct mode
- relay mode
- existing users
- old server records where possible

Avoid requiring re-pair merely because transport changes.

---

## Phase 7 — Uploads/binary traffic

Validate and implement binary/file flows.

Ensure:

- frame limits
- streaming
- cancellation
- backpressure
- no entire-file buffering when unnecessary

---

## Phase 8 — Production hardening

Implement:

- rate limits
- stream limits
- connection limits
- idle timeout
- metrics
- structured privacy-safe logs
- graceful deploy/restart
- health/readiness checks
- load tests
- abuse tests

---

## Phase 9 — Docs/privacy/release

Update all claims that currently state there is no hosted Threadbase service.

Search the entire ecosystem for claims such as:

```text
no hosted relay
nothing routes through Threadbase servers
traffic only goes to your own streamer
```

Update consistently across:

- app README
- streamer README/docs
- umbrella repo
- website
- privacy policy
- onboarding
- security docs
- architecture docs

Preferred conceptual wording:

> Threadbase Relay is an optional transport service for remote connectivity. Session traffic remains end-to-end encrypted between your device and your streamer, and the relay does not possess the keys required to decrypt session content.

Do not use this exact wording without validating it against the final implementation.

---

# 19. Test Matrix

Build automated integration tests covering at least:

## Isolation

```text
user A → streamer A        PASS
user A → streamer B        REJECT
streamer A impersonates B  REJECT
same session ID A/B        NO COLLISION
same stream ID A/B         NO COLLISION
stale connection routing   REJECT
```

## Reliability

```text
relay restart
streamer restart
mobile reconnect
streamer reconnect
connection replacement
network interruption
duplicate frames
out-of-order frame where applicable
half-closed stream
slow consumer
```

## Security

```text
invalid streamer proof
expired registration
random relay ID
enumerated relay IDs
malformed frame
oversized frame
excessive streams
replayed authentication
forged logical stream
```

## Direct-mode regression

Every major phase must run regression tests proving:

```text
Mobile → Streamer
```

still works with relay:

```text
disabled
misconfigured
offline
```

The relay feature is not complete if direct mode regresses.

---

# 20. Real-Device QA

Before calling relay beta-ready, manually validate:

```text
Wi-Fi → cellular
cellular → Wi-Fi
foreground → background → foreground
Mac sleep → wake
streamer restart
relay restart/deploy
large terminal output
long-running Claude session
Codex session
file upload
two phones
two streamers
same phone switching streamers
relay unavailable while LAN works
```

Record findings.

---

# 21. Deployment

Prefer a boring deployment model.

Initially assume one relay region/process unless real requirements prove otherwise.

Do not prematurely introduce:

- Kafka
- Kubernetes
- distributed consensus
- multi-region replication
- complex service mesh infrastructure

However, do not make core protocol identity depend on process-local IDs in a way that prevents future horizontal scaling.

Document what would need to change to support multiple relay instances later.

---

# 22. Privacy Impact

A hosted relay changes Threadbase's data-flow model even if payloads remain opaque.

Document:

- metadata visible to relay
- source/destination IP handling
- retention
- logs
- metrics
- crash reporting
- infrastructure providers/subprocessors
- whether IP addresses are stored
- deletion policy
- abuse/security logs

Default to minimal collection and minimal retention.

---

# 23. Explicit Non-Goals for v1

Unless the investigation proves one is strictly required, do NOT implement:

- Threadbase user accounts
- cloud conversation storage
- cloud session history
- cloud search
- cloud execution of Claude/Codex
- organizations
- teams
- collaboration
- cloud project database
- S3 conversation persistence
- billing/subscriptions
- multi-region active-active relay
- general-purpose VPN functionality
- arbitrary TCP forwarding

Do not allow scope creep to turn Relay v1 into Threadbase Cloud.

---

# 24. Definition of Done

Relay v1 is done when:

1. A new user can install `tb-streamer`, enable/pair relay access, and remotely use Threadbase Mobile without configuring Cloudflare/Tailscale/NAT.
2. Direct/self-hosted Threadbase remains fully functional.
3. Relay cannot decrypt Threadbase application payloads.
4. Streamer remains the authorization authority.
5. Cross-user / cross-streamer traffic mixing is prevented by construction and tested adversarially.
6. Multiple streamers and multiple clients work.
7. Relay loss does not make the streamer unusable.
8. REST works through relay.
9. WebSocket/live terminal traffic works through relay.
10. Backpressure and resource limits are bounded.
11. Reconnection behavior is deterministic.
12. Relevant privacy/documentation claims are updated.
13. Automated tests cover isolation, security, reconnect and direct-mode regression.
14. Real-device QA passes.

---

# 25. Working Style

Throughout this task:

- inspect before assuming
- prefer existing Threadbase primitives
- avoid parallel identity/auth systems
- avoid duplicated API implementations
- keep the relay dumb
- keep protocol surface small
- write tests for every security boundary
- test failure paths, not only success paths
- prefer incremental PR-sized changes
- preserve backwards compatibility
- record important architectural decisions

For every significant obstacle or surprising finding:

1. record what you expected
2. record what you found
3. explain the impact
4. list reasonable options
5. choose one if the choice is reversible and clearly superior
6. stop for human input if it materially changes security, privacy, product semantics, or architecture

---

# 26. First Execution Step

Do **not** start implementing the relay immediately.

First:

1. inspect the current Threadbase repositories
2. map the current transport/E2EE/pairing architecture
3. identify the exact reusable primitives
4. identify required changes in each repository
5. produce the proposed relay protocol and trust model
6. produce a PR-sized implementation sequence
7. identify unresolved decisions
8. estimate effort for every phase
9. present the design and plan for review

Only after the architecture review should implementation begin.

The most important question you must continuously validate is:

> Can the hosted relay provide zero-configuration remote connectivity while remaining a blind optional transport layer and preserving Threadbase's self-hosted/local-first architecture?

Optimize the implementation around making the answer demonstrably **yes**.
