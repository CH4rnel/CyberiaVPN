# Delivery roadmap

Cyberia VPN is delivered in small, testable increments. A milestone is only
complete when its tests, security checks and operational documentation pass.

## M0 — Architecture baseline

- [x] Record the control-plane/data-plane boundary.
- [x] Record the initial implementation languages and primary transport.
- [x] Establish the threat model and security reporting policy.
- [x] Create the Rust network-core workspace.
- [x] Define the transport lifecycle contract.
- [x] Implement deterministic node scoring and stable route selection.
- [x] Create a minimal, versioned Control API.
- [x] Create the first node-registry contract.
- [x] Run formatting, linting and tests in CI.

Exit criteria: architectural decisions are reviewable, public interfaces are
covered by tests, and every supported toolchain is checked on each change.

## M1 — WireGuard core MVP

Deliver device identity, authenticated configuration delivery, a managed
WireGuard node, client connection lifecycle, kill switch and privacy-preserving
operational telemetry.

Current component progress (not M1 completion):

- [x] Device proof-of-possession verification.
- [x] Signed, short-lived public configuration and versioned in-memory storage.
- [x] Node metadata validation and lifecycle transitions.
- [x] Public WireGuard profile validation and kill-switch state model.
- [x] Operational metric validation and bounded reconnect policy.
- [ ] Account authentication and authorization at HTTP boundaries.
- [ ] Atomic consumption of expiring enrollment challenges and device persistence.
- [ ] Authenticated configuration delivery and client rollback protection.
- [ ] Managed WireGuard node and real transport adapter.
- [ ] OS firewall implementation of the kill-switch contract.
- [ ] End-to-end connect, disconnect and fail-safe integration tests.

Exit criterion: a client can establish and safely tear down an authenticated
WireGuard tunnel in a test environment.

## M2 — Multi-protocol transport engine

Add validated VLESS profiles, Hysteria2, TUIC, Trojan, Shadowsocks and selected
native/legacy adapters behind the common lifecycle contract.

## M3 — Smart routing

Add active health probes, packet-loss measurement, circuit breakers, bounded
retry with jitter, automatic failover and protocol capability selection.

## M4 — Cyberia Shield

Add rate limiting, DDoS-provider integration, host filtering, IDS signals,
node risk scoring and a safeguarded quarantine workflow.

## M5 — Production platform

Add multi-region deployment automation, GitOps, end-to-end observability,
signed updates with rollback, load/soak tests and disaster-recovery exercises.

## Later milestones

- **M6:** subscriptions and stable Cyberia ecosystem integrations.
- **M7:** verified operator onboarding, reputation and node marketplace.

Blockchain services remain business/control-plane integrations. Their failure
must never interrupt already established data-plane sessions.
