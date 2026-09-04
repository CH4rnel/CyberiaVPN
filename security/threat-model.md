# Threat model

## Scope

This baseline covers clients, the Control API, configuration distribution,
transport adapters, edge gateways and managed nodes. Billing providers,
blockchain integrations and a future third-party node marketplace are trust
boundaries, not implicitly trusted internals.

Protected assets include user and node identity keys, signing keys, account and
billing records, policy/configuration integrity, service availability and the
confidentiality and integrity of tunnelled traffic.

## Trust boundaries

```text
User device | public network | edge/node | service network | control services
                                  |
                          operator boundary
Control services | payment, identity and Cyberia ecosystem providers
Build system | artifact registry | updater | running component
```

Every crossing is authenticated and authorized. Network location alone grants
no trust. Service, node and device credentials have separate issuers, purposes
and rotation/revocation paths.

## Baseline threats and controls

| Threat | STRIDE | Initial controls | Required evidence |
| --- | --- | --- | --- |
| API or node impersonation | Spoofing | short-lived identity, mutual authentication, revocation | negative auth and rotation tests |
| Configuration or update modification | Tampering | signatures, checksums, version binding, rollback protection | corrupted/replayed artifact tests |
| Privileged action denial | Repudiation | immutable audit events with actor and request ID | access review and audit tests |
| Traffic or credential disclosure | Information disclosure | encryption, secret isolation, redaction, data minimization | log/privacy review |
| Volumetric or application DDoS | Denial of service | upstream scrubbing, edge limits, bounded work, graceful degradation | load test and provider runbook |
| Rogue admin or over-privileged service | Elevation of privilege | MFA, short-lived access, RBAC, separation of duties | privilege matrix and audit drill |
| Compromised or malicious node | Multiple | least privilege, constrained config access, drain/revoke/rebuild | quarantine exercise |
| Replay or downgrade | Spoofing/tampering | freshness, monotonic versions, supported-suite policy | protocol tests |
| Supply-chain compromise | Tampering | pinned dependencies, review, SBOM, signed provenance | CI evidence and release verification |
| Sybil nodes or telemetry poisoning | Multiple | verified onboarding, independent probes, reputation decay | simulation before marketplace launch |

## Fail-secure invariants

- A failed client transport teardown keeps the kill-switch policy active.
- Invalid, expired or unverifiable configuration is rejected.
- A node cannot self-assign capabilities, region, trust or entitlements.
- Automatic security actions are bounded and reversible where false positives
  can deny legitimate service.
- Retry loops have deadlines, backoff, jitter and a terminal state.
- Control-plane loss cannot silently change an established session's policy.

## Privacy abuse cases

Operational metrics must not contain destination domains, IP traffic history,
payloads, raw DNS queries or stable cross-context identifiers. Security events
need documented purpose, access policy and retention. High-cardinality labels
are reviewed because they can accidentally become user tracking data.

## Deferred analyses

Before M1, produce attack trees for device enrollment, configuration delivery,
WireGuard key lifecycle and client updates. Before accepting third-party nodes,
model operator collusion, traffic correlation, fake capacity, reward fraud and
quarantine evasion.

This model is reviewed whenever a trust boundary, credential type, transport or
external provider is introduced.
