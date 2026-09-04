# Test strategy

The test suite mirrors risk and component boundaries.

| Level | Purpose | Initial scope |
| --- | --- | --- |
| Unit and property | Prove deterministic domain rules and invariants | scoring, policy, parsing, identity and configuration |
| Integration | Prove contracts with real adapters | PostgreSQL, Redis, API, node registry and transports |
| Contract | Prevent incompatible evolution | versioned HTTP/gRPC and configuration schemas |
| End-to-end | Prove user-visible journeys | install, enroll, connect, fail over, update and uninstall |
| Fuzz | Exercise hostile or malformed input | network and configuration parsers |
| Load and soak | Establish capacity and long-run stability | Control API, gateways and nodes |
| Chaos | Validate bounded recovery | node, region and control-plane loss |

## Test construction

Tests use arrange-act-assert, control time at state-machine boundaries and avoid
real sleeps. A test should fail for one reason, use deterministic data and avoid
asserting private implementation details. Concurrency tests run under the Go
race detector; Rust parsers gain property and fuzz tests before production use.

External systems are represented by narrow fakes in unit tests and replaced by
their real implementation in integration tests. Cryptographic tests use public
test keys that can never be mistaken for deployable secrets.

## Quality gates by milestone

- **M0:** formatting, linting, unit tests and race detection.
- **M1:** API contracts, component integration and the first connect/fail-safe
  end-to-end path.
- **M2–M3:** transport interoperability, property tests, fuzzing and chaos
  coverage for selection/failover.
- **M4–M5:** security review, load/soak tests, SBOM, signed artifacts, restore,
  rollback, incident and disaster-recovery drills.
