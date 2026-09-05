# Current component contracts

These contracts describe domain components implemented in the repository. They
are not evidence of an operational VPN or authenticated public API.

## Configuration and node metadata

Endpoints require a valid IP address and nonzero port. Unspecified and multicast
addresses are rejected, including IPv4-mapped forms. IPv6 zone identifiers are
rejected because interface names are local to a host and cannot be distributed
as portable node metadata. Private and loopback addresses remain available for
local test environments; deployment policy must decide which networks to allow.

DNS resolvers must be valid, unscoped, non-unspecified, non-multicast addresses.
Duplicates are rejected after comparing IPv4-mapped addresses with their IPv4
equivalents. Distinct IPv4 and IPv6 resolvers can coexist. Validation preserves
the original representation and ordering of accepted configuration fields.
Node transport capabilities must be supported and unique.

Configuration versions are positive and strictly increase per device in the
memory store. Reads and writes copy mutable slices. Both memory stores support
their zero values and concurrent method calls; do not copy them after first use.
They are process-local and lose all state on restart. The configuration store is
not a cryptographic verification boundary: callers must use `Seal`/`Open` with
trusted keys and enforce device authorization and replay protection separately.

## Transport and telemetry

WireGuard interface addresses must have valid family-specific prefixes. The
same IP cannot appear twice, even with different prefix lengths. Distinct
addresses in the same subnet and dual-stack addresses are allowed. Validation
does not create an interface or install routes.

Operational values must be finite and non-negative. `packet_loss_ratio` is in
`[0, 1]`, `connection_success` is a single binary observation (`0` or `1`), and
`reconnect_count` is an integer count. Latencies are milliseconds and may be
fractional. Attribute names are allowlisted, but producers remain responsible
for preventing sensitive or high-cardinality content inside attribute values.

## HTTP service lifecycle

The development server exposes `GET /healthz` and `GET /api/v1/version`; these
do not establish readiness of a VPN node. HTTP shutdown waits for active
requests for up to 10 seconds, then closes remaining connections. Lifecycle
tests use a loopback listener to cover graceful draining, drain expiry, an
already-cancelled context and listener failure. All Go checks run with the race
detector through `make check`.
