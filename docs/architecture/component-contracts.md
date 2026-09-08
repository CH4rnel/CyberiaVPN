# Current component contracts

These contracts describe domain components implemented in the repository. They
include separately constructible authenticated HTTP handlers. They are not
evidence of an operational VPN or a deployed authenticated public API.

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

## Authenticated HTTP handlers

`NewEnrollmentHandler` and `NewConfigurationHandler` require an injected
`AccountAuthenticator`. Account IDs come only from that provider; request bodies,
query parameters and arbitrary account headers do not establish ownership.
Neither handler is mounted in the development server yet. A production account
provider, trusted configuration keys and durable stores remain integration work.

Enrollment supports `POST /api/v1/enrollment/challenges`, `POST /api/v1/devices`
and `GET /api/v1/devices/{deviceID}`. Successful proof verification, challenge
consumption and registration happen atomically in the process-local store.
Device IDs are globally unique and cannot be overwritten or transferred.
Restarting the process loses devices and outstanding challenges.

Configuration delivery supports `GET /api/v1/devices/{deviceID}/configuration`.
It authenticates the account and checks device ownership before reading the
configuration store. Missing and foreign devices return the same `404`; invalid
credentials return `401` with a Bearer challenge. A missing configuration returns
`404`; storage errors return `500` without internal error details. Untrusted,
tampered, expired or wrong-device envelopes return `503` without connection
parameters. Successful responses contain the complete `SignedConfig` envelope
and use `Cache-Control: no-store`, as do errors.

The JSON envelope uses `Config`, `KeyID` and `Signature`. `Config` contains
`Version`, `DeviceID`, `NodeID`, `Transport`, `Endpoint`, `DNS`, `IssuedAt` and
`ExpiresAt`. Signatures are base64; endpoints and DNS addresses are strings;
timestamps use RFC 3339 with subsecond precision. Versions are unsigned 64-bit
integers and must be decoded without floating-point precision loss. The signature
covers the canonical binary configuration, not the JSON representation.

`OpenForDevice` verifies the signature and validity, matches a trusted local
device ID and requires a version strictly greater than the last accepted version.
Zero allows initial acceptance; equal versions are rejected as replays. A failed
check returns no configuration. Callers must serialize acceptance and durably
record the returned version before applying an update. That version must come
from trusted local state, never the downloaded envelope. This function does not
provide storage; resetting the version on restart loses rollback protection.
The server checks against zero because repeated authenticated downloads of the
current configuration are allowed; the client enforces its own version history.

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
