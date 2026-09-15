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

The JSON envelope uses `config`, `key_id` and `signature`. `config` contains
`version`, `device_id`, `node_id`, `transport`, `endpoint`, `dns`, `wireguard`,
`issued_at` and `expires_at`. `wireguard` contains `peer_public_key`,
`tunnel_addresses`, `allowed_ips`, `mtu` and `persistent_keepalive_seconds`. Signatures and
peer public keys are base64; endpoints, DNS addresses and tunnel prefixes are strings;
timestamps use RFC 3339 with subsecond precision. Versions are unsigned 64-bit
integers and must be decoded without floating-point precision loss. The signature
covers the canonical binary configuration, including every WireGuard peer,
tunnel-address, allowed-IP, MTU and keepalive field, not the JSON representation.

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

## WireGuard adapter and fail-secure lifecycle

`WireGuardAdapter` validates the public profile, a short local interface name,
the requested `TransportKind` and endpoint before calling a platform backend.
The adapter contains no device private key. A backend obtains that key from a
platform-specific protected store and must remove any partially created
interface if setup fails. A successful adapter session ID is the validated
interface name. The adapter cannot report itself disconnected when backend
teardown fails; callers must treat the tunnel as possibly live.

`ConnectionController` coordinates an adapter with the kill-switch state
machine and requires an explicit firewall backend. It applies
the initial policy during construction and refuses to create a controller when
that policy cannot be enforced. It applies
`BlockNonTunnel` before every connection attempt and changes to `TunnelOnly`
only after adapter success. It restores `BlockNonTunnel` before calling adapter
teardown. A firewall error prevents tunnel setup or teardown from creating an
unfiltered interval. Failed setup, invalid session identifiers and failed
teardown retain blocking. Disabling filtering while a tunnel is active is
rejected; always-on controllers cannot be disabled.

On Linux, `NftablesBackend` renders the complete `inet cyberia_vpn` table and
passes it to an absolute, validated `nft` executable through standard input;
no shell parses the rules. Updates use one nftables transaction and never flush
tables owned by other applications. Blocking permits loopback, established
flows and the configured UDP peer endpoint. Tunnel policy additionally permits
output through the validated tunnel interface. Disabling empties the owned
table. The endpoint must be resolved to an IP address before constructing the
backend.

The Linux backend invokes absolute `ip` and `wg` executables directly without a
shell. It requires a private-key file with permissions no broader than `0600`,
creates the interface, applies the peer and endpoint, assigns tunnel addresses,
sets MTU and brings the link up. A failure after interface creation triggers one
bounded delete attempt. A failure to create the link does not delete an existing
interface with the requested name. Teardown deletes only the interface owned by
the active backend instance.

Executable and key paths are deployment inputs and must reside on an operator-
controlled filesystem. The transport backend does not install routes, DNS
policy or NAT, and neither Linux backend is wired into a client executable yet.
Before M1 can claim a working VPN tunnel, the complete path must run with least
privilege inside an isolated Linux network namespace and demonstrate cleanup on
failure.

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
