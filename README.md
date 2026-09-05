# Cyberia VPN

Cyberia VPN is being built as the secure network access layer of the Cyberia
ecosystem. The target platform separates its control plane from its data plane
and combines a multi-protocol transport engine, deterministic routing, managed
nodes, private DNS and defensive security controls.

The project has an architecture baseline and is building **M1 foundations**.
The current code is not a production-ready VPN service and cannot yet establish
a VPN tunnel.

## Engineering principles

- security and privacy by design;
- explicit control-plane/data-plane boundaries;
- least privilege and fail-secure defaults;
- deterministic routing before ML-assisted routing;
- test-first development for critical logic;
- observable services without collection of user traffic contents.

## Repository map

The planned top-level layout is described in
[docs/architecture/overview.md](docs/architecture/overview.md). The delivery
sequence and acceptance criteria live in [docs/ROADMAP.md](docs/ROADMAP.md).
Development follows the TDD, XP and SOLID guidance in
[CONTRIBUTING.md](CONTRIBUTING.md), backed by the project
[test strategy](docs/testing/strategy.md).

## Status

The repository includes device proof-of-possession verification, signed public
configuration envelopes, in-memory configuration and node stores, deterministic
routing, retry policies and a kill-switch state machine. These are domain
components; the HTTP service currently exposes only health and version endpoints.
M1 still requires authenticated API integration, replay-safe enrollment, a real
WireGuard adapter, OS firewall integration and an end-to-end connection test.

## Local development

Run all formatting, lint and test checks:

```sh
make check
```

Start the development API in another terminal:

```sh
go run ./services/control-api/cmd/server
```

It listens on `127.0.0.1:8080` by default. Set `CYBERIA_API_ADDRESS` to override
the bind address. Check the service with:

```sh
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/api/v1/version
```

SIGINT and SIGTERM stop accepting connections and allow active requests up to
10 seconds to finish. Remaining connections are then closed; a failed graceful
shutdown exits with a nonzero status.

See [the current component contracts](docs/architecture/component-contracts.md)
for validation rules and integration boundaries.

## License

Apache License 2.0. See [LICENSE](LICENSE).
