# Cyberia VPN

Cyberia VPN is being built as the secure network access layer of the Cyberia
ecosystem. The target platform separates its control plane from its data plane
and combines a multi-protocol transport engine, deterministic routing, managed
nodes, private DNS and defensive security controls.

The project is at **Phase 0: Architecture**. Code merged at this stage is a
foundation, not a production-ready VPN service.

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

## Status

The current milestone is **M0**, which delivers architecture records, a threat
model, protocol contracts, a repository skeleton and continuous integration.
M1 will be the first milestone with an end-to-end WireGuard connection.

## License

Apache License 2.0. See [LICENSE](LICENSE).
