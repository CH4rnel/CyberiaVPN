# Architecture decision records

Architecture decision records (ADRs) preserve the reason behind decisions that
are expensive to reverse or affect multiple components.

## Process

1. Copy `template.md` to the next zero-padded number.
2. Open the record as `Proposed` before implementation.
3. Merge it as `Accepted` when the decision is approved.
4. Never rewrite history: supersede an old record with a new one.

## Index

- [ADR-0001: Separate control and data planes](0001-control-data-plane-separation.md)
- [ADR-0002: Use WireGuard as the primary transport](0002-wireguard-primary-transport.md)
- [ADR-0003: Use Rust for the network core](0003-rust-network-core.md)
