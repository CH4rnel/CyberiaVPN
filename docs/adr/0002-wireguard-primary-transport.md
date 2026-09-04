# ADR-0002: Use WireGuard as the primary transport

- Status: Accepted
- Date: 2026-09-04
- Owners: transport

## Context

The MVP needs one small, modern and widely supported transport before the
engine expands to compatibility and constrained-network protocols.

## Decision

WireGuard is the first production transport and the reference adapter for the
common transport lifecycle. It is preferred by automatic policy when it is
available and meets health requirements. Other transports remain first-class
adapters rather than WireGuard-specific branches in client code.

## Consequences

The MVP stays focused and gains mature platform implementations. UDP-restricted
networks will require later fallback adapters. Key distribution, rotation and
revocation become explicit control-plane responsibilities.

## Validation

M1 requires interoperability tests on supported platforms, safe teardown,
bounded connection time and confirmation that private keys never leave their
owning device or node.
