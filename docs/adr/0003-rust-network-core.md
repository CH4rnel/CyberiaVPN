# ADR-0003: Use Rust for the network core

- Status: Accepted
- Date: 2026-09-04
- Owners: transport and routing

## Context

Transport lifecycle, route selection and packet-adjacent code are exposed to
untrusted network input and need predictable performance across client targets.

## Decision

The shared transport and routing core is implemented in stable Rust with safe
Rust as the default. Any `unsafe` block requires a documented invariant,
focused tests and security review. Control-plane services may use Go behind
versioned network contracts.

## Consequences

The core gains strong ownership and type guarantees but needs a deliberate FFI
boundary for mobile and desktop clients. The project must keep compile times and
platform toolchains under continuous observation.

## Validation

CI formats, lints and tests the complete Rust workspace. Network parsers will
gain property tests and fuzz targets before processing production input.
