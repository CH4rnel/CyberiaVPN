# ADR-0001: Separate control and data planes

- Status: Accepted
- Date: 2026-09-04
- Owners: platform

## Context

Identity and configuration workloads have different scaling, availability and
privacy characteristics from encrypted packet forwarding. Coupling them would
let a control-plane or business-system outage interrupt active VPN sessions and
would expose packet-processing services to unnecessary account data.

## Decision

Control-plane services manage identity, authorization, configuration, routing
policy and node metadata. Data-plane components establish transports and
forward traffic. Communication across the boundary uses explicit, versioned
contracts. Established sessions do not require continuous control-plane access.

## Consequences

Each plane can scale and fail independently, and access policies remain narrow.
Configuration must be cached with a bounded validity period, and eventual
consistency across the boundary must be handled deliberately.

## Validation

Integration tests will withdraw the Control API during an active test tunnel
and verify that forwarding continues until the configuration expires.
