# Architecture overview

Cyberia VPN consists of five independently evolvable platforms:

1. Cyberia Client presents a simple connect/disconnect experience.
2. Cyberia Transport Engine owns transport adapters and their lifecycle.
3. Cyberia Control Plane owns identity, configuration and node metadata.
4. Cyberia Node Network carries encrypted user traffic.
5. Cyberia Shield detects, limits and isolates infrastructure threats.

The Intelligent Router connects these concerns by choosing a compatible,
healthy node and transport from policy and measurements.

```text
Client -> Transport Engine -> Intelligent Router -> Edge -> Node -> Internet
   |                                |
   +---------- Control API ---------+
                  |
       Identity / Registry / Config
```

## Control plane

The control plane authenticates accounts and devices, authorizes actions,
publishes configuration and routing policy, manages subscriptions, maintains
the node registry and distributes update metadata. Its APIs are versioned,
authenticated, authorized, rate limited and auditable.

It never forwards user VPN traffic.

## Data plane

The data plane establishes tunnels, forwards packets, applies routing/NAT,
forwards DNS requests and implements transport protocols. It scales and fails
independently from the control plane. An unavailable billing or blockchain
integration cannot terminate an established session.

## Data boundaries

Account data, billing data, operational telemetry and security events use
separate logical flows and retention policies. User payloads and browsing
history are not operational telemetry and are not collected by default.

## Planned repository layout

```text
apps/             desktop, mobile and web clients
core/             Rust transport, routing and cryptographic foundations
services/         Go control-plane services
node/             node, health, security and update agents
infrastructure/   deployment and provisioning code
tests/            cross-component integration, end-to-end and fuzz tests
docs/             architecture, operations and product decisions
security/         threat models and defensive policy
```
