# Privileged Linux E2E runner

The `Linux E2E` workflow is manual and targets only a self-hosted runner with
the labels `self-hosted`, `linux` and `cyberia-vpn-e2e`. It must not run on a
shared or production node: the scenarios create network namespaces, WireGuard
interfaces and nftables tables inside those namespaces.

Install the Linux `ip`, `wg`, `nft`, `ping`, `base64`, `od`, `make` and Rust
1.85 toolchain packages. The runner service account needs passwordless `sudo`
for `make e2e-linux`; do not grant a general interactive shell exemption.

The workflow builds the client as the runner user and passes the resulting
absolute artifact through `CYBERIA_CLIENT_BINARY`. This avoids depending on the
root user's Rust installation. `make e2e-linux` performs a prerequisite check
before it creates a namespace and cleans all created namespaces on exit.

Before registering the runner, execute `make e2e-linux-preflight` as the runner
service account. It does not create a namespace; it verifies the required Linux
tools, `ip netns` access, an available client build path and passwordless sudo.
The workflow repeats this check before it builds or invokes the privileged test
suite.

Trigger the workflow only from a reviewed commit. A successful default CI run
does not certify the privileged tests, and a privileged test result does not
replace normal Rust, Go or review gates.
