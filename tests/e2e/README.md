# Linux network namespace E2E tests

The scripts in this directory exercise real Linux `ip`, `wg` and `nft`
boundaries. They are deliberately opt-in because they require root or an
equivalent `CAP_NET_ADMIN` environment and create short-lived network
namespaces.

Run a scenario from the repository root:

```sh
sudo tests/e2e/linux-wireguard-namespace.sh

# Run the complete privileged suite.
sudo make e2e-linux
```

Each scenario checks its prerequisites before creating any namespace. It uses a
unique namespace suffix, deletes all created namespaces through an exit trap and
never changes the host routing or nftables tables.

`linux-wireguard-namespace.sh` creates two namespaces joined by a veth underlay,
configures both ends of a WireGuard tunnel, proves encrypted ICMP traffic and
then verifies that the client interface was removed.

`linux-client-failsafe-namespace.sh` launches the compiled Linux client in the
client namespace with a generated key and a no-op resolver stub. It proves
tunnel traffic, removes the tunnel underneath the client, verifies that ordinary
underlay ICMP is blocked, and confirms that a failed teardown retains the
default-deny nftables policy.
