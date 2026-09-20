# Linux network namespace E2E tests

The scripts in this directory exercise real Linux `ip`, `wg` and `nft`
boundaries. They are deliberately opt-in because they require root or an
equivalent `CAP_NET_ADMIN` environment and create short-lived network
namespaces.

Run a scenario from the repository root:

```sh
sudo tests/e2e/linux-wireguard-namespace.sh
```

Each scenario checks its prerequisites before creating any namespace. It uses a
unique namespace suffix, deletes all created namespaces through an exit trap and
never changes the host routing or nftables tables.
