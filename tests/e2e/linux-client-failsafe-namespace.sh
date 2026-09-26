#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repository_root/tests/e2e/linux-common.sh"

require_linux_e2e_prerequisites

suffix="${RANDOM}${RANDOM}"
client_namespace="cvpn-c-${suffix: -8}"
node_namespace="cvpn-n-${suffix: -8}"
client_veth="v-c-${suffix: -8}"
node_veth="v-n-${suffix: -8}"
node_tunnel="wg-e2e-n"
client_tunnel="wg0"
work_directory="$(mktemp -d /tmp/cyberia-vpn-e2e.XXXXXX)"
client_pid=""

cleanup() {
    local result="$1"
    if (( result != 0 )); then
        report_namespace_diagnostics "$client_namespace"
        report_namespace_diagnostics "$node_namespace"
    fi
    if [[ -n "$client_pid" ]]; then
        kill "$client_pid" >/dev/null 2>&1 || true
        wait "$client_pid" >/dev/null 2>&1 || true
    fi
    ip netns del "$client_namespace" >/dev/null 2>&1 || true
    ip netns del "$node_namespace" >/dev/null 2>&1 || true
    if [[ "$work_directory" == /tmp/cyberia-vpn-e2e.* ]]; then
        rm -rf "$work_directory"
    fi
    trap - EXIT
    exit "$result"
}
trap 'cleanup $?' EXIT

if [[ -n "${CYBERIA_CLIENT_BINARY:-}" ]]; then
    client_binary="$CYBERIA_CLIENT_BINARY"
    if [[ "$client_binary" != /* || ! -f "$client_binary" || ! -x "$client_binary" ]]; then
        printf '%s\n' 'CYBERIA_CLIENT_BINARY must be an absolute executable regular file' >&2
        exit 1
    fi
else
    if ! command -v cargo >/dev/null 2>&1; then
        printf '%s\n' 'Linux client E2E test requires cargo or CYBERIA_CLIENT_BINARY' >&2
        exit 1
    fi
    cargo build -p cyberia-linux-client --quiet
    client_binary="$repository_root/target/debug/cyberia-linux-client"
fi

ip netns add "$client_namespace"
ip netns add "$node_namespace"
ip link add "$client_veth" type veth peer name "$node_veth"
ip link set "$client_veth" netns "$client_namespace"
ip link set "$node_veth" netns "$node_namespace"
ip -n "$client_namespace" link set lo up
ip -n "$node_namespace" link set lo up
ip -n "$client_namespace" address add 192.0.2.2/24 dev "$client_veth"
ip -n "$node_namespace" address add 192.0.2.1/24 dev "$node_veth"
ip -n "$client_namespace" link set "$client_veth" up
ip -n "$node_namespace" link set "$node_veth" up

wg genkey >"$work_directory/client.key"
wg genkey >"$work_directory/node.key"
wg pubkey <"$work_directory/node.key" >"$work_directory/node.pub"
wg pubkey <"$work_directory/client.key" >"$work_directory/client.pub"
chmod 600 "$work_directory/client.key" "$work_directory/node.key"

ip -n "$node_namespace" link add "$node_tunnel" type wireguard
ip -n "$node_namespace" address add 10.20.0.1/24 dev "$node_tunnel"
ip netns exec "$node_namespace" wg set "$node_tunnel" \
    private-key "$work_directory/node.key" listen-port 51820 \
    peer "$(<"$work_directory/client.pub")" allowed-ips 10.20.0.2/32
ip -n "$node_namespace" link set "$node_tunnel" up

resolver="$work_directory/resolvectl"
printf '%s\n' '#!/usr/bin/env sh' 'exit 0' >"$resolver"
chmod 700 "$resolver"
client_config="$work_directory/client.json"
node_public_key_hex="$(base64 -d <"$work_directory/node.pub" | od -An -tx1 | tr -d ' \n')"
cat >"$client_config" <<EOF
{
  "interface": "$client_tunnel",
  "runtime_directory": "$work_directory",
  "endpoint_address": "192.0.2.1",
  "endpoint_port": 51820,
  "peer_public_key_hex": "$node_public_key_hex",
  "tunnel_addresses": ["10.20.0.2/24"],
  "allowed_ips": ["10.20.0.0/24"],
  "dns_resolvers": ["192.0.2.53"],
  "mtu": 1420,
  "persistent_keepalive_seconds": 1,
  "routing_mark": 51820,
  "connect_timeout_seconds": 5,
  "always_on": false,
  "tools": {
    "ip": "$(command -v ip)",
    "wg": "$(command -v wg)",
    "nft": "$(command -v nft)",
    "resolvectl": "$resolver",
    "private_key": "$work_directory/client.key"
  }
}
EOF
chmod 600 "$client_config"

ip netns exec "$client_namespace" "$client_binary" "$client_config" &
client_pid="$!"
wait_for_process_link "$client_namespace" "$client_tunnel" "$client_pid"

attempts=30
while ! ip netns exec "$client_namespace" ping -c 1 -W 1 10.20.0.1 >/dev/null; do
    attempts=$((attempts - 1))
    if (( attempts == 0 )); then
        printf '%s\n' 'Timed out waiting for encrypted client traffic' >&2
        exit 1
    fi
    sleep 0.1
done

contender_log="$work_directory/contender.log"
if ip netns exec "$client_namespace" "$client_binary" "$client_config" \
    >"$contender_log" 2>&1; then
    printf '%s\n' 'Competing client unexpectedly acquired the interface lease' >&2
    exit 1
fi
grep -q 'another client already manages this interface' "$contender_log"
kill -0 "$client_pid"
ip netns exec "$client_namespace" ping -c 1 -W 1 10.20.0.1 >/dev/null

kill -TERM "$client_pid"
if ! wait "$client_pid"; then
    printf '%s\n' 'Client failed to complete graceful teardown' >&2
    exit 1
fi
client_pid=""
assert_command_fails ip -n "$client_namespace" link show dev "$client_tunnel"
if ip netns exec "$client_namespace" nft list table inet cyberia_vpn >/dev/null 2>&1; then
    printf '%s\n' 'Client retained filtering after graceful non-always-on teardown' >&2
    exit 1
fi

ip netns exec "$client_namespace" "$client_binary" "$client_config" &
client_pid="$!"
wait_for_process_link "$client_namespace" "$client_tunnel" "$client_pid"
ip netns exec "$client_namespace" ping -c 1 -W 1 10.20.0.1 >/dev/null

ip -n "$client_namespace" link delete dev "$client_tunnel"
assert_command_fails ip netns exec "$client_namespace" ping -c 1 -W 1 192.0.2.1

kill -TERM "$client_pid"
if wait "$client_pid"; then
    printf '%s\n' 'Client unexpectedly reported successful teardown after tunnel loss' >&2
    exit 1
fi
client_pid=""
ip netns exec "$client_namespace" nft list table inet cyberia_vpn | grep -q 'policy drop'

ip netns exec "$client_namespace" "$client_binary" "$client_config" &
client_pid="$!"
wait_for_process_link "$client_namespace" "$client_tunnel" "$client_pid"
ip netns exec "$client_namespace" ping -c 1 -W 1 10.20.0.1 >/dev/null
kill -KILL "$client_pid"
if wait "$client_pid"; then
    printf '%s\n' 'Client unexpectedly survived forced termination' >&2
    exit 1
fi
client_pid=""
ip -n "$client_namespace" link show dev "$client_tunnel" >/dev/null
ip netns exec "$client_namespace" nft list table inet cyberia_vpn | grep -q 'policy drop'
assert_command_fails ip netns exec "$client_namespace" ping -c 1 -W 1 192.0.2.1
ip -n "$client_namespace" link delete dev "$client_tunnel"
assert_command_fails ip netns exec "$client_namespace" ping -c 1 -W 1 192.0.2.1

always_on_config="$work_directory/client-always-on.json"
sed 's/"always_on": false/"always_on": true/' "$client_config" >"$always_on_config"
chmod 600 "$always_on_config"
ip netns exec "$client_namespace" "$client_binary" "$always_on_config" &
client_pid="$!"
wait_for_process_link "$client_namespace" "$client_tunnel" "$client_pid"
ip netns exec "$client_namespace" ping -c 1 -W 1 10.20.0.1 >/dev/null
kill -TERM "$client_pid"
if ! wait "$client_pid"; then
    printf '%s\n' 'Always-on client failed to complete graceful teardown' >&2
    exit 1
fi
client_pid=""
assert_command_fails ip -n "$client_namespace" link show dev "$client_tunnel"
ip netns exec "$client_namespace" nft list table inet cyberia_vpn | grep -q 'policy drop'
assert_command_fails ip netns exec "$client_namespace" ping -c 1 -W 1 192.0.2.1

printf '%s\n' 'Linux client fail-safe namespace scenario passed'
