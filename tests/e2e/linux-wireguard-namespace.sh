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
client_tunnel="wg-e2e-c"
node_tunnel="wg-e2e-n"
work_directory="$(mktemp -d /tmp/cyberia-vpn-e2e.XXXXXX)"

cleanup() {
    local result="$1"
    if (( result != 0 )); then
        report_namespace_diagnostics "$client_namespace"
        report_namespace_diagnostics "$node_namespace"
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
wg pubkey <"$work_directory/client.key" >"$work_directory/client.pub"
wg pubkey <"$work_directory/node.key" >"$work_directory/node.pub"

ip -n "$node_namespace" link add "$node_tunnel" type wireguard
ip -n "$node_namespace" address add 10.20.0.1/24 dev "$node_tunnel"
ip netns exec "$node_namespace" wg set "$node_tunnel" \
    private-key "$work_directory/node.key" listen-port 51820 \
    peer "$(<"$work_directory/client.pub")" allowed-ips 10.20.0.2/32
ip -n "$node_namespace" link set "$node_tunnel" up

ip -n "$client_namespace" link add "$client_tunnel" type wireguard
ip -n "$client_namespace" address add 10.20.0.2/24 dev "$client_tunnel"
ip netns exec "$client_namespace" wg set "$client_tunnel" \
    private-key "$work_directory/client.key" \
    peer "$(<"$work_directory/node.pub")" endpoint 192.0.2.1:51820 \
    allowed-ips 10.20.0.0/24 persistent-keepalive 1
ip -n "$client_namespace" link set "$client_tunnel" up

ip netns exec "$client_namespace" ping -c 1 -W 2 10.20.0.1 >/dev/null
ip -n "$client_namespace" link delete dev "$client_tunnel"
assert_command_fails ip -n "$client_namespace" link show dev "$client_tunnel"

printf '%s\n' 'Linux WireGuard namespace connect/disconnect scenario passed'
