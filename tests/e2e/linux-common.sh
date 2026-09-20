#!/usr/bin/env bash
# Shared guards and assertions for privileged Linux network E2E scenarios.

set -euo pipefail

require_linux_e2e_prerequisites() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        printf '%s\n' 'Linux network E2E tests require Linux' >&2
        return 1
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        printf '%s\n' 'Linux network E2E tests require root or CAP_NET_ADMIN' >&2
        return 1
    fi
    local command
    for command in base64 ip nft od ping wg; do
        if ! command -v "$command" >/dev/null 2>&1; then
            printf 'Linux network E2E tests require %s in PATH\n' "$command" >&2
            return 1
        fi
    done
}

wait_for_link() {
    local namespace="$1"
    local interface="$2"
    local attempts=50
    while (( attempts > 0 )); do
        if ip -n "$namespace" link show dev "$interface" >/dev/null 2>&1; then
            return 0
        fi
        attempts=$((attempts - 1))
        sleep 0.1
    done
    printf 'Timed out waiting for interface %s in namespace %s\n' "$interface" "$namespace" >&2
    return 1
}

assert_command_fails() {
    if "$@"; then
        printf 'Command unexpectedly succeeded: %q ' "$@" >&2
        printf '\n' >&2
        return 1
    fi
}

report_namespace_diagnostics() {
    local namespace="$1"
    printf '%s\n' "--- diagnostics for namespace $namespace ---" >&2
    ip -n "$namespace" link show >&2 || true
    ip -n "$namespace" address show >&2 || true
    ip netns exec "$namespace" wg show >&2 || true
    ip netns exec "$namespace" nft list table inet cyberia_vpn >&2 || true
}
