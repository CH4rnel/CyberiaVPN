#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repository_root/tests/e2e/linux-common.sh"

require_linux_e2e_tools
ip netns list >/dev/null

if [[ -n "${CYBERIA_CLIENT_BINARY:-}" ]]; then
    if [[ "$CYBERIA_CLIENT_BINARY" != /* || ! -f "$CYBERIA_CLIENT_BINARY" || ! -x "$CYBERIA_CLIENT_BINARY" ]]; then
        printf '%s\n' 'CYBERIA_CLIENT_BINARY must be an absolute executable regular file' >&2
        exit 1
    fi
elif ! command -v cargo >/dev/null 2>&1; then
    printf '%s\n' 'Linux E2E preflight requires cargo or CYBERIA_CLIENT_BINARY' >&2
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]] && ! sudo -n true; then
    printf '%s\n' 'Linux E2E preflight requires passwordless sudo for the runner user' >&2
    exit 1
fi

printf '%s\n' 'Linux E2E preflight passed'
