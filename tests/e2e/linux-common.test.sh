#!/usr/bin/env bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/linux-common.sh"

assert_command_fails false

if command -v bash >/dev/null 2>&1; then
    assert_command_fails bash -c 'exit 1'
fi

(
    ip() { return 0; }
    wait_for_process_link test-namespace wg0 "$$"
)

(
    ip() { return 1; }
    assert_command_fails wait_for_process_link test-namespace wg0 99999999
)
