.PHONY: check format-check rust-check go-check e2e-shell-check e2e-linux

check: format-check rust-check go-check e2e-shell-check

format-check:
	@cargo fmt --all --check
	@test -z "$$(gofmt -l services)" || (gofmt -l services && exit 1)

rust-check:
	@cargo clippy --workspace --all-targets -- -D warnings
	@cargo test --workspace

go-check:
	@go vet ./services/control-api/...
	@go test -race ./services/control-api/...

e2e-shell-check:
	@bash -n tests/e2e/linux-common.sh tests/e2e/linux-common.test.sh \
		tests/e2e/linux-wireguard-namespace.sh tests/e2e/linux-client-failsafe-namespace.sh
	@bash tests/e2e/linux-common.test.sh

e2e-linux:
	@tests/e2e/linux-wireguard-namespace.sh
	@tests/e2e/linux-client-failsafe-namespace.sh
