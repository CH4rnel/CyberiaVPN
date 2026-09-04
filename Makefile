.PHONY: check format-check rust-check go-check

check: format-check rust-check go-check

format-check:
	@cargo fmt --all --check
	@test -z "$$(gofmt -l services)" || (gofmt -l services && exit 1)

rust-check:
	@cargo clippy --workspace --all-targets -- -D warnings
	@cargo test --workspace

go-check:
	@go vet ./services/control-api/...
	@go test -race ./services/control-api/...
