# rttp Makefile
#
# Prerequisites:
#   cargo install cargo-watch   (for watch / watch-test targets)
#   cargo install cargo-audit   (for audit target)

.PHONY: all build test lint fmt fmt-check check clean doc doc-build audit run watch watch-test ci help

## all: Run check, lint, and test (default target)
all: check lint test

## build: Compile the library and all examples
build:
	cargo build --all-targets

## test: Run all unit and integration tests
test:
	cargo test --all-targets --all-features

## lint: Run Clippy — warnings are treated as errors
lint:
	cargo clippy --all-targets --all-features -- -D warnings

## fmt: Auto-format all source files with rustfmt
fmt:
	cargo fmt --all

## fmt-check: Check formatting without modifying files (used in CI)
fmt-check:
	cargo fmt --all -- --check

## check: Fast compile check without producing binaries
check:
	cargo check --all-targets --all-features

## clean: Remove all build artifacts
clean:
	cargo clean

## doc: Generate documentation and open it in the browser
doc:
	cargo doc --no-deps --open

## doc-build: Generate documentation without opening the browser
doc-build:
	cargo doc --no-deps

## audit: Scan dependencies for known security vulnerabilities
audit:
	cargo audit

## run: Run the hello_world example (INFO log level)
run:
	RUST_LOG=info cargo run --example hello_world

## watch: Watch for changes and re-run the hello_world example (requires cargo-watch)
watch:
	RUST_LOG=info cargo watch -x 'run --example hello_world'

## watch-test: Watch for changes and re-run tests (requires cargo-watch)
watch-test:
	cargo watch -x 'test --all-targets'

## ci: Simulate the full CI pipeline locally (fmt-check → check → lint → test → audit)
ci: fmt-check check lint test audit

## help: Show this help message
help:
	@echo "rttp — Rust HTTP Server Framework"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /' | column -t -s ':'
