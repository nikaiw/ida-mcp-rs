# IDA MCP Server Makefile

.PHONY: build
build: ## Build debug binary
	cargo build

.PHONY: release
release: ## Build release binary
	cargo build --release

.PHONY: snapshot
snapshot: ## Build snapshot with goreleaser
	goreleaser build --clean --timeout 60m --snapshot

.PHONY: dist
dist: ## Build and publish release with goreleaser
	goreleaser release --clean --timeout 60m --skip=validate

.PHONY: test
test: build ## Run integration test (debug)
	$(MAKE) -C test test SERVER_BIN=../target/debug/ida-mcp RUST_LOG=ida_mcp=trace

.PHONY: test-http
test-http: build ## Run HTTP integration test (debug)
	$(MAKE) -C test test-http SERVER_BIN=../target/debug/ida-mcp RUST_LOG=ida_mcp=trace

.PHONY: cargo-test
cargo-test: ## Run cargo unit tests
	RUST_BACKTRACE=1 cargo test

.PHONY: fmt
fmt: ## Format code
	cargo fmt --all

.PHONY: lint
lint: ## Run clippy linter
	cargo clippy -- -D warnings

.PHONY: clean
clean: ## Clean build artifacts
	cargo clean
	rm -rf dist/
	$(MAKE) -C test clean

.PHONY: bump
bump: ## Bump version and push tag
	git tag $(shell svu patch)
	git push --tags

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_%-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
