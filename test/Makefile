# Test Makefile for ida-mcp

CC ?= cc
CFLAGS ?= -O0 -g -fno-omit-frame-pointer

TEST_SRC := fixtures/mini.c
TEST_BIN := fixtures/mini
TEST_LOCK := fixtures/mini.imcp

SERVER_BIN ?= ../target/release/ida-mcp
RUST_LOG ?= ida_mcp=trace

.PHONY: all fixture test test-http clean

all: fixture

fixture: $(TEST_BIN)

$(TEST_BIN): $(TEST_SRC)
	$(CC) $(CFLAGS) -o "$@" "$<"

test: $(TEST_BIN)
	@if [ ! -x "$(SERVER_BIN)" ]; then \
		echo "Server binary not found: $(SERVER_BIN)"; \
		echo "Run 'cargo build --release' first"; \
		exit 1; \
	fi
	@LOCK="$(TEST_LOCK)"; \
	if [ -f "$$LOCK" ]; then \
		pid=$$(awk -F= '$$1=="pid"{print $$2}' "$$LOCK" | tr -d '\r'); \
		if [ -n "$$pid" ] && kill -0 "$$pid" 2>/dev/null; then \
			echo "Lock file $$LOCK is held by pid $$pid; close that server first." >&2; \
			exit 1; \
		else \
			rm -f "$$LOCK"; \
		fi; \
	fi
	@echo "🧪 Running stdio integration test..."
	@tmp="$$(mktemp)"; \
	RUST_LOG="$(RUST_LOG)" "$(SERVER_BIN)" < payloads/mini.jsonl >"$$tmp" 2>&1; \
	cat "$$tmp"; \
	if rg -q '\"isError\"\\s*:\\s*true' "$$tmp"; then \
		rm -f "$$tmp"; \
		exit 1; \
	fi; \
	rm -f "$$tmp"
	@echo "✅ Stdio test passed"

test-http: $(TEST_BIN)
	@if [ ! -x "$(SERVER_BIN)" ]; then \
		echo "Server binary not found: $(SERVER_BIN)"; \
		echo "Run 'cargo build --release' first"; \
		exit 1; \
	fi
	@LOCK="$(TEST_LOCK)"; \
	if [ -f "$$LOCK" ]; then \
		pid=$$(awk -F= '$$1=="pid"{print $$2}' "$$LOCK" | tr -d '\r'); \
		if [ -n "$$pid" ] && kill -0 "$$pid" 2>/dev/null; then \
			echo "Lock file $$LOCK is held by pid $$pid; close that server first." >&2; \
			exit 1; \
		else \
			rm -f "$$LOCK"; \
		fi; \
	fi
	@echo "🧪 Running HTTP integration test..."
	RUST_LOG="$(RUST_LOG)" IDB_PATH="$(TEST_BIN)" MCP_HTTP_BIN="$(SERVER_BIN)" ./http_integration.sh
	@echo "✅ HTTP test passed"

clean:
	rm -f $(TEST_BIN)
	rm -rf fixtures/mini.dSYM
	rm -f fixtures/*.i64 fixtures/*.idb
	rm -f fixtures/*.id0 fixtures/*.id1 fixtures/*.id2 fixtures/*.nam fixtures/*.til fixtures/*.imcp
