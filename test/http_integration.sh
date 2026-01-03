#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8765}"
BIN="${MCP_HTTP_BIN:-./target/release/ida-mcp}"
ORIGIN="${MCP_HTTP_ORIGIN:-http://localhost}"
IDB_PATH="${IDB_PATH:-fixtures/mini}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
stream_file="$tmpdir/stream.log"
headers_file="$tmpdir/headers.log"
body_file="$tmpdir/body.log"
server_log="$tmpdir/server.log"

cleanup() {
  if [[ -n "${sse_pid:-}" ]]; then
    kill "$sse_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

"$BIN" serve-http --bind "127.0.0.1:$PORT" --allow-origin "http://localhost,http://127.0.0.1" >"$server_log" 2>&1 &
server_pid=$!

init_payload='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"0.1"},"capabilities":{}}}'

session_id=""
for _ in {1..100}; do
  if curl -sS -D "$headers_file" -o "$body_file" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Origin: $ORIGIN" \
    -d "$init_payload" \
    "http://127.0.0.1:$PORT/" >/dev/null 2>/dev/null; then
    session_id="$(awk -F': ' 'tolower($1)=="mcp-session-id" {print $2}' "$headers_file" | tr -d '\r')"
    if [[ -n "$session_id" ]]; then
      break
    fi
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if [[ -z "$session_id" ]]; then
  echo "failed to obtain Mcp-Session-Id" >&2
  if [[ -s "$server_log" ]]; then
    echo "server output:" >&2
    cat "$server_log" >&2
  fi
  exit 1
fi

# Send notifications/initialized
curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  "http://127.0.0.1:$PORT/" >/dev/null

# Open SSE stream to receive list_changed notifications
curl -sN \
  -H "Accept: text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  "http://127.0.0.1:$PORT/" > "$stream_file" &
sse_pid=$!

sleep 0.5

# tools/list should include core tools
list_resp=$(curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  "http://127.0.0.1:$PORT/")

echo "$list_resp" | grep -q '"enable_tools"' || {
  echo "tools/list missing enable_tools" >&2
  exit 1
}

# enable_tools for xrefs
curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"enable_tools","arguments":{"categories":["xrefs"]}}}' \
  "http://127.0.0.1:$PORT/" >/dev/null

# tools/list should now include xrefs_to
list_resp2=$(curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}' \
  "http://127.0.0.1:$PORT/")

echo "$list_resp2" | grep -q '"xrefs_to"' || {
  echo "tools/list missing xrefs_to after enable_tools" >&2
  exit 1
}

# Wait briefly for list_changed notification
found=0
for _ in {1..20}; do
  if grep -q "notifications/tools/list_changed" "$stream_file"; then
    found=1
    break
  fi
  sleep 0.1
done

if [[ "$found" -ne 1 ]]; then
  echo "list_changed notification not observed" >&2
  exit 1
fi

# Open mini fixture and verify functions list
open_resp=$(curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"open_idb\",\"arguments\":{\"path\":\"$IDB_PATH\"}}}" \
  "http://127.0.0.1:$PORT/")

echo "$open_resp" | grep -q "function_count" || {
  echo "open_idb failed" >&2
  echo "$open_resp" >&2
  exit 1
}

func_resp=$(curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"list_functions","arguments":{"limit":10}}}' \
  "http://127.0.0.1:$PORT/")

echo "$func_resp" | grep -q "interesting_function" || {
  echo "list_functions missing interesting_function" >&2
  echo "$func_resp" >&2
  exit 1
}

curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}' \
  "http://127.0.0.1:$PORT/" >/dev/null

echo "HTTP integration test passed"
