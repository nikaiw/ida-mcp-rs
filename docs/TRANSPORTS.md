# Transports

## Stdio (default)

- Single-client, simplest setup.
- Use with CLI agents that launch a child process.

```bash
./target/release/ida-mcp
```

## Streamable HTTP (multi-client)

- Supports multiple clients over HTTP.
- SSE is used for streaming responses within this transport.
- The server validates Origin headers; defaults allow localhost only.

```bash
./target/release/ida-mcp serve-http --bind 127.0.0.1:8765
```

Options:
- `--stateless`: POST-only mode (no sessions)
- `--allow-origin`: comma-separated allowlist
- `--sse-keep-alive-secs`: keep-alive interval (0 disables)

## Concurrency model

IDA requires main-thread access. All IDA operations are serialized through a single
worker loop, while multiple clients can submit requests concurrently.

## Shutdown

The server listens for SIGINT/SIGTERM/SIGQUIT and will close the open database
before exiting when possible.
