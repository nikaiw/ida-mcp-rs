# Building from Source

## Prerequisites

- IDA Pro 9.2+ with valid license
- Rust 1.77+ (stable toolchain)
- LLVM/Clang (for C++ bindings)

## Build

```bash
git clone https://github.com/blacktop/ida-mcp-rs.git
cd ida-mcp-rs
cargo build --release
```

The binary is at `target/release/ida-mcp`.

## IDA Installation Path

Build is configured for IDA 9.2 at `/Applications/IDA Professional 9.2.app/Contents/MacOS`.

Set `IDADIR` if your installation differs:

```bash
IDADIR=/path/to/ida cargo build --release
```

## RPATH

The IDA library path is baked into the binary via RPATH at build time, so no wrapper script or environment variables are needed at runtime.

## Run modes

```bash
# Stdio (default, single-client)
./target/release/ida-mcp

# Streamable HTTP (multi-client, SSE)
./target/release/ida-mcp serve-http --bind 127.0.0.1:8765

# CLI probe (test IDA connection)
./target/release/ida-mcp probe --path /path/to/binary --list 10
```
