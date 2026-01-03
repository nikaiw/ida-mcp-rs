# ida-mcp

Headless IDA Pro MCP server for AI-powered reverse engineering.

## Prerequisites

- IDA Pro 9.2+ with valid license

## Getting Started

### Install

Via [Homebrew](https://brew.sh)
```bash
brew install blacktop/tap/ida-mcp
```

**Download binary**

Grab the latest release from [GitHub Releases](https://github.com/blacktop/ida-mcp-rs/releases).

**Build from source**

See [docs/BUILDING.md](docs/BUILDING.md).

### Configure your AI agent

#### [Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/overview)
```bash
claude mcp add ida -- ida-mcp
```

#### [Codex CLI](https://platform.openai.com/docs/guides/mcp)
```bash
cursor mcp add ida -- ida-mcp
```

#### [Gemini CLI](https://github.com/google/gemini-cli)

```bash
gemini mcp add ida ida-mcp
```

### Usage

Once configured, you can analyze binaries through your AI agent:

```
# Open a binary (IDA analyzes raw binaries automatically)
open_idb(path: "~/samples/malware")

# Discover available tools
tool_catalog(query: "find callers")

# List functions
list_functions(limit: 20)

# Disassemble by name
disasm_by_name(name: "main", count: 20)

# Decompile (requires Hex-Rays)
decompile(address: "0x100000f00")
```

The default tool list is intentionally minimal to avoid context bloat. Use `tool_catalog` to discover tools and `enable_tools` to expand what's visible.

## Docs

- [docs/TOOLS.md](docs/TOOLS.md) - Tool catalog and discovery workflow
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) - Stdio vs Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) - Build from source
- [docs/TESTING.md](docs/TESTING.md) - Running tests

## License

MIT Copyright (c) 2026 **blacktop**
