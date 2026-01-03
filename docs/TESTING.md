# Testing

## Run tests

```bash
make test       # Stdio JSONL integration test
make test-http  # HTTP/SSE integration test
```

## What's tested

**Stdio test** (`make test`)
- MCP protocol handshake
- Tool discovery (`tool_catalog`, `tool_help`)
- Database operations (`open_idb`, `close_idb`, `idb_meta`)
- Analysis tools (`list_functions`, `resolve_function`, `disasm_by_name`, `find_insns`, `find_insn_operands`)
- Editing tools (`set_comments`, `rename`, `patch`, `patch_asm`)
- Types/stack tools (`declare_type`, `apply_types`, `infer_types`, `stack_frame`, `declare_stack`, `delete_stack`)
- Metadata tools (`segments`, `strings`, `imports`, `exports`, `structs`, `xrefs_to_field`, `search_structs`)

**HTTP test** (`make test-http`)
- Streamable HTTP transport with SSE
- `tools/list` returns minimal core tools
- `enable_tools` expands the visible tool list
- `notifications/tools/list_changed` emitted over SSE
- Database operations work over HTTP (`open_idb`, `list_functions`, `close_idb`)

## Test fixture

Tests use `test/fixtures/mini.c`, a minimal C program compiled into a Mach-O binary.
The tests open the raw binary via `open_idb` (IDA auto-analyzes and writes an .i64 alongside).
