use ida_mcp::{ToolCategory, ToolInfo, TOOL_REGISTRY};
use std::collections::HashMap;
use std::fmt::Write as _;

fn category_order() -> Vec<ToolCategory> {
    vec![
        ToolCategory::Core,
        ToolCategory::Functions,
        ToolCategory::Disassembly,
        ToolCategory::Decompile,
        ToolCategory::Xrefs,
        ToolCategory::ControlFlow,
        ToolCategory::Memory,
        ToolCategory::Search,
        ToolCategory::Metadata,
        ToolCategory::Types,
        ToolCategory::Editing,
        ToolCategory::Debug,
        ToolCategory::Ui,
        ToolCategory::Scripting,
    ]
}

fn category_title(cat: ToolCategory) -> &'static str {
    match cat {
        ToolCategory::Core => "Core (default)",
        ToolCategory::Functions => "Functions",
        ToolCategory::Disassembly => "Disassembly",
        ToolCategory::Decompile => "Decompile",
        ToolCategory::Xrefs => "Xrefs",
        ToolCategory::ControlFlow => "Control Flow",
        ToolCategory::Memory => "Memory",
        ToolCategory::Search => "Search",
        ToolCategory::Metadata => "Metadata",
        ToolCategory::Types => "Types",
        ToolCategory::Editing => "Editing",
        ToolCategory::Debug => "Debug",
        ToolCategory::Ui => "UI",
        ToolCategory::Scripting => "Scripting",
    }
}

fn is_headless_unsupported(cat: ToolCategory) -> bool {
    matches!(
        cat,
        ToolCategory::Types
            | ToolCategory::Editing
            | ToolCategory::Debug
            | ToolCategory::Ui
            | ToolCategory::Scripting
    )
}

fn all_tools_unsupported(tools: &[&ToolInfo]) -> bool {
    tools
        .iter()
        .all(|tool| tool.short_desc.contains("not supported"))
}

fn main() {
    let mut groups: HashMap<ToolCategory, Vec<&ToolInfo>> = HashMap::new();
    for tool in TOOL_REGISTRY {
        groups.entry(tool.category).or_default().push(tool);
    }
    for tools in groups.values_mut() {
        tools.sort_by_key(|t| t.name);
    }

    let default_count = TOOL_REGISTRY.iter().filter(|t| t.default).count();

    let mut out = String::new();
    let _ = writeln!(out, "# Tools\n");
    let _ = writeln!(
        out,
        "> Auto-generated from `src/tool_registry.rs`. Do not edit by hand."
    );
    let _ = writeln!(
        out,
        "> Regenerate with: `cargo run --bin gen_tools_doc -- docs/TOOLS.md`.\n"
    );

    let _ = writeln!(out, "## Discovery Workflow\n");
    let _ = writeln!(
        out,
        "- `tools/list` returns a minimal core set (currently {default_count} tools)"
    );
    let _ = writeln!(
        out,
        "- `tool_catalog(query=...)` searches all tools by intent"
    );
    let _ = writeln!(
        out,
        "- `tool_help(name=...)` returns full documentation and schema"
    );
    let _ = writeln!(
        out,
        "- `enable_tools(...)` expands what `tools/list` exposes\n"
    );

    let _ = writeln!(
        out,
        "Note: `open_idb` accepts .i64/.idb or raw binaries (Mach-O/ELF/PE). Raw binaries are"
    );
    let _ = writeln!(
        out,
        "auto-analyzed and saved as a .i64 alongside the input. If a sibling .dSYM"
    );
    let _ = writeln!(
        out,
        "exists and no .i64 is present, its DWARF debug info is loaded automatically.\n"
    );

    let _ = writeln!(out, "## Enable Tools\n");
    let _ = writeln!(out, "Enable by category:");
    let _ = writeln!(
        out,
        "```json\n{{\"categories\": [\"xrefs\", \"control_flow\"]}}\n```"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "Enable specific tools:");
    let _ = writeln!(
        out,
        "```json\n{{\"tools\": [\"callgraph\", \"find_paths\"]}}\n```"
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "After enabling, `tools/list` returns the expanded set and emits"
    );
    let _ = writeln!(out, "`notifications/tools/list_changed`.\n");

    for cat in category_order() {
        let Some(tools) = groups.get(&cat) else {
            continue;
        };
        if tools.is_empty() {
            continue;
        }
        let _ = writeln!(out, "## {} (`{}`)\n", category_title(cat), cat.as_str());
        let _ = writeln!(out, "{}", cat.description());
        if is_headless_unsupported(cat) && all_tools_unsupported(tools) {
            let _ = writeln!(
                out,
                "Headless unsupported: these tools return NotSupported in headless mode."
            );
        }
        let _ = writeln!(out, "\n| Tool | Description |");
        let _ = writeln!(out, "|------|-------------|");
        for tool in tools {
            let _ = writeln!(out, "| `{}` | {} |", tool.name, tool.short_desc);
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## Notes\n");
    let _ = writeln!(
        out,
        "- Many tools accept a single value or array (e.g., `\"0x1000\"` or `[\"0x1000\", \"0x2000\"]`)"
    );
    let _ = writeln!(
        out,
        "- String inputs may be comma-separated: `\"0x1000, 0x2000\"`"
    );
    let _ = writeln!(out, "- Addresses accept hex (`0x1000`) or decimal (`4096`)");
    let _ = writeln!(
        out,
        "- Raw binaries are auto-analyzed on first open; `.i64` is saved alongside the input"
    );

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        if let Err(err) = std::fs::write(&args[1], out) {
            eprintln!("failed to write {}: {}", args[1], err);
            std::process::exit(1);
        }
    } else {
        print!("{out}");
    }
}
