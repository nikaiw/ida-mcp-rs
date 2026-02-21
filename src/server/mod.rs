//! MCP server implementation with IDA Pro tools.

mod requests;

pub use requests::*;

use crate::error::ToolError;
use crate::ida::IdaWorker;
use crate::tool_registry::{self, ToolCategory};
use rmcp::{
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo, Tool},
    schemars::{schema_for, JsonSchema},
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, info, instrument};

/// Format a serializable result for MCP response text.
/// Tries TOON encoding for tabular data; falls back to compact JSON.
fn format_response<T: Serialize + std::fmt::Debug>(result: &T) -> String {
    crate::toon::try_encode(result).unwrap_or_else(|| {
        serde_json::to_string(result).unwrap_or_else(|_| format!("{:?}", result))
    })
}

/// MCP server for IDA Pro analysis
#[derive(Clone)]
pub struct IdaMcpServer {
    worker: Arc<IdaWorker>,
    tool_mux: ToolMux<IdaMcpServer>,
    mode: ServerMode,
}

#[derive(Clone, Copy, Debug)]
pub enum ServerMode {
    Stdio,
    Http,
}

#[derive(Clone)]
struct ToolMux<S> {
    call_router: ToolRouter<S>,
}

impl<S> ToolMux<S>
where
    S: Send + Sync + 'static,
{
    fn new(call_router: ToolRouter<S>) -> Self {
        Self { call_router }
    }

    async fn call(
        &self,
        context: ToolCallContext<'_, S>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.call_router.call(context).await
    }

    fn get(&self, name: &str) -> Option<&Tool> {
        self.call_router.map.get(name).map(|route| &route.attr)
    }

    fn list_all(&self) -> Vec<Tool> {
        let mut tools = Vec::new();
        for info in tool_registry::all_tools() {
            if let Some(route) = self.call_router.map.get(info.name) {
                tools.push(route.attr.clone());
            }
        }
        tools
    }
}

impl IdaMcpServer {
    pub fn new(worker: Arc<IdaWorker>, mode: ServerMode) -> Self {
        info!("Creating IDA MCP server");
        let call_router = Self::tool_router();
        Self {
            worker,
            tool_mux: ToolMux::new(call_router),
            mode,
        }
    }

    fn close_hint(&self) -> &'static str {
        match self.mode {
            ServerMode::Stdio => {
                "Call close_idb when done to release locks for other sessions."
            }
            ServerMode::Http => {
                "In multi-client (HTTP/SSE) mode, close_idb requires the close_token returned by open_idb; only the opener should close."
            }
        }
    }

    fn instructions(&self) -> String {
        format!(
            "IDA Pro headless analysis server for reverse engineering binaries. \
                 \n\nWorkflow: \
                 \n1. open_idb: Open a .i64/.idb file or a raw binary (Mach-O/ELF/PE). Large DBs may take 30+ seconds. \
                 \n   load_debug_info: Optional for existing .i64 to load DWARF/dSYM \
                 \n2. tool_catalog: Discover tools for your task (e.g., 'find callers', 'decompile') \
                 \n3. tool_help: Get full docs for a specific tool \
                 \n4. Use the discovered tools to analyze the binary \
                 \n5. close_idb: Optionally close when done \
                 \n\nNote: tools/list exposes the full tool set by default; use tool_catalog/tool_help to discover usage. \
                 \n{close_hint} \
                 \n\nTool Categories: \
                 \n- core: open/close/discover (open_idb, close_idb, tool_catalog, tool_help, idb_meta) \
                 \n- functions: list, resolve, lookup functions \
                 \n- disassembly: disasm at addresses \
                 \n- decompile: Hex-Rays pseudocode \
                 \n- xrefs: cross-reference analysis \
                 \n- control_flow: CFG, callgraph, paths \
                 \n- memory: read bytes, strings, values \
                 \n- search: find patterns, strings \
                 \n- metadata: segments, imports, exports \
                 \n- types: declare_type, apply_types (addr/stack), infer_types, local_types, stack_frame, declare_stack, delete_stack, structs (list/info/read) \
                \n- editing: comments/rename/patch/patch_asm \
                 \n- scripting: run_script (execute IDAPython code) \
                 \n\nTip: Use tool_catalog(query='what you want to do') to find the right tool. \
                 \nTip: If xrefs/decompile look incomplete, call analysis_status to check auto-analysis.",
            close_hint = self.close_hint()
        )
    }

    fn validate_path(path: &str) -> bool {
        let path = path.trim();
        let expanded = if let Some(stripped) = path.strip_prefix("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                std::path::PathBuf::from(home).join(stripped)
            } else {
                return false;
            }
        } else {
            std::path::PathBuf::from(path)
        };
        let p = expanded.as_path();
        // Check: exists, is file, no path traversal
        // IDA can open many formats: .i64, .idb, ELF, Mach-O, PE, raw binaries, etc.
        p.exists() && p.is_file() && !path.contains("..")
    }

    fn parse_address(s: &str) -> Result<u64, ToolError> {
        let mut s = s.trim().to_string();
        s.retain(|c| c != '_');
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).map_err(|_| ToolError::InvalidAddress(s))
        } else if s.starts_with("0b") || s.starts_with("0B") {
            u64::from_str_radix(&s[2..], 2).map_err(|_| ToolError::InvalidAddress(s))
        } else if s.starts_with("0o") || s.starts_with("0O") {
            u64::from_str_radix(&s[2..], 8).map_err(|_| ToolError::InvalidAddress(s))
        } else {
            s.parse()
                .map_err(|_| ToolError::InvalidAddress(s.to_string()))
        }
    }

    fn value_to_strings(value: &Value) -> Result<Vec<String>, ToolError> {
        match value {
            Value::String(s) => {
                if s.contains(',') {
                    Ok(s.split(',')
                        .map(|t| t.trim())
                        .filter(|t| !t.is_empty())
                        .map(|t| t.to_string())
                        .collect())
                } else if s.trim().is_empty() {
                    Err(ToolError::IdaError("empty string".to_string()))
                } else {
                    Ok(vec![s.to_string()])
                }
            }
            Value::Number(n) => Ok(vec![n.to_string()]),
            Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::String(s) => out.push(s.to_string()),
                        Value::Number(n) => out.push(n.to_string()),
                        _ => {
                            return Err(ToolError::IdaError(
                                "expected string or number".to_string(),
                            ))
                        }
                    }
                }
                Ok(out)
            }
            _ => Err(ToolError::IdaError(
                "expected string, number, or array".to_string(),
            )),
        }
    }

    fn value_to_addresses(value: &Value) -> Result<Vec<u64>, ToolError> {
        let strings = Self::value_to_strings(value)?;
        if strings.is_empty() {
            return Err(ToolError::InvalidAddress(
                "no addresses provided".to_string(),
            ));
        }
        strings.iter().map(|s| Self::parse_address(s)).collect()
    }

    fn value_to_single_address(value: &Value) -> Result<u64, ToolError> {
        let addrs = Self::value_to_addresses(value)?;
        addrs
            .into_iter()
            .next()
            .ok_or_else(|| ToolError::InvalidAddress("empty address list".to_string()))
    }

    fn value_to_bytes(value: &Value) -> Result<Vec<u8>, ToolError> {
        match value {
            Value::String(s) => {
                let mut cleaned = String::with_capacity(s.len());
                for c in s.chars() {
                    if c.is_ascii_hexdigit() {
                        cleaned.push(c);
                    } else if c.is_ascii_whitespace()
                        || matches!(c, ',' | '_' | ':' | '-')
                        || c == 'x'
                        || c == 'X'
                    {
                        continue;
                    } else {
                        return Err(ToolError::InvalidParams(format!(
                            "invalid hex character: {c}"
                        )));
                    }
                }
                if cleaned.is_empty() {
                    return Err(ToolError::InvalidParams("no bytes provided".to_string()));
                }
                if !cleaned.len().is_multiple_of(2) {
                    return Err(ToolError::InvalidParams(
                        "hex string has odd length".to_string(),
                    ));
                }
                let mut out = Vec::with_capacity(cleaned.len() / 2);
                for i in (0..cleaned.len()).step_by(2) {
                    let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
                        .map_err(|_| ToolError::InvalidParams("invalid hex byte".to_string()))?;
                    out.push(byte);
                }
                Ok(out)
            }
            Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::Number(n) => {
                            let byte = n.as_u64().ok_or_else(|| {
                                ToolError::InvalidParams("invalid byte".to_string())
                            })?;
                            if byte > u8::MAX as u64 {
                                return Err(ToolError::InvalidParams(
                                    "byte value out of range".to_string(),
                                ));
                            }
                            out.push(byte as u8);
                        }
                        Value::String(s) => {
                            let val = Self::parse_address(s)?;
                            if val > u8::MAX as u64 {
                                return Err(ToolError::InvalidParams(
                                    "byte value out of range".to_string(),
                                ));
                            }
                            out.push(val as u8);
                        }
                        _ => {
                            return Err(ToolError::InvalidParams(
                                "bytes must be numbers or strings".to_string(),
                            ))
                        }
                    }
                }
                if out.is_empty() {
                    Err(ToolError::InvalidParams("no bytes provided".to_string()))
                } else {
                    Ok(out)
                }
            }
            Value::Number(n) => {
                let byte = n
                    .as_u64()
                    .ok_or_else(|| ToolError::InvalidParams("invalid byte".to_string()))?;
                if byte > u8::MAX as u64 {
                    return Err(ToolError::InvalidParams(
                        "byte value out of range".to_string(),
                    ));
                }
                Ok(vec![byte as u8])
            }
            _ => Err(ToolError::InvalidParams(
                "expected hex string or array of bytes".to_string(),
            )),
        }
    }
}

// Tool implementations using the #[tool_router] attribute

#[tool_router]
impl IdaMcpServer {
    #[tool(description = "Open an IDA database or raw binary for analysis")]
    #[instrument(skip(self), fields(path = %req.path))]
    async fn open_idb(
        &self,
        Parameters(req): Parameters<OpenIdbRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: open_idb");
        // Validate path (prevent directory traversal, check extension)
        if !Self::validate_path(&req.path) {
            return Ok(ToolError::InvalidPath(req.path).to_tool_result());
        }

        match self
            .worker
            .open(
                &req.path,
                req.load_debug_info.unwrap_or(false),
                req.debug_info_path.clone(),
                req.debug_info_verbose.unwrap_or(false),
                req.force.unwrap_or(false),
                req.file_type.clone(),
                true,
                Vec::new(),
            )
            .await
        {
            Ok(info) => {
                let close_token = if matches!(self.mode, ServerMode::Http) {
                    self.worker.issue_close_token()
                } else {
                    None
                };
                let mut value = match serde_json::to_value(&info) {
                    Ok(v) => v,
                    Err(_) => {
                        return Ok(CallToolResult::success(vec![Content::text(format!(
                            "{info:?}"
                        ))]))
                    }
                };
                if let Value::Object(map) = &mut value {
                    map.insert(
                        "quick_tools".to_string(),
                        json!([
                            "list_functions",
                            "resolve_function",
                            "disasm",
                            "decompile",
                            "xrefs_to",
                            "strings",
                            "close_idb"
                        ]),
                    );
                    map.insert("close_hint".to_string(), json!(self.close_hint()));
                    if let Some(token) = close_token {
                        map.insert("close_token".to_string(), json!(token));
                    }
                }
                Ok(CallToolResult::success(vec![Content::text(
                    format_response(&value),
                )]))
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Load external debug info (dSYM/DWARF)")]
    #[instrument(skip(self))]
    async fn load_debug_info(
        &self,
        Parameters(req): Parameters<LoadDebugInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: load_debug_info");
        match self
            .worker
            .load_debug_info(req.path, req.verbose.unwrap_or(false))
            .await
        {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&info),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Report auto-analysis status")]
    #[instrument(skip(self))]
    async fn analysis_status(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: analysis_status");
        match self.worker.analysis_status().await {
            Ok(status) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&status),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Close the current database and release locks")]
    #[instrument(skip(self))]
    async fn close_idb(
        &self,
        Parameters(req): Parameters<CloseIdbRequest>,
    ) -> Result<CallToolResult, McpError> {
        info!("Tool call: close_idb received");
        if matches!(self.mode, ServerMode::Http)
            && !self.worker.close_token_matches(req.token.as_deref())
        {
            info!("close_idb ignored: owner token required");
            return Ok(CallToolResult::success(vec![Content::text(
                "close_idb ignored: owner token required",
            )]));
        }
        match self.worker.close().await {
            Ok(()) => {
                self.worker.clear_close_token();
                info!("Tool call: close_idb completed successfully");
                Ok(CallToolResult::success(vec![Content::text(
                    "Database closed",
                )]))
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Discover tools by query or category")]
    #[instrument(skip(self))]
    async fn tool_catalog(
        &self,
        Parameters(req): Parameters<ToolCatalogRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: tool_catalog");
        let limit = req.limit.unwrap_or(7).min(15);

        // If category specified, list tools in that category
        if let Some(cat_str) = &req.category {
            if let Ok(cat) = cat_str.parse::<ToolCategory>() {
                let tools: Vec<_> = tool_registry::tools_by_category(cat)
                    .take(limit)
                    .map(|t| {
                        json!({
                            "name": t.name,
                            "description": t.short_desc,
                            "category": t.category.as_str(),
                        })
                    })
                    .collect();

                return Ok(CallToolResult::success(vec![Content::text(
                    format_response(&json!({
                        "category": cat.as_str(),
                        "category_description": cat.description(),
                        "tools": tools,
                        "hint": "Use tool_help(name) for full documentation and examples"
                    })),
                )]));
            }
        }

        // If query specified, search for matching tools
        if let Some(query) = &req.query {
            let results = tool_registry::search_tools(query, limit);
            let tools: Vec<_> = results
                .iter()
                .map(|(t, keywords)| {
                    json!({
                        "name": t.name,
                        "description": t.short_desc,
                        "category": t.category.as_str(),
                        "matched": keywords,
                    })
                })
                .collect();

            return Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({
                    "query": query,
                    "tools": tools,
                    "hint": "Use tool_help(name) for full documentation and examples"
                })),
            )]));
        }

        // No query or category - list all categories
        let categories: Vec<_> = ToolCategory::all()
            .iter()
            .map(|c| {
                let count = tool_registry::tools_by_category(*c).count();
                json!({
                    "category": c.as_str(),
                    "description": c.description(),
                    "tool_count": count,
                })
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            format_response(&json!({
                "categories": categories,
                "hint": "Use tool_catalog(category='...') to list tools in a category, or tool_catalog(query='...') to search. tools/list already includes all tools."
            })),
        )]))
    }

    #[tool(description = "Get full documentation for a tool")]
    #[instrument(skip(self))]
    async fn tool_help(
        &self,
        Parameters(req): Parameters<ToolHelpRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: tool_help for {}", req.name);

        if let Some(tool) = tool_registry::get_tool(&req.name) {
            let params = tool_params_schema(&req.name);
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({
                    "name": tool.name,
                    "category": tool.category.as_str(),
                    "description": tool.full_desc,
                    "parameters": params,
                    "example": tool.example,
                })),
            )]))
        } else {
            // Suggest similar tools
            let suggestions = tool_registry::search_tools(&req.name, 3);
            let suggestion_names: Vec<_> = suggestions.iter().map(|(t, _)| t.name).collect();

            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({
                    "error": format!("Tool '{}' not found", req.name),
                    "suggestions": suggestion_names,
                    "hint": "Use tool_catalog to discover available tools"
                })),
            )]))
        }
    }

    #[tool(description = "List functions (paginated, filterable)")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn list_functions(
        &self,
        Parameters(req): Parameters<ListFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_functions");
        // Clamp limit to prevent excessive responses
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let filter = req.filter.clone();

        match self
            .worker
            .list_functions(offset, limit, filter, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find function address by name")]
    #[instrument(skip(self), fields(name = %req.name))]
    async fn resolve_function(
        &self,
        Parameters(req): Parameters<ResolveFunctionRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: resolve_function");
        match self.worker.resolve_function(&req.name).await {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&info),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Resolve address to segment/function/symbol")]
    async fn addr_info(
        &self,
        Parameters(req): Parameters<AddrInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .addr_info(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&info),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find the function containing an address")]
    async fn function_at(
        &self,
        Parameters(req): Parameters<FunctionAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .function_at(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&info),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Disassemble at address(es)")]
    #[instrument(skip(self), fields(address = %req.address, count = req.count))]
    async fn disasm(
        &self,
        Parameters(req): Parameters<DisasmRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: disasm");
        // Clamp instruction count
        let count = req.count.unwrap_or(10).min(1000);
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.disasm(addrs[0], count).await {
                Ok(text) => Ok(CallToolResult::success(vec![Content::text(text)])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.disasm(addr, count).await {
                    Ok(text) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "disasm": text
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "Decompile function to C pseudocode")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn decompile(
        &self,
        Parameters(req): Parameters<DecompileRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: decompile");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.decompile(addrs[0]).await {
                Ok(code) => Ok(CallToolResult::success(vec![Content::text(code)])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.decompile(addr).await {
                    Ok(code) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "decompile": code
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "Decompile pseudocode at address or range")]
    #[instrument(skip(self), fields(address = %req.address, end_address = ?req.end_address))]
    async fn pseudocode_at(
        &self,
        Parameters(req): Parameters<PseudocodeAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: pseudocode_at");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let end_addr = if let Some(ref end_str) = req.end_address {
            match Self::parse_address(end_str) {
                Ok(a) => Some(a),
                Err(e) => return Ok(e.to_tool_result()),
            }
        } else {
            None
        };

        if addrs.len() == 1 {
            match self.worker.pseudocode_at(addrs[0], end_addr).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.pseudocode_at(addr, end_addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "pseudocode": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "List all segments")]
    #[instrument(skip(self))]
    async fn segments(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: segments");
        match self.worker.segments().await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List strings in the database")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn strings(
        &self,
        Parameters(req): Parameters<StringsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: strings");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self
            .worker
            .strings(offset, limit, req.filter, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find strings matching a query")]
    async fn find_string(
        &self,
        Parameters(req): Parameters<FindStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let exact = req.exact.unwrap_or(false);
        let case_insensitive = req.case_insensitive.unwrap_or(true);
        match self
            .worker
            .find_string(
                req.query.clone(),
                exact,
                case_insensitive,
                offset,
                limit,
                req.timeout_secs,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find xrefs to strings matching a query")]
    async fn xrefs_to_string(
        &self,
        Parameters(req): Parameters<XrefsToStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let exact = req.exact.unwrap_or(false);
        let case_insensitive = req.case_insensitive.unwrap_or(true);
        let max_xrefs = req.max_xrefs.unwrap_or(64);
        match self
            .worker
            .xrefs_to_string(
                req.query.clone(),
                exact,
                case_insensitive,
                offset,
                limit,
                max_xrefs,
                req.timeout_secs,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find all references TO an address")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn xrefs_to(
        &self,
        Parameters(req): Parameters<PaginatedAddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: xrefs_to");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(100).min(10000);

        if addrs.len() == 1 {
            match self.worker.xrefs_to(addrs[0], limit).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.xrefs_to(addr, limit).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "xrefs": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "Find all references FROM an address")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn xrefs_from(
        &self,
        Parameters(req): Parameters<PaginatedAddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: xrefs_from");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(100).min(10000);

        if addrs.len() == 1 {
            match self.worker.xrefs_from(addrs[0], limit).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.xrefs_from(addr, limit).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "xrefs": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "List imported symbols")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn imports(
        &self,
        Parameters(req): Parameters<PaginatedRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: imports");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self.worker.imports(offset, limit).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List exported symbols")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn exports(
        &self,
        Parameters(req): Parameters<PaginatedRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: exports");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self.worker.exports(offset, limit).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List entry points")]
    #[instrument(skip(self))]
    async fn entrypoints(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: entrypoints");
        match self.worker.entrypoints().await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Read raw bytes at an address")]
    #[instrument(skip(self), fields(size = req.size))]
    async fn get_bytes(
        &self,
        Parameters(req): Parameters<GetBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_bytes");
        let size = req.size.unwrap_or(256).min(0x10000);
        if let Some(addr_value) = req.address.as_ref() {
            let addrs = match Self::value_to_addresses(addr_value) {
                Ok(a) => a,
                Err(e) => return Ok(e.to_tool_result()),
            };

            if addrs.len() == 1 {
                match self.worker.get_bytes(Some(addrs[0]), None, 0, size).await {
                    Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                        format_response(&result),
                    )])),
                    Err(e) => Ok(e.to_tool_result()),
                }
            } else {
                let mut results = Vec::new();
                for addr in addrs {
                    match self.worker.get_bytes(Some(addr), None, 0, size).await {
                        Ok(result) => results.push(json!({
                            "address": format!("{:#x}", addr),
                            "bytes": result
                        })),
                        Err(e) => results.push(json!({
                            "address": format!("{:#x}", addr),
                            "error": e.to_string()
                        })),
                    }
                }
                Ok(CallToolResult::success(vec![Content::text(
                    format_response(&json!({ "results": results })),
                )]))
            }
        } else if let Some(name) = req.target_name.as_ref() {
            let offset = req.offset.unwrap_or(0);
            match self
                .worker
                .get_bytes(None, Some(name.clone()), offset, size)
                .await
            {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            Ok(ToolError::InvalidParams("address or name required".to_string()).to_tool_result())
        }
    }

    #[tool(description = "Get basic blocks of a function")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn basic_blocks(
        &self,
        Parameters(req): Parameters<PaginatedAddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: basic_blocks");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(1000).min(10000);

        if addrs.len() == 1 {
            match self.worker.basic_blocks(addrs[0], limit).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.basic_blocks(addr, limit).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "basic_blocks": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "Find all functions called by a function")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn callees(
        &self,
        Parameters(req): Parameters<PaginatedAddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: callees");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(100).min(10000);

        if addrs.len() == 1 {
            match self.worker.callees(addrs[0], limit).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.callees(addr, limit).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "callees": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "Find all callers of a function")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn callers(
        &self,
        Parameters(req): Parameters<PaginatedAddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: callers");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(100).min(10000);

        if addrs.len() == 1 {
            match self.worker.callers(addrs[0], limit).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.callers(addr, limit).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "callers": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "Get database metadata and summary")]
    #[instrument(skip(self))]
    async fn idb_meta(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: idb_meta");
        match self.worker.idb_meta().await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Batch lookup functions by name")]
    #[instrument(skip(self))]
    async fn lookup_funcs(
        &self,
        Parameters(req): Parameters<LookupFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: lookup_funcs");
        let queries = match Self::value_to_strings(&req.queries) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self.worker.lookup_funcs(queries).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List global variables")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, query = ?req.query))]
    async fn list_globals(
        &self,
        Parameters(req): Parameters<ListGlobalsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_globals");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .list_globals(req.query.clone(), offset, limit, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Analyze strings with filtering")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, query = ?req.query))]
    async fn analyze_strings(
        &self,
        Parameters(req): Parameters<AnalyzeStringsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: analyze_strings");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .analyze_strings(req.query.clone(), offset, limit, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Search for byte patterns")]
    #[instrument(skip(self))]
    async fn find_bytes(
        &self,
        Parameters(req): Parameters<FindBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: find_bytes");
        let patterns = match Self::value_to_strings(&req.patterns) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let timeout_secs = req.timeout_secs;
        let mut results = Vec::new();

        for pattern in patterns {
            let max_results = (offset + limit).min(20000);
            match self
                .worker
                .find_bytes(pattern.clone(), max_results, timeout_secs)
                .await
            {
                Ok(value) => {
                    let matches = value
                        .get("matches")
                        .and_then(|m| m.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let total = matches.len();
                    let sliced = matches
                        .into_iter()
                        .skip(offset)
                        .take(limit)
                        .collect::<Vec<_>>();
                    let next_offset = if offset + limit < total {
                        Some(offset + limit)
                    } else {
                        None
                    };
                    results.push(json!({
                        "pattern": pattern,
                        "matches": sliced,
                        "total": total,
                        "next_offset": next_offset
                    }));
                }
                Err(e) => results.push(json!({
                    "pattern": pattern,
                    "error": e.to_string()
                })),
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            format_response(&json!({ "results": results })),
        )]))
    }

    #[tool(description = "Search for text or immediate values")]
    #[instrument(skip(self))]
    async fn search(
        &self,
        Parameters(req): Parameters<SearchRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: search");
        let targets = match Self::value_to_strings(&req.targets) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let timeout_secs = req.timeout_secs;
        let kind = req.kind.as_deref().unwrap_or("auto").to_lowercase();

        let mut results = Vec::new();
        for target in targets {
            let max_results = (offset + limit).min(20000);
            let search_result = if kind == "imm" || kind == "immediate" {
                match Self::parse_address(&target) {
                    Ok(val) => self.worker.search_imm(val, max_results, timeout_secs).await,
                    Err(e) => {
                        results.push(json!({
                            "target": target,
                            "error": e.to_string()
                        }));
                        continue;
                    }
                }
            } else if kind == "text" || kind == "string" {
                self.worker
                    .search_text(target.clone(), max_results, timeout_secs)
                    .await
            } else if let Ok(val) = Self::parse_address(&target) {
                self.worker.search_imm(val, max_results, timeout_secs).await
            } else {
                self.worker
                    .search_text(target.clone(), max_results, timeout_secs)
                    .await
            };

            match search_result {
                Ok(value) => {
                    let matches = value
                        .get("matches")
                        .and_then(|m| m.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let total = matches.len();
                    let sliced = matches
                        .into_iter()
                        .skip(offset)
                        .take(limit)
                        .collect::<Vec<_>>();
                    let next_offset = if offset + limit < total {
                        Some(offset + limit)
                    } else {
                        None
                    };
                    results.push(json!({
                        "target": target,
                        "matches": sliced,
                        "total": total,
                        "next_offset": next_offset
                    }));
                }
                Err(e) => results.push(json!({
                    "target": target,
                    "error": e.to_string()
                })),
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            format_response(&json!({ "results": results })),
        )]))
    }

    #[tool(description = "Read string(s) at address(es)")]
    #[instrument(skip(self))]
    async fn get_string(
        &self,
        Parameters(req): Parameters<GetStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_string");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_len = req.max_len.unwrap_or(256).min(0x10000);

        if addrs.len() == 1 {
            match self.worker.get_string(addrs[0], max_len).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.get_string(addr, max_len).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "string": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "Read global value by name or address")]
    #[instrument(skip(self))]
    async fn get_global_value(
        &self,
        Parameters(req): Parameters<GetGlobalValueRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_global_value");
        let queries = match Self::value_to_strings(&req.query) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if queries.len() == 1 {
            match self.worker.get_global_value(queries[0].clone()).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for query in queries {
                match self.worker.get_global_value(query.clone()).await {
                    Ok(result) => results.push(json!({
                        "query": query,
                        "value": result
                    })),
                    Err(e) => results.push(json!({
                        "query": query,
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "Find CFG paths between two addresses")]
    #[instrument(skip(self))]
    async fn find_paths(
        &self,
        Parameters(req): Parameters<FindPathsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: find_paths");
        let start = match Self::value_to_single_address(&req.start) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let end = match Self::value_to_single_address(&req.end) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_paths = req.max_paths.unwrap_or(8).min(128);
        let max_depth = req.max_depth.unwrap_or(64).min(2048);

        match self
            .worker
            .find_paths(start, end, max_paths, max_depth)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Build call graph from a function")]
    #[instrument(skip(self))]
    async fn callgraph(
        &self,
        Parameters(req): Parameters<CallGraphRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: callgraph");
        let roots = match Self::value_to_addresses(&req.roots) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_depth = req.max_depth.unwrap_or(2).min(16);
        let max_nodes = req.max_nodes.unwrap_or(256).min(10000);

        if roots.len() == 1 {
            match self.worker.callgraph(roots[0], max_depth, max_nodes).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for root in roots {
                match self.worker.callgraph(root, max_depth, max_nodes).await {
                    Ok(result) => results.push(json!({
                        "root": format!("{:#x}", root),
                        "callgraph": result
                    })),
                    Err(e) => results.push(json!({
                        "root": format!("{:#x}", root),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "Build xref matrix between addresses")]
    #[instrument(skip(self))]
    async fn xref_matrix(
        &self,
        Parameters(req): Parameters<XrefMatrixRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: xref_matrix");
        let addrs = match Self::value_to_addresses(&req.addrs) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self.worker.xref_matrix(addrs).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Export functions as JSON")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn export_funcs(
        &self,
        Parameters(req): Parameters<ExportFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: export_funcs");
        if let Some(fmt) = req.format.as_deref() {
            if fmt.to_lowercase() != "json" {
                return Ok(ToolError::NotSupported(format!(
                    "format {} not supported (only json)",
                    fmt
                ))
                .to_tool_result());
            }
        }
        if let Some(addrs) = req.addrs {
            let queries = match Self::value_to_strings(&addrs) {
                Ok(v) => v,
                Err(e) => return Ok(e.to_tool_result()),
            };
            match self.worker.lookup_funcs(queries).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let limit = req.limit.unwrap_or(100).min(10000);
            let offset = req.offset.unwrap_or(0);
            match self.worker.export_funcs(offset, limit).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        }
    }

    #[tool(description = "Convert integers between bases")]
    #[instrument(skip(self))]
    async fn int_convert(
        &self,
        Parameters(req): Parameters<IntConvertRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: int_convert");
        let inputs = match Self::value_to_strings(&req.inputs) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let mut results = Vec::new();
        for input in inputs {
            match Self::parse_address(&input) {
                Ok(value) => {
                    let le = value.to_le_bytes();
                    let be = value.to_be_bytes();
                    let le_trim = trim_bytes_le(&le);
                    let be_trim = trim_bytes_be(&be);
                    results.push(json!({
                        "input": input,
                        "value": value,
                        "dec": value.to_string(),
                        "hex": format!("0x{:x}", value),
                        "bin": format!("0b{:b}", value),
                        "bytes_le": hex_encode(&le_trim),
                        "bytes_be": hex_encode(&be_trim),
                        "ascii": bytes_to_ascii(&le_trim),
                    }));
                }
                Err(e) => results.push(json!({
                    "input": input,
                    "error": e.to_string()
                })),
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            format_response(&json!({ "results": results })),
        )]))
    }

    #[tool(description = "List local types")]
    async fn local_types(
        &self,
        Parameters(req): Parameters<LocalTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let offset = req.offset.unwrap_or(0);
        let limit = req.limit.unwrap_or(100);
        match self
            .worker
            .local_types(offset, limit, req.filter.clone(), req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get xrefs to a struct field")]
    async fn xrefs_to_field(
        &self,
        Parameters(req): Parameters<XrefsToFieldRequest>,
    ) -> Result<CallToolResult, McpError> {
        let limit = req.limit.unwrap_or(1000).min(10000);
        match self
            .worker
            .xrefs_to_field(
                req.ordinal,
                req.name.clone(),
                req.member_index,
                req.member_name.clone(),
                limit,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Set comments at an address")]
    async fn set_comments(
        &self,
        Parameters(req): Parameters<SetCommentsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let repeatable = req.repeatable.unwrap_or(false);
        let offset = req.offset.unwrap_or(0);
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .set_comments(
                addr,
                req.target_name.clone(),
                offset,
                req.comment.clone(),
                repeatable,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Patch instructions with assembly text")]
    async fn patch_asm(
        &self,
        Parameters(req): Parameters<PatchAsmRequest>,
    ) -> Result<CallToolResult, McpError> {
        let offset = req.offset.unwrap_or(0);
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .patch_asm(addr, req.target_name.clone(), offset, req.line.clone())
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Declare a type in local type library")]
    async fn declare_type(
        &self,
        Parameters(req): Parameters<DeclareTypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        let relaxed = req.relaxed.unwrap_or(false);
        let replace = req.replace.unwrap_or(false);
        let multi = req.multi.unwrap_or(false);
        match self
            .worker
            .declare_type(req.decl.clone(), relaxed, replace, multi)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get stack frame info")]
    async fn stack_frame(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match Self::value_to_single_address(&req.address) {
            Ok(addr) => addr,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self.worker.stack_frame(addr).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Declare a stack variable")]
    async fn declare_stack(
        &self,
        Parameters(req): Parameters<DeclareStackRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let relaxed = req.relaxed.unwrap_or(false);
        match self
            .worker
            .declare_stack(
                addr,
                req.target_name.clone(),
                req.offset,
                req.var_name.clone(),
                req.decl.clone(),
                relaxed,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Delete a stack variable")]
    async fn delete_stack(
        &self,
        Parameters(req): Parameters<DeleteStackRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .delete_stack(
                addr,
                req.target_name.clone(),
                req.offset,
                req.var_name.clone(),
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List structs with pagination")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn structs(
        &self,
        Parameters(req): Parameters<StructsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: structs");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self
            .worker
            .structs(offset, limit, req.filter, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get struct details by name or ordinal")]
    #[instrument(skip(self), fields(ordinal = req.ordinal, name = ?req.name))]
    async fn struct_info(
        &self,
        Parameters(req): Parameters<StructInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: struct_info");
        match self.worker.struct_info(req.ordinal, req.name).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Read struct instance at an address")]
    #[instrument(skip(self), fields(address = %req.address, ordinal = req.ordinal, name = ?req.name))]
    async fn read_struct(
        &self,
        Parameters(req): Parameters<ReadStructRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_struct");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self
                .worker
                .read_struct(addrs[0], req.ordinal, req.name)
                .await
            {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    format_response(&result),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self
                    .worker
                    .read_struct(addr, req.ordinal, req.name.clone())
                    .await
                {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "struct": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({ "results": results })),
            )]))
        }
    }

    #[tool(description = "Search structs by name")]
    async fn search_structs(
        &self,
        Parameters(req): Parameters<StructsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let offset = req.offset.unwrap_or(0);
        let limit = req.limit.unwrap_or(100);
        match self
            .worker
            .structs(offset, limit, req.filter.clone(), req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find instructions by mnemonic")]
    async fn find_insns(
        &self,
        Parameters(req): Parameters<FindInsnsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let patterns = match Self::value_to_strings(&req.patterns) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        if patterns.is_empty() {
            return Ok(ToolError::InvalidParams("empty patterns".to_string()).to_tool_result());
        }
        let max_results = req.limit.unwrap_or(100);
        let case_insensitive = req.case_insensitive.unwrap_or(false);
        match self
            .worker
            .find_insns(patterns, max_results, case_insensitive, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find instructions by operand")]
    async fn find_insn_operands(
        &self,
        Parameters(req): Parameters<FindInsnOperandsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let patterns = match Self::value_to_strings(&req.patterns) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        if patterns.is_empty() {
            return Ok(ToolError::InvalidParams("empty patterns".to_string()).to_tool_result());
        }
        let max_results = req.limit.unwrap_or(100);
        let case_insensitive = req.case_insensitive.unwrap_or(false);
        match self
            .worker
            .find_insn_operands(patterns, max_results, case_insensitive, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Apply a type to an address")]
    async fn apply_types(
        &self,
        Parameters(req): Parameters<ApplyTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let relaxed = req.relaxed.unwrap_or(false);
        let delay = req.delay.unwrap_or(false);
        let strict = req.strict.unwrap_or(false);
        match self
            .worker
            .apply_types(
                addr,
                req.target_name.clone(),
                offset,
                req.stack_offset,
                req.stack_name.clone(),
                req.decl.clone(),
                req.type_name.clone(),
                relaxed,
                delay,
                strict,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Infer/guess type at an address")]
    async fn infer_types(
        &self,
        Parameters(req): Parameters<InferTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .infer_types(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Rename symbols")]
    async fn rename(
        &self,
        Parameters(req): Parameters<RenameRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let flags = req.flags.unwrap_or(0);
        match self
            .worker
            .rename(addr, req.current_name.clone(), req.name.clone(), flags)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Patch bytes at an address")]
    async fn patch(
        &self,
        Parameters(req): Parameters<PatchRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let bytes = match Self::value_to_bytes(&req.bytes) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self
            .worker
            .patch_bytes(addr, req.target_name.clone(), offset, bytes)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Read integer values from memory addresses")]
    #[instrument(skip(self))]
    async fn get_int(
        &self,
        Parameters(req): Parameters<GetIntRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_int");
        // queries can be a single {addr, ty} or an array of them
        let items = match &req.queries {
            Value::Array(arr) => arr.clone(),
            Value::Object(_) => vec![req.queries.clone()],
            _ => return Ok(ToolError::InvalidParams("queries must be object or array".to_string()).to_tool_result()),
        };

        let mut results = Vec::new();
        for item in &items {
            let addr_val = item.get("addr").or_else(|| item.get("address"));
            let ty_val = item.get("ty").or_else(|| item.get("type"));

            let addr_str = match addr_val.and_then(|v| v.as_str()) {
                Some(s) => s,
                None => match addr_val.and_then(|v| v.as_u64()) {
                    Some(n) => {
                        results.push(match self.worker.get_int(n, ty_val.and_then(|v| v.as_str()).unwrap_or("u8").to_string()).await {
                            Ok(r) => r,
                            Err(e) => json!({"error": e.to_string()}),
                        });
                        continue;
                    }
                    None => {
                        results.push(json!({"error": "missing 'addr' field"}));
                        continue;
                    }
                },
            };
            let ty = ty_val.and_then(|v| v.as_str()).unwrap_or("u8");

            let addr = match Self::parse_address(addr_str) {
                Ok(a) => a,
                Err(e) => {
                    results.push(json!({"addr": addr_str, "error": e.to_string()}));
                    continue;
                }
            };

            match self.worker.get_int(addr, ty.to_string()).await {
                Ok(r) => results.push(r),
                Err(e) => results.push(json!({"addr": addr_str, "error": e.to_string()})),
            }
        }

        if results.len() == 1 {
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&results[0]),
            )]))
        } else {
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({"results": results})),
            )]))
        }
    }

    #[tool(description = "Write integer values to memory addresses")]
    #[instrument(skip(self))]
    async fn put_int(
        &self,
        Parameters(req): Parameters<PutIntRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: put_int");
        let items = match &req.items {
            Value::Array(arr) => arr.clone(),
            Value::Object(_) => vec![req.items.clone()],
            _ => return Ok(ToolError::InvalidParams("items must be object or array".to_string()).to_tool_result()),
        };

        let mut results = Vec::new();
        for item in &items {
            let addr_val = item.get("addr").or_else(|| item.get("address"));
            let ty_val = item.get("ty").or_else(|| item.get("type"));
            let value_val = item.get("value");

            let addr_str = match addr_val {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Number(n)) => n.to_string(),
                _ => {
                    results.push(json!({"error": "missing 'addr' field"}));
                    continue;
                }
            };
            let ty = match ty_val.and_then(|v| v.as_str()) {
                Some(s) => s,
                None => {
                    results.push(json!({"addr": addr_str, "error": "missing 'ty' field"}));
                    continue;
                }
            };
            let value_str = match value_val {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Number(n)) => n.to_string(),
                _ => {
                    results.push(json!({"addr": addr_str, "error": "missing 'value' field"}));
                    continue;
                }
            };

            let addr = match Self::parse_address(&addr_str) {
                Ok(a) => a,
                Err(e) => {
                    results.push(json!({"addr": addr_str, "error": e.to_string()}));
                    continue;
                }
            };

            match self.worker.put_int(addr, ty.to_string(), value_str).await {
                Ok(r) => results.push(r),
                Err(e) => results.push(json!({"addr": addr_str, "error": e.to_string()})),
            }
        }

        if results.len() == 1 {
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&results[0]),
            )]))
        } else {
            Ok(CallToolResult::success(vec![Content::text(
                format_response(&json!({"results": results})),
            )]))
        }
    }

    #[tool(description = "Search for patterns in the binary (strings, immediate values, or references)")]
    #[instrument(skip(self))]
    async fn find(
        &self,
        Parameters(req): Parameters<FindRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: find");
        let targets = match Self::value_to_strings(&req.targets) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(1000).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self
            .worker
            .find(req.r#type.clone(), targets, limit, offset, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Search strings with case-insensitive regex patterns")]
    #[instrument(skip(self))]
    async fn find_regex(
        &self,
        Parameters(req): Parameters<FindRegexRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: find_regex");
        let limit = req.limit.unwrap_or(30).min(500);
        let offset = req.offset.unwrap_or(0);

        match self
            .worker
            .find_regex(req.pattern.clone(), limit, offset, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Execute Python code in IDA context (deprecated, use run_script)")]
    #[instrument(skip(self), fields(current_ea = ?req.current_ea))]
    async fn py_eval(
        &self,
        Parameters(req): Parameters<PyEvalRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: py_eval");
        let current_ea = if let Some(ref ea_str) = req.current_ea {
            match Self::parse_address(ea_str) {
                Ok(a) => Some(a),
                Err(e) => return Ok(e.to_tool_result()),
            }
        } else {
            None
        };

        match self.worker.py_eval(req.code.clone(), current_ea).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Execute Python code via IDAPython")]
    #[instrument(skip(self))]
    async fn run_script(
        &self,
        Parameters(req): Parameters<RunScriptRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: run_script");

        let code = match (req.code, req.file) {
            (Some(code), None) => code,
            (None, Some(file_path)) => {
                if !Self::validate_path(&file_path) {
                    return Ok(ToolError::InvalidPath(
                        format!("Invalid script path: {}", file_path),
                    ).to_tool_result());
                }
                match std::fs::read_to_string(&file_path) {
                    Ok(content) => content,
                    Err(e) => return Ok(ToolError::InvalidPath(
                        format!("Failed to read {}: {}", file_path, e),
                    ).to_tool_result()),
                }
            }
            (Some(_), Some(_)) => {
                return Ok(ToolError::InvalidParams(
                    "Provide either 'code' or 'file', not both".to_string(),
                ).to_tool_result());
            }
            (None, None) => {
                return Ok(ToolError::InvalidParams(
                    "Provide either 'code' or 'file'".to_string(),
                ).to_tool_result());
            }
        };

        match self.worker.run_script(&code, req.timeout_secs).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                format_response(&result),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn trim_bytes_le(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    while out.len() > 1 && out.last() == Some(&0) {
        out.pop();
    }
    out
}

fn trim_bytes_be(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0usize;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    bytes[start..].to_vec()
}

fn bytes_to_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| {
            let c = *b as char;
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '.'
            }
        })
        .collect()
}

fn tool_params_schema(name: &str) -> Option<Value> {
    fn schema<T: JsonSchema>() -> Value {
        serde_json::to_value(schema_for!(T)).unwrap_or_else(|_| json!({}))
    }

    match name {
        // Core
        "open_idb" => Some(schema::<OpenIdbRequest>()),
        "close_idb" => Some(schema::<CloseIdbRequest>()),
        "load_debug_info" => Some(schema::<LoadDebugInfoRequest>()),
        "analysis_status" => Some(schema::<EmptyParams>()),
        "tool_catalog" => Some(schema::<ToolCatalogRequest>()),
        "tool_help" => Some(schema::<ToolHelpRequest>()),
        "idb_meta" => Some(schema::<EmptyParams>()),

        // Functions
        "list_functions" => Some(schema::<ListFunctionsRequest>()),
        "resolve_function" => Some(schema::<ResolveFunctionRequest>()),
        "addr_info" => Some(schema::<AddrInfoRequest>()),
        "function_at" => Some(schema::<FunctionAtRequest>()),
        "lookup_funcs" => Some(schema::<LookupFuncsRequest>()),

        // Disassembly / Decompile
        "disasm" => Some(schema::<DisasmRequest>()),
        "decompile" => Some(schema::<DecompileRequest>()),
        "pseudocode_at" => Some(schema::<PseudocodeAtRequest>()),

        // Xrefs / Control flow
        "xrefs_to" | "xrefs_from" => Some(schema::<PaginatedAddressRequest>()),
        "xref_matrix" => Some(schema::<XrefMatrixRequest>()),
        "basic_blocks" | "callers" | "callees" => Some(schema::<PaginatedAddressRequest>()),
        "find_paths" => Some(schema::<FindPathsRequest>()),
        "callgraph" => Some(schema::<CallGraphRequest>()),

        // Memory / Search / Metadata
        "get_bytes" => Some(schema::<GetBytesRequest>()),
        "get_string" => Some(schema::<GetStringRequest>()),
        "get_global_value" => Some(schema::<GetGlobalValueRequest>()),
        "strings" => Some(schema::<StringsRequest>()),
        "find_string" => Some(schema::<FindStringRequest>()),
        "analyze_strings" => Some(schema::<AnalyzeStringsRequest>()),
        "xrefs_to_string" => Some(schema::<XrefsToStringRequest>()),
        "find_bytes" => Some(schema::<FindBytesRequest>()),
        "search" => Some(schema::<SearchRequest>()),
        "find_insns" => Some(schema::<FindInsnsRequest>()),
        "find_insn_operands" => Some(schema::<FindInsnOperandsRequest>()),
        "segments" => Some(schema::<EmptyParams>()),
        "imports" | "exports" => Some(schema::<PaginatedRequest>()),
        "export_funcs" => Some(schema::<ExportFuncsRequest>()),
        "entrypoints" => Some(schema::<EmptyParams>()),
        "list_globals" => Some(schema::<ListGlobalsRequest>()),
        "int_convert" => Some(schema::<IntConvertRequest>()),
        "get_int" => Some(schema::<GetIntRequest>()),
        "put_int" => Some(schema::<PutIntRequest>()),
        "find" => Some(schema::<FindRequest>()),
        "find_regex" => Some(schema::<FindRegexRequest>()),

        // Editing
        "set_comments" => Some(schema::<SetCommentsRequest>()),
        "rename" => Some(schema::<RenameRequest>()),
        "patch" => Some(schema::<PatchRequest>()),
        "patch_asm" => Some(schema::<PatchAsmRequest>()),

        // Types
        "structs" => Some(schema::<StructsRequest>()),
        "struct_info" => Some(schema::<StructInfoRequest>()),
        "read_struct" => Some(schema::<ReadStructRequest>()),
        "search_structs" => Some(schema::<StructsRequest>()),
        "local_types" => Some(schema::<LocalTypesRequest>()),
        "xrefs_to_field" => Some(schema::<XrefsToFieldRequest>()),
        "stack_frame" => Some(schema::<AddressRequest>()),
        "declare_type" => Some(schema::<DeclareTypeRequest>()),
        "apply_types" => Some(schema::<ApplyTypesRequest>()),
        "infer_types" => Some(schema::<InferTypesRequest>()),
        "declare_stack" => Some(schema::<DeclareStackRequest>()),
        "delete_stack" => Some(schema::<DeleteStackRequest>()),

        // Scripting
        "run_script" => Some(schema::<RunScriptRequest>()),
        "py_eval" => Some(schema::<PyEvalRequest>()),

        _ => None,
    }
}

#[tool_handler(router = self.tool_mux)]
impl ServerHandler for IdaMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(self.instructions()),
            ..Default::default()
        }
    }
}

use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};

/// Wrapper that sanitizes tool schemas by removing `$schema` fields.
///
/// Some MCP clients (like Claude Desktop) choke on the JSON Schema `$schema` field.
/// This wrapper intercepts `list_tools` to remove these fields while delegating
/// all other methods to the inner server.
pub struct SanitizedIdaServer<S>(pub S);

impl<S> std::ops::Deref for SanitizedIdaServer<S> {
    type Target = S;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Strips `$schema` keys and per-parameter descriptions from tool input
/// schemas. Parameter descriptions are only needed for `tool_help` (which
/// generates schemas on-the-fly); stripping them from `tools/list` saves
/// ~300-600 bytes per tool.
fn sanitize_tool_schemas(result: &mut ListToolsResult) {
    for tool in &mut result.tools {
        let schema_arc = &mut tool.input_schema;
        let mut map = (**schema_arc).clone();
        map.remove("$schema");
        strip_property_descriptions(&mut map);
        *schema_arc = std::sync::Arc::new(map);
    }
}

/// Recursively strip `description` from property sub-schemas.
fn strip_property_descriptions(map: &mut serde_json::Map<String, Value>) {
    if let Some(Value::Object(props)) = map.get_mut("properties") {
        for (_key, val) in props.iter_mut() {
            if let Value::Object(prop_map) = val {
                prop_map.remove("description");
            }
        }
    }
}

/// Default maximum response size in characters (~12,500 tokens).
const DEFAULT_MAX_RESPONSE_CHARS: usize = 50_000;

/// Get the configured max response chars from env or default.
fn max_response_chars() -> usize {
    std::env::var("IDA_MCP_MAX_RESPONSE_CHARS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_RESPONSE_CHARS)
}

/// Truncate oversized tool responses to prevent unbounded context consumption.
fn truncate_response(result: &mut CallToolResult, max_chars: usize) {
    use rmcp::model::RawContent;
    if max_chars == 0 {
        return;
    }
    for content in &mut result.content {
        if let RawContent::Text(ref mut text_content) = content.raw {
            let len = text_content.text.len();
            if len > max_chars {
                text_content.text.truncate(max_chars);
                text_content.text.push_str(&format!(
                    "\n[TRUNCATED: {} chars total. Use offset/limit for pagination.]",
                    len
                ));
            }
        }
    }
}

impl<S: ServerHandler + Send + Sync> ServerHandler for SanitizedIdaServer<S> {
    async fn initialize(
        &self,
        params: InitializeRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        self.0.initialize(params, ctx).await
    }

    async fn list_tools(
        &self,
        params: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut result = self.0.list_tools(params, ctx).await?;
        sanitize_tool_schemas(&mut result);
        Ok(result)
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let mut result = self.0.call_tool(params, ctx).await?;
        truncate_response(&mut result, max_response_chars());
        Ok(result)
    }

    fn get_info(&self) -> ServerInfo {
        self.0.get_info()
    }
}
