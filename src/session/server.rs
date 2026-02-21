//! MCP server for session management.

use super::manager::SessionManager;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, InitializeRequestParams, InitializeResult,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};
use serde_json::{json, Map, Value};
use std::borrow::Cow;
use std::sync::Arc;
use tracing::debug;

/// Session tool names.
const SESSION_OPEN: &str = "session_open";
const SESSION_LIST: &str = "session_list";
const SESSION_SWITCH: &str = "session_switch";
const SESSION_CLOSE: &str = "session_close";
const SESSION_INFO: &str = "session_info";

/// MCP server that manages multiple IDA sessions.
#[derive(Clone)]
pub struct SessionManagerServer {
    manager: Arc<SessionManager>,
}

impl SessionManagerServer {
    /// Create a new session manager server.
    pub fn new(manager: Arc<SessionManager>) -> Self {
        Self { manager }
    }

    /// Get server instructions.
    fn instructions(&self) -> String {
        "IDA Pro multi-session manager for analyzing multiple binaries simultaneously.\n\n\
         Workflow:\n\
         1. session_open: Open a binary in a new session\n\
         2. Use IDA tools (list_functions, decompile, etc.) - automatically forwarded to active session\n\
         3. session_switch: Switch between sessions\n\
         4. session_close: Close a session when done\n\n\
         Session Tools:\n\
         - session_open: Open a binary in a new session\n\
         - session_list: List all sessions\n\
         - session_switch: Switch the active session\n\
         - session_close: Close a session\n\
         - session_info: Get info about a session\n\n\
         All IDA tools are forwarded to the active session."
            .to_string()
    }

    /// Check if a tool name is a session management tool.
    fn is_session_tool(name: &str) -> bool {
        matches!(
            name,
            SESSION_OPEN | SESSION_LIST | SESSION_SWITCH | SESSION_CLOSE | SESSION_INFO
        )
    }

    /// Create a Tool with the given parameters.
    fn make_tool(name: &'static str, description: &'static str, schema: Value) -> Tool {
        Tool {
            name: Cow::Borrowed(name),
            description: Some(Cow::Borrowed(description)),
            input_schema: Arc::new(serde_json::from_value(schema).unwrap_or_default()),
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
            output_schema: None,
            title: None,
        }
    }

    /// Get session management tools.
    fn session_tools() -> Vec<Tool> {
        vec![
            Self::make_tool(
                SESSION_OPEN,
                "Open a binary file in a new IDA session. Returns session info including ID. \
                 The new session becomes active automatically if no other session is active.",
                json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the binary file to analyze"
                        }
                    },
                    "required": ["path"]
                }),
            ),
            Self::make_tool(
                SESSION_LIST,
                "List all IDA sessions with their status and binary path. \
                 Shows which session is currently active.",
                json!({
                    "type": "object",
                    "properties": {}
                }),
            ),
            Self::make_tool(
                SESSION_SWITCH,
                "Switch the active session to a different session by ID. \
                 All subsequent IDA tool calls will be forwarded to this session.",
                json!({
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "description": "ID of the session to make active"
                        }
                    },
                    "required": ["session_id"]
                }),
            ),
            Self::make_tool(
                SESSION_CLOSE,
                "Close an IDA session. If no session_id is provided, closes the active session. \
                 The IDA database is saved before closing.",
                json!({
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "description": "ID of the session to close (optional, defaults to active session)"
                        }
                    }
                }),
            ),
            Self::make_tool(
                SESSION_INFO,
                "Get detailed information about a session. \
                 If no session_id is provided, returns info about the active session.",
                json!({
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "description": "ID of the session to get info for (optional, defaults to active session)"
                        }
                    }
                }),
            ),
        ]
    }

    /// Handle a session management tool call.
    async fn handle_session_tool(
        &self,
        name: &str,
        arguments: Option<Map<String, Value>>,
    ) -> Result<CallToolResult, McpError> {
        let args = arguments
            .map(Value::Object)
            .unwrap_or(Value::Object(Map::new()));

        match name {
            SESSION_OPEN => self.handle_session_open(&args).await,
            SESSION_LIST => self.handle_session_list().await,
            SESSION_SWITCH => self.handle_session_switch(&args).await,
            SESSION_CLOSE => self.handle_session_close(&args).await,
            SESSION_INFO => self.handle_session_info(&args).await,
            _ => Err(McpError::invalid_params(
                format!("Unknown session tool: {}", name),
                None,
            )),
        }
    }

    async fn handle_session_open(&self, args: &Value) -> Result<CallToolResult, McpError> {
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::invalid_params("Missing required parameter: path", None))?;

        debug!(path = %path, "Opening new session");

        match self.manager.open_session(path).await {
            Ok(info) => {
                let mut response = serde_json::to_value(&info).unwrap_or(Value::Null);
                if let Value::Object(ref mut map) = response {
                    map.insert("message".to_string(), json!("Session opened successfully"));
                    map.insert("active".to_string(), json!(true));
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string(&response).unwrap_or_else(|_| format!("{:?}", info)),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to open session: {}",
                e
            ))])),
        }
    }

    async fn handle_session_list(&self) -> Result<CallToolResult, McpError> {
        let sessions = self.manager.list_sessions().await;
        let active_id = self.manager.get_active_session_id().await;
        let stats = self.manager.stats().await;

        let response = json!({
            "sessions": sessions.iter().map(|s| {
                let mut obj = serde_json::to_value(s).unwrap_or(Value::Null);
                if let Value::Object(ref mut map) = obj {
                    map.insert("active".to_string(), json!(active_id.as_ref() == Some(&s.id)));
                }
                obj
            }).collect::<Vec<_>>(),
            "stats": stats
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string(&response).unwrap_or_else(|_| "[]".to_string()),
        )]))
    }

    async fn handle_session_switch(&self, args: &Value) -> Result<CallToolResult, McpError> {
        let session_id = args
            .get("session_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                McpError::invalid_params("Missing required parameter: session_id", None)
            })?;

        match self.manager.switch_session(session_id).await {
            Ok(info) => {
                let mut response = serde_json::to_value(&info).unwrap_or(Value::Null);
                if let Value::Object(ref mut map) = response {
                    map.insert(
                        "message".to_string(),
                        json!("Switched to session successfully"),
                    );
                    map.insert("active".to_string(), json!(true));
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string(&response).unwrap_or_else(|_| format!("{:?}", info)),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to switch session: {}",
                e
            ))])),
        }
    }

    async fn handle_session_close(&self, args: &Value) -> Result<CallToolResult, McpError> {
        let session_id = if let Some(id) = args.get("session_id").and_then(|v| v.as_str()) {
            id.to_string()
        } else {
            self.manager
                .get_active_session_id()
                .await
                .ok_or_else(|| McpError::invalid_params("No active session to close", None))?
        };

        match self.manager.close_session(&session_id).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(
                json!({
                    "message": "Session closed successfully",
                    "session_id": session_id
                })
                .to_string(),
            )])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to close session: {}",
                e
            ))])),
        }
    }

    async fn handle_session_info(&self, args: &Value) -> Result<CallToolResult, McpError> {
        let info = if let Some(id) = args.get("session_id").and_then(|v| v.as_str()) {
            self.manager.get_session_info(id).await
        } else {
            self.manager.get_active_session_info().await
        };

        match info {
            Ok(info) => {
                let active_id = self.manager.get_active_session_id().await;
                let mut response = serde_json::to_value(&info).unwrap_or(Value::Null);
                if let Value::Object(ref mut map) = response {
                    map.insert("active".to_string(), json!(active_id.as_ref() == Some(&info.id)));
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string(&response).unwrap_or_else(|_| format!("{:?}", info)),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to get session info: {}",
                e
            ))])),
        }
    }

    /// Forward a tool call to the active session.
    async fn forward_tool_call(
        &self,
        name: &str,
        arguments: Option<Map<String, Value>>,
    ) -> Result<CallToolResult, McpError> {
        let args = arguments
            .map(Value::Object)
            .unwrap_or(Value::Object(Map::new()));

        match self.manager.forward_tool_call(name, args).await {
            Ok(result) => {
                // Convert the result back to CallToolResult
                // The result should have a "content" field with the tool output
                if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
                    let contents: Vec<Content> = content
                        .iter()
                        .filter_map(|c| {
                            c.get("text")
                                .and_then(|t| t.as_str())
                                .map(|text| Content::text(text.to_string()))
                        })
                        .collect();
                    if result.get("isError").and_then(|e| e.as_bool()).unwrap_or(false) {
                        Ok(CallToolResult::error(contents))
                    } else {
                        Ok(CallToolResult::success(contents))
                    }
                } else {
                    // Fallback: just serialize the result
                    Ok(CallToolResult::success(vec![Content::text(
                        serde_json::to_string(&result)
                            .unwrap_or_else(|_| format!("{:?}", result)),
                    )]))
                }
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Tool call failed: {}",
                e
            ))])),
        }
    }
}

impl ServerHandler for SessionManagerServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(self.instructions()),
            ..Default::default()
        }
    }

    async fn list_tools(
        &self,
        _params: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools = Self::session_tools();

        // Add cached IDA tools
        let ida_tools = self.manager.get_cached_ida_tools().await;
        tools.extend(ida_tools);

        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let name = &params.name;
        let arguments = params.arguments;

        if Self::is_session_tool(name) {
            self.handle_session_tool(name, arguments).await
        } else {
            // Forward to active session
            self.forward_tool_call(name, arguments).await
        }
    }
}

/// Wrapper that sanitizes tool schemas (same as in server/mod.rs).
pub struct SanitizedSessionServer<S>(pub S);

impl<S> std::ops::Deref for SanitizedSessionServer<S> {
    type Target = S;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn sanitize_tool_schemas(result: &mut ListToolsResult) {
    for tool in &mut result.tools {
        let schema_arc = &mut tool.input_schema;
        if let Some(map) = Arc::get_mut(schema_arc) {
            map.remove("$schema");
        } else {
            let mut map = (**schema_arc).clone();
            map.remove("$schema");
            *schema_arc = Arc::new(map);
        }
    }
}

impl<S: ServerHandler + Send + Sync> ServerHandler for SanitizedSessionServer<S> {
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
        self.0.call_tool(params, ctx).await
    }

    fn get_info(&self) -> ServerInfo {
        self.0.get_info()
    }
}
