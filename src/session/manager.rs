//! Session manager for spawning and managing multiple IDA sessions.

use super::port_allocator::PortAllocator;
use super::types::{Session, SessionInfo, SessionStatus};
use chrono::Utc;
use reqwest::Client;
use rmcp::model::Tool;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Timeout for waiting for a session to become ready.
const SESSION_READY_TIMEOUT_SECS: u64 = 120;
/// Interval between health checks when waiting for session ready.
const HEALTH_CHECK_INTERVAL_MS: u64 = 500;
/// Timeout for HTTP requests to child sessions.
const HTTP_REQUEST_TIMEOUT_SECS: u64 = 300;
/// Timeout for graceful shutdown of child sessions.
const SHUTDOWN_TIMEOUT_SECS: u64 = 10;

/// Error type for session management operations.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("No active session")]
    NoActiveSession,
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    #[error("Session not ready: {0}")]
    SessionNotReady(String),
    #[error("Failed to spawn session: {0}")]
    SpawnFailed(String),
    #[error("No ports available")]
    NoPortsAvailable,
    #[error("HTTP request failed: {0}")]
    HttpError(String),
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    #[error("Session startup timeout")]
    StartupTimeout,
    #[error("Tool call failed: {0}")]
    ToolCallFailed(String),
}

impl From<reqwest::Error> for SessionError {
    fn from(e: reqwest::Error) -> Self {
        SessionError::HttpError(e.to_string())
    }
}

/// Manager for multiple IDA analysis sessions.
pub struct SessionManager {
    /// Map of session ID to session.
    sessions: RwLock<HashMap<String, Session>>,
    /// Currently active session ID.
    active_session_id: RwLock<Option<String>>,
    /// Port allocator for child HTTP servers.
    port_allocator: PortAllocator,
    /// Cached IDA tools from child sessions.
    cached_ida_tools: RwLock<Vec<Tool>>,
    /// HTTP client for forwarding requests.
    http_client: Client,
    /// Path to the ida-mcp executable.
    ida_mcp_path: String,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(port_range_start: u16, port_range_end: u16) -> Self {
        // Find the ida-mcp executable path
        let ida_mcp_path = env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "ida-mcp".to_string());

        Self {
            sessions: RwLock::new(HashMap::new()),
            active_session_id: RwLock::new(None),
            port_allocator: PortAllocator::new(port_range_start, port_range_end),
            cached_ida_tools: RwLock::new(Vec::new()),
            http_client: Client::builder()
                .timeout(Duration::from_secs(HTTP_REQUEST_TIMEOUT_SECS))
                .build()
                .expect("Failed to create HTTP client"),
            ida_mcp_path,
        }
    }

    /// Open a new session for the given binary path.
    pub async fn open_session(&self, binary_path: &str) -> Result<SessionInfo, SessionError> {
        // Validate path
        let path = std::path::Path::new(binary_path);
        if !path.exists() {
            return Err(SessionError::InvalidPath(format!(
                "File does not exist: {}",
                binary_path
            )));
        }
        if !path.is_file() {
            return Err(SessionError::InvalidPath(format!(
                "Not a file: {}",
                binary_path
            )));
        }

        // Allocate a port
        let port = self
            .port_allocator
            .allocate()
            .ok_or(SessionError::NoPortsAvailable)?;

        // Generate session ID
        let session_id = Uuid::new_v4().to_string();

        info!(
            session_id = %session_id,
            binary_path = %binary_path,
            port = port,
            "Opening new session"
        );

        // Spawn child process
        let child = match Command::new(&self.ida_mcp_path)
            .args([
                "serve-http",
                "--bind",
                &format!("127.0.0.1:{}", port),
                "--allow-origin",
                "*", // Allow all origins for internal communication
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                self.port_allocator.release(port);
                return Err(SessionError::SpawnFailed(e.to_string()));
            }
        };

        let pid = child.id();

        let info = SessionInfo {
            id: session_id.clone(),
            binary_path: binary_path.to_string(),
            port,
            status: SessionStatus::Starting,
            pid,
            created_at: Utc::now(),
            error: None,
        };

        let session = Session::new(info.clone(), child);

        // Add session to map
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session);
        }

        // Wait for the session to become ready and open the database
        match self.wait_for_ready_and_open(&session_id, binary_path).await {
            Ok(updated_info) => {
                // Set as active session if there's no active session
                let mut active = self.active_session_id.write().await;
                if active.is_none() {
                    *active = Some(session_id.clone());
                }

                // Cache IDA tools from this session if not already cached
                self.cache_ida_tools_if_needed(&session_id).await;

                Ok(updated_info)
            }
            Err(e) => {
                // Clean up on failure
                error!(session_id = %session_id, error = %e, "Session startup failed");
                let _ = self.close_session(&session_id).await;
                Err(e)
            }
        }
    }

    /// Wait for a session to become ready and open the database.
    async fn wait_for_ready_and_open(
        &self,
        session_id: &str,
        binary_path: &str,
    ) -> Result<SessionInfo, SessionError> {
        let port = {
            let sessions = self.sessions.read().await;
            let session = sessions
                .get(session_id)
                .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;
            session.port()
        };

        let base_url = format!("http://127.0.0.1:{}", port);

        // Wait for HTTP server to be ready
        let ready = timeout(
            Duration::from_secs(SESSION_READY_TIMEOUT_SECS),
            self.wait_for_http_ready(&base_url),
        )
        .await;

        match ready {
            Ok(Ok(())) => {
                debug!(session_id = %session_id, "HTTP server is ready");
            }
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(_) => {
                return Err(SessionError::StartupTimeout);
            }
        }

        // Initialize MCP session
        let session_url = format!("{}/mcp", base_url);
        let init_result = self.initialize_mcp_session(&session_url).await?;
        debug!(session_id = %session_id, "MCP session initialized: {:?}", init_result);

        // Open the database via tool call
        let open_result = self
            .call_tool_on_session(session_id, "open_idb", json!({"path": binary_path}))
            .await?;

        // Extract close_token if present
        if let Some(content) = open_result.get("content").and_then(|c| c.as_array()) {
            for item in content {
                if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                    if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                        if let Some(token) = parsed.get("close_token").and_then(|t| t.as_str()) {
                            let mut sessions = self.sessions.write().await;
                            if let Some(session) = sessions.get_mut(session_id) {
                                session.set_close_token(token.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Update session status to Ready
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.set_status(SessionStatus::Ready);
            Ok(session.info.clone())
        } else {
            Err(SessionError::SessionNotFound(session_id.to_string()))
        }
    }

    /// Wait for the HTTP server to respond to requests.
    async fn wait_for_http_ready(&self, base_url: &str) -> Result<(), SessionError> {
        let url = format!("{}/mcp", base_url);
        loop {
            match self.http_client.get(&url).send().await {
                Ok(resp) => {
                    // Any response (even 4xx) means the server is up
                    debug!("HTTP server responded with status: {}", resp.status());
                    return Ok(());
                }
                Err(e) => {
                    if e.is_connect() {
                        // Server not ready yet, keep trying
                        sleep(Duration::from_millis(HEALTH_CHECK_INTERVAL_MS)).await;
                    } else {
                        // Unexpected error
                        return Err(SessionError::HttpError(e.to_string()));
                    }
                }
            }
        }
    }

    /// Initialize an MCP session with a child server.
    async fn initialize_mcp_session(&self, session_url: &str) -> Result<Value, SessionError> {
        let init_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "ida-mcp-session-manager",
                    "version": "0.1.0"
                }
            }
        });

        let response = self
            .http_client
            .post(session_url)
            .header("Content-Type", "application/json")
            .json(&init_request)
            .send()
            .await?;

        let result: Value = response.json().await?;
        Ok(result)
    }

    /// Cache IDA tools from a session if not already cached.
    async fn cache_ida_tools_if_needed(&self, session_id: &str) {
        let cached = self.cached_ida_tools.read().await;
        if !cached.is_empty() {
            return;
        }
        drop(cached);

        if let Ok(tools) = self.list_tools_from_session(session_id).await {
            let mut cached = self.cached_ida_tools.write().await;
            *cached = tools;
            info!("Cached {} IDA tools from session", cached.len());
        }
    }

    /// List tools from a specific session.
    async fn list_tools_from_session(&self, session_id: &str) -> Result<Vec<Tool>, SessionError> {
        let port = {
            let sessions = self.sessions.read().await;
            let session = sessions
                .get(session_id)
                .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;
            session.port()
        };

        let url = format!("http://127.0.0.1:{}/mcp", port);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        });

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let result: Value = response.json().await?;

        // Parse tools from response
        let tools = result
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| serde_json::from_value::<Tool>(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();

        Ok(tools)
    }

    /// Get cached IDA tools.
    pub async fn get_cached_ida_tools(&self) -> Vec<Tool> {
        self.cached_ida_tools.read().await.clone()
    }

    /// Reap any child sessions whose process has exited, releasing their ports.
    async fn reap_dead_sessions(&self) {
        let dead_ids: Vec<String> = {
            let mut sessions = self.sessions.write().await;
            let dead_ids: Vec<String> = sessions
                .iter_mut()
                .filter_map(|(id, s)| if !s.is_running() { Some(id.clone()) } else { None })
                .collect();

            for id in &dead_ids {
                if let Some(mut session) = sessions.remove(id) {
                    warn!(session_id = %id, port = session.port(), "Reaping dead session");
                    // Wait to collect exit status and avoid zombie process
                    let _ = session.process.wait();
                    self.port_allocator.release(session.port());
                }
            }
            dead_ids
        }; // sessions lock dropped here before acquiring active_session_id lock

        if !dead_ids.is_empty() {
            let mut active = self.active_session_id.write().await;
            if let Some(ref active_id) = *active {
                if dead_ids.contains(active_id) {
                    let sessions = self.sessions.read().await;
                    *active = sessions
                        .iter()
                        .find(|(_, s)| s.status() == SessionStatus::Ready)
                        .map(|(id, _)| id.clone());
                }
            }
        }
    }

    /// Call a tool on a specific session.
    async fn call_tool_on_session(
        &self,
        session_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> Result<Value, SessionError> {
        let port = {
            let mut sessions = self.sessions.write().await;
            let session = sessions
                .get_mut(session_id)
                .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;
            // Check if the child process is still alive
            if !session.is_running() {
                let port = session.port();
                if let Some(mut removed) = sessions.remove(session_id) {
                    // Wait to collect exit status and avoid zombie process
                    let _ = removed.process.wait();
                }
                self.port_allocator.release(port);
                return Err(SessionError::SessionNotReady(format!(
                    "session {} child process has exited",
                    session_id
                )));
            }
            if session.status() != SessionStatus::Ready
                && session.status() != SessionStatus::Starting
            {
                return Err(SessionError::SessionNotReady(session_id.to_string()));
            }
            session.port()
        };

        let url = format!("http://127.0.0.1:{}/mcp", port);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        });

        debug!(session_id = %session_id, tool = %tool_name, "Forwarding tool call");

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let result: Value = response.json().await?;

        // Check for error
        if let Some(error) = result.get("error") {
            return Err(SessionError::ToolCallFailed(error.to_string()));
        }

        Ok(result.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Forward a tool call to the active session.
    pub async fn forward_tool_call(
        &self,
        tool_name: &str,
        arguments: Value,
    ) -> Result<Value, SessionError> {
        let session_id = {
            let active = self.active_session_id.read().await;
            active
                .clone()
                .ok_or(SessionError::NoActiveSession)?
        };

        self.call_tool_on_session(&session_id, tool_name, arguments)
            .await
    }

    /// Close a session.
    pub async fn close_session(&self, session_id: &str) -> Result<(), SessionError> {
        let (port, close_token, mut process) = {
            let mut sessions = self.sessions.write().await;
            let session = sessions
                .remove(session_id)
                .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;
            (session.port(), session.close_token.clone(), session.process)
        };

        info!(session_id = %session_id, port = port, "Closing session");

        // Try to gracefully close the database first
        if let Some(token) = close_token {
            let url = format!("http://127.0.0.1:{}/mcp", port);
            let request = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "close_idb",
                    "arguments": {"token": token}
                }
            });

            let _ = timeout(
                Duration::from_secs(SHUTDOWN_TIMEOUT_SECS),
                self.http_client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .json(&request)
                    .send(),
            )
            .await;
        }

        // Kill the process if still running
        let _ = process.kill();
        let _ = process.wait();

        // Release the port
        self.port_allocator.release(port);

        // Update active session if needed
        let needs_new_active = {
            let active = self.active_session_id.read().await;
            active.as_deref() == Some(session_id)
        };
        if needs_new_active {
            // Acquire sessions first (consistent lock ordering: sessions -> active_session_id)
            let sessions = self.sessions.read().await;
            let mut active = self.active_session_id.write().await;
            // Re-check in case another task already updated it
            if active.as_deref() == Some(session_id) {
                *active = sessions
                    .iter()
                    .find(|(_, s)| s.status() == SessionStatus::Ready)
                    .map(|(id, _)| id.clone());
            }
        }

        Ok(())
    }

    /// Switch the active session.
    pub async fn switch_session(&self, session_id: &str) -> Result<SessionInfo, SessionError> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;

        if session.status() != SessionStatus::Ready {
            return Err(SessionError::SessionNotReady(session_id.to_string()));
        }

        let info = session.info.clone();
        drop(sessions);

        let mut active = self.active_session_id.write().await;
        *active = Some(session_id.to_string());

        info!(session_id = %session_id, "Switched active session");
        Ok(info)
    }

    /// Get the active session ID.
    pub async fn get_active_session_id(&self) -> Option<String> {
        self.active_session_id.read().await.clone()
    }

    /// Get info about a specific session.
    pub async fn get_session_info(&self, session_id: &str) -> Result<SessionInfo, SessionError> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;
        Ok(session.info.clone())
    }

    /// Get info about the active session.
    pub async fn get_active_session_info(&self) -> Result<SessionInfo, SessionError> {
        let session_id = self
            .active_session_id
            .read()
            .await
            .clone()
            .ok_or(SessionError::NoActiveSession)?;
        self.get_session_info(&session_id).await
    }

    /// List all sessions (reaps dead sessions first).
    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        self.reap_dead_sessions().await;
        let sessions = self.sessions.read().await;
        sessions.values().map(|s| s.info.clone()).collect()
    }

    /// Get session statistics.
    pub async fn stats(&self) -> SessionStats {
        let sessions = self.sessions.read().await;
        let active_id = self.active_session_id.read().await.clone();

        SessionStats {
            total_sessions: sessions.len(),
            ready_sessions: sessions
                .values()
                .filter(|s| s.status() == SessionStatus::Ready)
                .count(),
            active_session_id: active_id,
            available_ports: self.port_allocator.available_count(),
        }
    }

    /// Shutdown all sessions.
    pub async fn shutdown_all(&self) {
        let session_ids: Vec<String> = {
            let sessions = self.sessions.read().await;
            sessions.keys().cloned().collect()
        };

        for session_id in session_ids {
            if let Err(e) = self.close_session(&session_id).await {
                warn!(session_id = %session_id, error = %e, "Failed to close session during shutdown");
            }
        }
    }
}

/// Statistics about sessions.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionStats {
    pub total_sessions: usize,
    pub ready_sessions: usize,
    pub active_session_id: Option<String>,
    pub available_ports: usize,
}
