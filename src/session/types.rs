//! Session and session info types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::process::Child;

/// Status of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Session is starting up (process spawned, waiting for ready).
    Starting,
    /// Session is ready for tool calls.
    Ready,
    /// Session encountered an error.
    Error,
    /// Session has been closed.
    Closed,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Starting => write!(f, "starting"),
            SessionStatus::Ready => write!(f, "ready"),
            SessionStatus::Error => write!(f, "error"),
            SessionStatus::Closed => write!(f, "closed"),
        }
    }
}

/// Information about a session (serializable for API responses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Unique session identifier.
    pub id: String,
    /// Path to the binary being analyzed.
    pub binary_path: String,
    /// HTTP port the session is listening on.
    pub port: u16,
    /// Current status of the session.
    pub status: SessionStatus,
    /// Process ID of the child ida-mcp process.
    pub pid: u32,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// Error message if status is Error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A running session with its child process.
pub struct Session {
    /// Session metadata.
    pub info: SessionInfo,
    /// Child process handle.
    pub process: Child,
    /// Close token returned by open_idb (needed to close the database).
    pub close_token: Option<String>,
}

impl Session {
    /// Create a new session with the given info and child process.
    pub fn new(info: SessionInfo, process: Child) -> Self {
        Self {
            info,
            process,
            close_token: None,
        }
    }

    /// Check if the child process is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.process.try_wait(), Ok(None))
    }

    /// Get the session ID.
    pub fn id(&self) -> &str {
        &self.info.id
    }

    /// Get the port this session is listening on.
    pub fn port(&self) -> u16 {
        self.info.port
    }

    /// Get the binary path being analyzed.
    pub fn binary_path(&self) -> &str {
        &self.info.binary_path
    }

    /// Get the current status.
    pub fn status(&self) -> SessionStatus {
        self.info.status
    }

    /// Update the session status.
    pub fn set_status(&mut self, status: SessionStatus) {
        self.info.status = status;
    }

    /// Set the error message and update status to Error.
    pub fn set_error(&mut self, error: String) {
        self.info.error = Some(error);
        self.info.status = SessionStatus::Error;
    }

    /// Set the close token.
    pub fn set_close_token(&mut self, token: String) {
        self.close_token = Some(token);
    }
}
