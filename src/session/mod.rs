//! Session management for multi-binary analysis.
//!
//! This module provides multi-session support for ida-mcp, allowing multiple
//! binaries to be analyzed simultaneously. Due to IDA's single-database-per-process
//! limitation, each session spawns a separate child `ida-mcp serve-http` process.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │              Session Manager Process                     │
//! │                                                          │
//! │  MCP Client ──▶  SessionManagerServer                   │
//! │  (stdio/HTTP)    ├─ session_open/list/switch/close/info │
//! │                  └─ IDA tools → HTTP forward             │
//! │                                                          │
//! │                  SessionManager                          │
//! │                  ├─ sessions: HashMap<String, Session>   │
//! │                  ├─ active_session_id: Option<String>    │
//! │                  └─ port_allocator: 13400-13500          │
//! └─────────────────────────────────────────────────────────┘
//!                               │ HTTP
//!         ┌─────────────────────┼─────────────────────┐
//!         ▼                     ▼                     ▼
//! ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
//! │ Session "s1" │     │ Session "s2" │     │ Session "sN" │
//! │ Port: 13400  │     │ Port: 13401  │     │ Port: ...    │
//! │ ida-mcp      │     │ ida-mcp      │     │ ida-mcp      │
//! │ serve-http   │     │ serve-http   │     │ serve-http   │
//! └──────────────┘     └──────────────┘     └──────────────┘
//! ```

mod manager;
mod port_allocator;
pub mod server;
mod types;

pub use manager::SessionManager;
pub use port_allocator::PortAllocator;
pub use server::{SanitizedSessionServer, SessionManagerServer};
pub use types::{Session, SessionInfo, SessionStatus};
