//! Port allocation for session HTTP servers.

use std::collections::HashSet;
use std::sync::Mutex;

/// Default starting port for session HTTP servers.
pub const DEFAULT_PORT_RANGE_START: u16 = 13400;
/// Default ending port for session HTTP servers.
pub const DEFAULT_PORT_RANGE_END: u16 = 13500;

/// Allocates ports for session HTTP servers within a configured range.
pub struct PortAllocator {
    /// Starting port (inclusive).
    base_port: u16,
    /// Maximum port (exclusive).
    max_port: u16,
    /// Set of currently allocated ports.
    used_ports: Mutex<HashSet<u16>>,
}

impl PortAllocator {
    /// Create a new port allocator with the given range.
    pub fn new(base_port: u16, max_port: u16) -> Self {
        Self {
            base_port,
            max_port,
            used_ports: Mutex::new(HashSet::new()),
        }
    }

    /// Allocate the next available port.
    ///
    /// Returns `None` if no ports are available in the range.
    pub fn allocate(&self) -> Option<u16> {
        let mut used = self.used_ports.lock().unwrap_or_else(|e| e.into_inner());
        for port in self.base_port..self.max_port {
            if !used.contains(&port) {
                used.insert(port);
                return Some(port);
            }
        }
        None
    }

    /// Release a previously allocated port.
    pub fn release(&self, port: u16) {
        let mut used = self.used_ports.lock().unwrap_or_else(|e| e.into_inner());
        used.remove(&port);
    }

    /// Get the number of currently allocated ports.
    pub fn allocated_count(&self) -> usize {
        let used = self.used_ports.lock().unwrap_or_else(|e| e.into_inner());
        used.len()
    }

    /// Get the number of available ports.
    pub fn available_count(&self) -> usize {
        let total = (self.max_port - self.base_port) as usize;
        total.saturating_sub(self.allocated_count())
    }

    /// Check if a specific port is available.
    pub fn is_available(&self, port: u16) -> bool {
        if port < self.base_port || port >= self.max_port {
            return false;
        }
        let used = self.used_ports.lock().unwrap_or_else(|e| e.into_inner());
        !used.contains(&port)
    }
}

impl Default for PortAllocator {
    fn default() -> Self {
        Self::new(DEFAULT_PORT_RANGE_START, DEFAULT_PORT_RANGE_END)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_and_release() {
        let allocator = PortAllocator::new(13400, 13403);

        // Allocate all ports
        assert_eq!(allocator.allocate(), Some(13400));
        assert_eq!(allocator.allocate(), Some(13401));
        assert_eq!(allocator.allocate(), Some(13402));
        assert_eq!(allocator.allocate(), None); // Range exhausted

        // Release one port
        allocator.release(13401);
        assert_eq!(allocator.allocate(), Some(13401));

        // Still no more available
        assert_eq!(allocator.allocate(), None);
    }

    #[test]
    fn test_available_count() {
        let allocator = PortAllocator::new(13400, 13405);
        assert_eq!(allocator.available_count(), 5);
        assert_eq!(allocator.allocated_count(), 0);

        allocator.allocate();
        allocator.allocate();
        assert_eq!(allocator.available_count(), 3);
        assert_eq!(allocator.allocated_count(), 2);
    }
}
