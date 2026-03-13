use std::sync::Arc;

use fastrand::usize;
use tokio::sync::RwLock;
/// This file contains logic related to load balancing client requests across multiple backend servers
/// here is the core logic that decides which backend server to use for a given client request

pub type GlobalBackends = Arc<RwLock<Backends>>;

pub struct Backends {
    // Maps backend server address to active connections
    backends: Vec<(([u8; 4], u16), u32)>,
}

impl Backends {
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
        }
    }

    /// Returns a clone of the current list of backends and their active connection counts. This method is useful for retrieving the current state of the backends without modifying it.
    pub fn list_backends(&self) -> Vec<(([u8; 4], u16), u32)> {
        self.backends.clone()
    }

    /// This functions adds a backend into the backends vector if it is not already present.
    pub fn add_backend(&mut self, ip: [u8; 4], port: u16) {
        let backend_address = (ip, port);
        if !self
            .backends
            .iter()
            .any(|(addr, _)| *addr == backend_address)
        {
            self.backends.push((backend_address, 0));
        }
    }

    /// This functions removes a backend from the backends vector.
    pub fn remove_backend(&mut self, ip: [u8; 4], port: u16) {
        let backend_address = (ip, port);
        self.backends.retain(|(addr, _)| *addr != backend_address);
    }

    /// Select a backend server based on the least active connections strategy. This method returns the selected backend's IP and port.
    /// From a vector of N backends, it selects two backends randomly and the one with the less connections is selected.
    /// The purpose of this approach is to balance connections more evenly acroos available backends and avoid overloading a single backend while others are underutilized.
    pub fn select_backend(&mut self) -> Option<([u8; 4], u16)> {
        if self.backends.is_empty() {
            return None;
        }

        let random_index = usize(..self.backends.len());
        let random_index2 = usize(..self.backends.len());

        let mut selected_backend = {
            let (address1, act_conn1) = &self.backends[random_index];
            let (address2, act_conn2) = &self.backends[random_index2];

            if act_conn1 > act_conn2 {
                Some(*address2)
            } else {
                Some(*address1)
            }
        };

        // Increment the connection count for the selected backend
        if let Some(addr) = selected_backend {
            if let Some((_, connections)) = self.backends.iter_mut().find(|(a, _)| *a == addr) {
                *connections += 1;
            }
        }

        selected_backend
    }
}

pub trait BackendSelector {
    fn select_backend(&mut self) -> Option<([u8; 4], u16)>;

    fn backend_exist(&self, ip: [u8; 4], port: u16) -> bool;
}

impl BackendSelector for Backends {
    /// Retrieve a backend from a list of backends. Algorithm implementation for selection is arbitrary and can be changed.
    fn select_backend(&mut self) -> Option<([u8; 4], u16)> {
        self.select_backend()
    }

    fn backend_exist(&self, ip: [u8; 4], port: u16) -> bool {
        self.backends
            .iter()
            .any(|((backend_ip, backend_port), _)| *backend_ip == ip && *backend_port == port)
    }
}

/// Trait to abstract the management of backends, allowing for different implementations of backend storage and management while providing a consistent interface for adding, removing, and listing backends. This trait can be implemented by any structure that manages backend servers, enabling flexibility in how backends are stored and accessed.
pub trait BackendManager {
    /// Adds a backend address to the structure storing it
    fn add_backend(&mut self, ip: [u8; 4], port: u16);

    /// Removes a backend address from the structures storing them
    fn remove_backend(&mut self, ip: [u8; 4], port: u16);

    /// Decrease quantity of active connections in backend
    fn decrease_conn(&mut self, ip: [u8; 4], port: u16);

    /// Returns a clone of the current list of backends and their active connection counts. This method is useful for retrieving the current state of the backends without modifying it.
    fn list_backends(&self) -> Vec<(([u8; 4], u16), u32)>;
}

impl BackendManager for Backends {
    fn add_backend(&mut self, ip: [u8; 4], port: u16) {
        self.add_backend(ip, port);
    }

    fn remove_backend(&mut self, ip: [u8; 4], port: u16) {
        self.remove_backend(ip, port);
    }

    fn list_backends(&self) -> Vec<(([u8; 4], u16), u32)> {
        self.list_backends
    }

    fn decrease_conn(&mut self, ip: [u8; 4], port: u16) {
        if let Some((_, connections)) = self
            .list_backends()
            .iter_mut()
            .find(|((backend_ip, backend_port), _)| *backend_ip == ip && *backend_port == port)
        {
            if *connections > 0 {
                *connections -= 1;
            }
        }
    }
}
