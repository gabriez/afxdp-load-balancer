use std::collections::HashMap;

use fastrand::usize;
/// This file contains logic related to load balancing client requests across multiple backend servers
/// here is the core logic that decides which backend server to use for a given client request

#[derive(Debug, Clone)]
pub struct Backends {
    /// Maps backend server address to active connections. This structure is used to keep track of the number of active connections for each backend server.
    /// The purpose of using a HashMap is to allow for efficient lookups and updates of the active connection counts for each backend server.
    counter: HashMap<([u8; 4], u16), u32>,
    // Maps backend server address to active connections
    backends: Vec<([u8; 4], u16)>,
}

impl Backends {
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
            counter: HashMap::new(),
        }
    }

    /// Returns a clone of the current list of backends and their active connection counts. This method is useful for retrieving the current state of the backends without modifying it.
    pub fn list_backends(&self) -> HashMap<([u8; 4], u16), u32> {
        self.counter.clone()
    }

    /// This functions adds a backend into the backends vector if it is not already present.
    pub fn add_backend(&mut self, ip: [u8; 4], port: u16) {
        let backend_address = (ip, port);

        if self.counter.contains_key(&backend_address) {
            return;
        }

        self.counter.insert(backend_address, 0);
        self.backends.push(backend_address);
    }

    /// This functions removes a backend from the backends vector.
    pub fn remove_backend(&mut self, ip: [u8; 4], port: u16) {
        let backend_address = (ip, port);
        self.backends.retain(|addr| *addr != backend_address);
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

        let selected_backend = {
            let address1 = &self.backends[random_index];
            let address2 = &self.backends[random_index2];

            let act_conn1 = self.counter.get(&(*address1)).cloned().unwrap_or(0);

            let act_conn2 = self.counter.get(&(*address2)).cloned().unwrap_or(0);

            if act_conn1 > act_conn2 {
                Some(*address2)
            } else {
                Some(*address1)
            }
        };

        selected_backend
    }
}

pub trait BackendSelector {
    fn select_backend(&mut self) -> Option<([u8; 4], u16)>;

    fn backend_exist(&self, ip: [u8; 4], port: u16) -> bool;

    /// Decrease quantity of active connections in backend
    fn decrease_conn(&mut self, ip: [u8; 4], port: u16);

    /// Increase quantity of active connections in backend
    fn increase_conn(&mut self, ip: [u8; 4], port: u16);
}

impl BackendSelector for Backends {
    /// Retrieve a backend from a list of backends. Algorithm implementation for selection is arbitrary and can be changed.
    fn select_backend(&mut self) -> Option<([u8; 4], u16)> {
        self.select_backend()
    }

    fn backend_exist(&self, ip: [u8; 4], port: u16) -> bool {
        self.counter.contains_key(&(ip, port))
    }

    fn decrease_conn(&mut self, ip: [u8; 4], port: u16) {
        if let Some(connections) = self.counter.get_mut(&(ip, port)) {
            if *connections > 0 {
                *connections -= 1;
            }
        }
    }

    fn increase_conn(&mut self, ip: [u8; 4], port: u16) {
        if let Some(connections) = self.counter.get_mut(&(ip, port)) {
            *connections += 1;
        }
    }
}

/// Trait to abstract the management of backends, allowing for different implementations of backend storage and management while providing a consistent interface for adding, removing, and listing backends. This trait can be implemented by any structure that manages backend servers, enabling flexibility in how backends are stored and accessed.
pub trait BackendManager {
    /// Adds a backend address to the structure storing it
    fn add_backend(&mut self, ip: [u8; 4], port: u16);

    /// Removes a backend address from the structures storing them
    fn remove_backend(&mut self, ip: [u8; 4], port: u16);

    /// Returns a clone of the current list of backends and their active connection counts. This method is useful for retrieving the current state of the backends without modifying it.
    fn list_backends(&self) -> HashMap<([u8; 4], u16), u32>;
}

impl BackendManager for Backends {
    fn add_backend(&mut self, ip: [u8; 4], port: u16) {
        self.add_backend(ip, port);
    }

    fn remove_backend(&mut self, ip: [u8; 4], port: u16) {
        self.remove_backend(ip, port);
    }

    fn list_backends(&self) -> HashMap<([u8; 4], u16), u32> {
        self.list_backends()
    }
}
