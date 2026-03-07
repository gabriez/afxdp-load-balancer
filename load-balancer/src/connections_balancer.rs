use std::collections::HashMap;

/// This file contains logic related to load balancing client requests across multiple backend servers
/// here is the core logic that decides which backend server to use for a given client request

pub struct Backends {
    // Maps backend server address to active connections
    backends: HashMap<([u8; 4], u16), u32>,
}
