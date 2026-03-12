use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
};

use internet_checksum::update;
use load_balancer_common::MIN_IPV4_HEADER_LEN;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};
use tokio::task::JoinHandle;

use crate::{TcpFlags, TcpState};

/*
NatTable should not modify packets structure, we only want this structure to handle connections and manage the state of the TCP connection.
fn route_packet and fn shift_mac will be responsible for modifying the packets and redirecting them to the correct backend server according to the NAT entries in the NatTable.

TODO: Should I implement a logic with a frontend and a backend?

The frontend will be doing the following:
- Return IP and port to which the client should connect to. This will be used by the XDP program to redirect the traffic to the correct backend server.
- Return the origin proxy port from where we are starting the connection.
- Receive the TCP flags from the XDP program to manage the state of the TCP connection.
- The frontend will be build when we create the backend. If by any means the frontend disappears, then we have to drop the backend and connections.

The backend will be doing the following:
- Create async tasks to manage the TCP connections. This way I can also implement timeouts for connections in different states.
- Check the state of the TCP connection and update it according to the TCP flags received from the XDP program.
- Close the connection and clean up the NAT entries when the connection is closed by the client, the backend server or doesn't change for too long.
- We don't want NatEntries to be public because we want to manage them only inside the backend, so we can ensure that the state of the TCP connection is updated correctly.


Now the logic implement two different services connected through channels from crossbeam.
- The first service will be sync
- The second service will be async and will be responsible to handle TCP connections state
Both will comunicate through crossbeam channels

NatTable will live in sync context

Meanwhile connections state will live in async context

Questions:
- Should frontend handle PortsPool?
*/

const MIN_PORT: u16 = 32768;
const MAX_PORT: u16 = 60999;

/// PortsPool structure to manage the pool of available ports for NAT entries. It keeps track of the maximum number of ports and the number of ports currently available.
/// It provides methods to get a port from the pool and release a port back to the pool.
#[derive(Debug)]
pub struct PortsPool {
    max_ports: usize,
    ports_available: usize,
    ports: Vec<Option<u16>>,
}

impl PortsPool {
    pub fn new(min_port: u16, max_port: u16) -> Self {
        let capacity = (max_port - min_port + 1) as usize;
        let mut ports = Vec::with_capacity(capacity);
        for i in 0..capacity {
            ports.push(Some(min_port + i as u16));
        }
        Self {
            max_ports: capacity,
            ports_available: capacity,
            ports,
        }
    }

    pub fn get_port(&mut self) -> Option<u16> {
        if self.ports_available == 0 {
            return None;
        }
        self.ports_available -= 1;
        self.ports[self.ports_available].take()
    }

    pub fn release_port(&mut self, port: u16) {
        if self.ports_available < self.max_ports {
            self.ports[self.ports_available] = Some(port);
            self.ports_available += 1;
        }
    }

    pub fn get_max_ports(&self) -> usize {
        self.max_ports
    }
}

pub struct NatState {
    last_seen: std::time::Instant, // Timestamp of the last packet seen for this connection, used for timeouts and cleanup
    last_tcp_flag: TcpFlags, // The last TCP flag received for this connection, used to manage the state of the TCP connection
    state: TcpState, // The current state of the TCP connection, used to manage the connection lifecycle
}

/// NatEntry structure to represent a NAT entry in the NAT table. It contains the client IP and port, the destination IP and port, the last seen timestamp, and the state of the TCP connection.
#[derive(Hash, Eq, PartialEq)]
pub struct NatEntry {
    // These addresses are the origin addresses from which the connection starts
    client_port: u16,
    client_ip: [u8; 4],

    // This addresses are the destination addresses to which the proxy port maps
    destination_port: u16,
    destination_ip: [u8; 4],

    // TCP connection management fields
    last_seen: std::time::Instant, // Timestamp of the last packet seen for this connection, used for timeouts and cleanup
    last_tcp_flag: TcpFlags, // The last TCP flag received for this connection, used to manage the state of the TCP connection
    state: TcpState, // The current state of the TCP connection, used to manage the connection lifecycle
}

/// ClientKey structure to represent a key for the client map in the NAT table. It contains the client IP and port. This structure is used to quickly look up the NAT entry for a given client.
#[derive(Hash, Eq, PartialEq)]
pub struct ClientKey {
    client_ip: [u8; 4],
    client_port: u16,
}

impl ClientKey {
    pub fn new(client_ip: [u8; 4], client_port: u16) -> Self {
        Self {
            client_ip,
            client_port,
        }
    }
}

/// NAT Table structure to hold active NAT entries and mappings
pub struct NatTable {
    /// Maps the proxy port to the corresponding NAT entry. This allows for quick lookups of NAT entries based on the proxy port used in the TCP connection.
    nat_map: HashMap<u16, NatEntry>,

    /// Used to quickly look up the NAT entry for a given client IP and port. It maps the client key (IP and port) to the proxy port used in the NAT entry.
    client_map: HashMap<ClientKey, u16>,

    /// Manages the pool of available ports for NAT entries. It keeps track of the maximum number of ports and the number of ports currently available, and provides methods to get a port from the pool and release a port back to the pool.
    ports_pool: PortsPool,
}

pub type SharedNatTable = Arc<RwLock<NatTable>>;

impl NatTable {
    pub fn new(ports_pool: PortsPool) -> Self {
        Self {
            nat_map: HashMap::new(),
            client_map: HashMap::new(),
            ports_pool,
        }
    }

    pub fn close_connection(&mut self, client_key: ClientKey) -> Result<(), NatTableError> {
        // Implementation for closing a connection and cleaning up NAT entries
        if self.connection_exists(key) {
            if let Some(port) = self.client_map.remove(&client_key) {
                self.nat_map.remove(&port);
                self.ports_pool.release_port(port);
            }
        } else {
            return Err(NatTableError::ConnectionNotFound);
        }
        Ok(())
    }

    // TODO: probably i'll return here an async task to manage the connection and update the state of the TCP connection according to the TCP flags received in the packets.
    // This way I can also implement timeouts for connections in different states.
    pub fn open_connection(
        &mut self,
        client_port: u16,
        client_ip: [u8; 4],
        destination_port: u16,
        destination_ip: [u8; 4],
    ) -> Result<(), NatTableError> {
        // Implementation for opening a new connection and creating NAT entries

        let proxy_port = match self.ports_pool.get_port() {
            Some(port) => port,
            None => {
                // No available ports in the pool, handle this case as needed (e.g., return an error)
                return Err(NatTableError::NoAvailablePorts);
            }
        };

        let _nat_entry = NatEntry {
            client_port,
            client_ip,
            destination_port,
            destination_ip,
            last_seen: std::time::Instant::now(),
            last_tcp_flag: TcpFlags::SYN, // Placeholder, the first packet should have the SYN flag set
            state: TcpState::SynReceived, // Placeholder i have to read TCP docs
        };

        let client_key = ClientKey::new(client_ip, client_port);

        todo!()
    }

    pub fn get_nat_entry(&self, port: u16) -> Option<&NatEntry> {
        self.nat_map.get(&port)
    }

    pub fn connection_exists(&self, key: ClientKey) -> bool {
        self.client_map.contains_key(&key)
    }

    pub fn get_active_connections(&self) -> usize {
        self.nat_map.len()
    }

    pub fn get_connection_port(&self, key: ClientKey) -> Option<u16> {
        self.client_map.get(&key).cloned()
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new(PortsPool::new(MIN_PORT, MAX_PORT))
    }
}

#[thiserror::Error]
enum NatTableError {
    #[error("No available ports in the pool")]
    NoAvailablePorts,
    #[error("NAT entry not found for the given port")]
    NatEntryNotFound,
    #[error("NAT entry already exists for the given client")]
    NatEntryAlreadyExists,
    #[error("Connection does not exists")]
    ConnectionNotFound,
}
pub struct ConnectionsManager {
    nat_table: SharedNatTable,
    ports_pool: PortsPool,
}

impl ConnectionsManager {
    pub fn build(nat_table: SharedNatTable, ports_pool: PortsPool) -> Self {
        Self {
            nat_table,
            ports_pool,
        }
    }

    pub fn manage_tasks(&self) -> JoinHandle<()> {
        // Implementation for checking and managing connections
        // TODO: I think I should check every connection separetaly
        // and update the state of the TCP connection according to the TCP flags received in the packets.
        // This way I can also implement timeouts for connections in different states.
        // I will use this function to clean up tasks that already finished or handle errors
        tokio::task::spawn(async move {
            // Connection checking logic goes here
        })
    }
}

pub trait ConnectionHandler {
    /// Get backend address is the function that will be called by the XDP program to get the backend address to which the packet should be redirected. It takes the client IP and port as parameters
    /// and returns the backend IP and port if a NAT entry exists for the given client, or None if no NAT entry exists.
    fn get_backend_address(&self, ip: [u8; 4], port: u16) -> Option<RedirectionAddress>;

    /// This function obtains client address information based on the provided proxy port. It is used to retrieve the original client IP and port associated with a given proxy port,
    /// which is essential for managing TCP connections and ensuring proper routing of packets back to the client.
    fn get_client_address(&self, proxy_port: u16) -> Option<RedirectionAddress>;
}

pub struct AddressProvider {
    nat_manager: Arc<dyn ConnectionHandler + 'static>,
}

struct RedirectionAddress {
    origin_port: u16,
    backend_ip: [u8; 4],
    backend_port: u16,
}

impl AddressProvider {
    pub fn new(nat_manager: Arc<dyn ConnectionHandler + 'static>) -> Self {
        Self { nat_manager }
    }

    pub fn get_backend_address(&self, ip: [u8; 4], port: u16) -> Option<RedirectionAddress> {
        self.nat_manager.get_backend_address(ip, port)
    }

    pub fn get_client_address(&self, proxy_port: u16) -> Option<RedirectionAddress> {
        self.nat_manager.get_client_address(proxy_port)
    }
}

// TODO: Still to be implemented. I need to study how to manage connections and the best patterns to follow in this case.
// I can use this guide: https://www.rfc-editor.org/rfc/rfc793.html and this one too https://medium.com/@itherohit/tcp-connection-establishment-an-in-depth-exploration-46031ef69908
// Also, I could check how other load balancers do it, like HAProxy and NGINX.

/// Get mutable headers from the raw packet data. This function is used to extract the Ethernet, IPv4, and TCP headers.
#[inline(always)]
pub fn get_mut_headers<'a>(
    frame_data: &'a [u8],
) -> Option<(&'a mut EthHdr, &'a mut Ipv4Hdr, &'a mut TcpHdr)> {
    let eth_hdr = unsafe { &mut *(frame_data.as_mut_ptr() as *mut EthHdr) };
    let ether_type = eth_hdr.ether_type;

    if ether_type != network_types::eth::EtherType::Ipv4 {
        return None;
    }

    let ipv4_hdr = unsafe { &mut *(frame_data.as_mut_ptr().add(EthHdr::LEN) as *mut Ipv4Hdr) };

    if ipv4_hdr.proto != network_types::ip::IpProto::Tcp {
        return None;
    }

    let tcp_hdr_offset = if ipv4_hdr.ihl() == 5 {
        EthHdr::LEN + MIN_IPV4_HEADER_LEN
    } else {
        EthHdr::LEN + (ipv4_hdr.ihl() as usize) * 4
    };

    let tcp_hdr = unsafe { &mut *(frame_data.as_mut_ptr().add(tcp_hdr_offset) as *mut TcpHdr) };

    Some((eth_hdr, ipv4_hdr, tcp_hdr))
}

/// Shift the source and destination MAC addresses in the Ethernet header of the packet. This is necessary to redirect the packet,
/// if we don't, the kernel will drop the packet because it will think that the packet is coming from internet and not going back to it.
#[inline(always)]
pub fn shift_mac(eth_hdr: &mut EthHdr) {
    let src_mac = eth_hdr.src_addr;
    let dst_mac = eth_hdr.dst_addr;

    eth_hdr.src_addr = dst_mac;
    eth_hdr.dst_addr = src_mac;
}

// To implement checksum update I'm using internet-checksum. This crate is optimized to calculate checksums efficiently and take advantage of CPU.
// You can check the code on the following link https://docs.rs/internet-checksum/0.2.1/src/internet_checksum/lib.rs.html
/// Route the packet by modifying the destination IP address and port in the IPv4 and TCP headers, respectively. It also updates the checksums accordingly.
#[inline(always)]
pub fn route_packet(
    ipv4_hdr: &mut Ipv4Hdr,
    tcp_hdr: &mut TcpHdr,
    ip_dest: [u8; 4],
    port_dest: u16,
) {
    let old_dst_ip = ipv4_hdr.dst_addr;
    let old_src_ip = ipv4_hdr.src_addr;
    let old_csum_ip = ipv4_hdr.check;

    ipv4_hdr.src_addr = old_dst_ip;
    ipv4_hdr.dst_addr = ip_dest;

    ipv4_hdr.check = update(old_csum_ip, &old_src_ip, &ip_dest);

    let old_dst_port = tcp_hdr.dest;
    let old_source_port = tcp_hdr.source;
    let mut old_csum_tcp_bytes = tcp_hdr.check.to_be_bytes();

    tcp_hdr.source = old_dst_port;
    tcp_hdr.dest = port_dest.to_be();

    old_csum_tcp_bytes = update(
        old_csum_tcp_bytes,
        &old_source_port.to_be_bytes(),
        &port_dest.to_be_bytes(),
    );

    old_csum_tcp_bytes = update(old_csum_tcp_bytes, &old_src_ip, &ip_dest);

    // I'm using here from_ne_bytes because update function expects values in native endianess.
    tcp_hdr.check = u16::from_ne_bytes(old_csum_tcp_bytes);
}
