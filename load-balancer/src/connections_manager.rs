use std::{collections::HashMap, sync::Arc};

use crossbeam_channel::unbounded;
use log::{error, info, warn};
use network_types::tcp;
use tokio::{sync, sync::RwLock, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{TcpFlags, TcpFlagsEnum, TcpState};

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

/// NatEntry structure to represent a NAT entry in the NAT table. It contains the client IP and port, the destination IP and port, the last seen timestamp, and the state of the TCP connection.
#[derive(Hash, Eq, PartialEq)]
pub struct NatEntry {
    // These addresses are the origin addresses from which the connection starts
    client_port: u16,
    client_ip: [u8; 4],

    // This addresses are the destination addresses to which the proxy port maps
    destination_port: u16,
    destination_ip: [u8; 4],

    tx_flag: sync::watch::Sender<TcpFlagsEnum>,
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

pub struct AddressProvider {
    nat_table: SharedNatTable,
    tx_new_conn: tokio::sync::mpsc::Sender<TcpNewConn>,
}

impl AddressProvider {
    pub fn get_address(&self) {
        // self.tx_new_conn.blocking_send(value)
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

pub trait NatConnections {
    // TODO:
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

    pub fn close_connection(&mut self, port: u16) -> Result<(), NatTableError> {
        // Implementation for closing a connection and cleaning up NAT entries
        if self.proxy_port_exists(port) {
            if let Some(NatEntry {
                client_ip,
                client_port,
                ..
            }) = self.nat_map.remove(&port)
            {
                self.client_map
                    .remove(&ClientKey::new(client_ip, client_port));
                self.ports_pool.release_port(port);
            }
        } else {
            return Err(NatTableError::ConnectionNotFound);
        }
        Ok(())
    }

    pub fn new_conn(
        &mut self,
        client_port: u16,
        client_ip: [u8; 4],
        destination_port: u16,
        destination_ip: [u8; 4],
        tx_flag: sync::watch::Sender<TcpFlagsEnum>,
    ) -> Result<(u16, NatEntry), NatTableError> {
        let proxy_port = match self.ports_pool.get_port() {
            Some(port) => port,
            None => {
                // No available ports in the pool, handle this case as needed (e.g., return an error)
                return Err(NatTableError::NoAvailablePorts);
            }
        };

        let nat_entry = NatEntry {
            client_port,
            client_ip,
            destination_port,
            destination_ip,
            tx_flag,
        };

        let client_key = ClientKey::new(client_ip, client_port);

        if self.client_map.contains_key(&client_key) {
            return Err(NatTableError::NatEntryAlreadyExists);
        }

        if self.nat_map.contains_key(&proxy_port) {
            return Err(NatTableError::NatEntryAlreadyExists);
        }

        self.nat_map.insert(proxy_port, nat_entry.clone());
        self.client_map.insert(client_key, proxy_port);

        Ok((proxy_port, nat_entry))
    }

    pub fn get_nat_entry(&self, port: u16) -> Option<&NatEntry> {
        self.nat_map.get(&port)
    }

    pub fn connection_exists(&self, key: &ClientKey) -> bool {
        self.client_map.contains_key(key)
    }

    pub fn proxy_port_exists(&self, port: u16) -> bool {
        self.nat_map.contains_key(&port)
    }

    pub fn get_active_connections(&self) -> usize {
        self.nat_map.len()
    }

    pub fn get_connection_port(&self, key: &ClientKey) -> Option<u16> {
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

pub struct TcpConnState {
    last_seen: std::time::Instant, // Timestamp of the last packet seen for this connection, used for timeouts and cleanup
    last_tcp_flag: TcpFlagsEnum, // The last TCP flag received for this connection, used to manage the state of the TCP connection
    state: TcpState, // The current state of the TCP connection, used to manage the connection lifecycle
    last_packet_origin: TcpPacketOrigin,
}

pub struct TcpUpdateState {
    proxy_port: u16,
    flag: TcpFlagsEnum, // The current state of the TCP connection, used to manage the connection lifecycle
    origin: TcpPacketOrigin,
}

pub struct TcpNewConn {
    proxy_port: u16,
    flag: TcpFlagsEnum, // The current state of the TCP connection, used to manage the connection lifecycle
    origin: TcpPacketOrigin,
    rx_flag: sync::watch::Receiver<TcpUpdateState>,
}

pub enum TcpPacketOrigin {
    Client,
    Backend,
}

async fn conns_state_manager(
    mut rx_new_conn: tokio::sync::mpsc::Receiver<TcpNewConn>,
    cancel_token: CancellationToken,
    nat_table: SharedNatTable,
) {
    let mut active_conn = JoinSet::new();
    loop {
        tokio::select! {
            conn_try = rx_new_conn.recv()  => {
                match conn_try {
                    Some(new_conn) => {
                        active_conn.spawn(tcp_state_manager(
                            new_conn.rx_flag,
                            cancel_token.clone(),
                            new_conn,
                        ));
                    },
                    None => {
                        warn!("Channel is closed for connections state manager. Finishing task");
                        break;
                    }
                }
            }
            _ = cancel_token.cancelled() => {
                    info!("Connections state manager received cancellation signal, shutting down.");
                    break;
                }
                Some(join_result) = active_conn.join_next() => {
                    match join_result {
                        Ok(proxy_port) => {
                            println!("TCP state manager task completed successfully.");
                            let mut lock_nat_table = nat_table.write().await;
                            if let Err(e) =  lock_nat_table.close_connection(proxy_port) {
                                eprintln!("Error closing connection for proxy port {}: {}", proxy_port, e);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error in TCP state manager task: {}", e);
                        }
                    }
                }
        }
    }

    active_conn.shutdown().await;
}

async fn tcp_state_manager(
    rx_event: sync::watch::Receiver<TcpUpdateState>,
    cancel_token: CancellationToken,
    tcp_new_conn: TcpNewConn,
) -> u16 {
    let mut timeout = tokio::time::sleep(std::time::Duration::from_secs(60)); // TODO: define timeout duration
    let TcpNewConn {
        proxy_port,
        flag,
        origin,
        rx_flag,
    } = tcp_new_conn;

    let mut tcp_state: TcpConnState = TcpConnState {
        last_seen: std::time::Instant::now(), // Timestamp of the last packet seen for this connection, used for timeouts and cleanup
        last_tcp_flag: flag, // The last TCP flag received for this connection, used to manage the state of the TCP connection
        state: if origin == TcpPacketOrigin::Client {
            TcpState::SynReceived
        } else {
            TcpState::SynSent
        }, // The current state of the TCP connection, used to manage the connection lifecycle
        last_packet_origin: origin,
    };

    loop {
        tokio::select! {
            _ = &mut timeout => {
                // Handle connection timeout, e.g., remove the connection from the manager
                println!("Connection timed out: {:?}", tcp_state);
                return proxy_port;
            }
            _ = rx_event.changed() => {

                    let new_flag = *rx_event.borrow();
                    // Update the TCP state based on the new flag
                    println!("TCP flag changed for connection {:?}: {:?}", tcp_state, new_flag);
                    // Reset the timeout on activity
                    timeout = tokio::time::sleep(std::time::Duration::from_secs(60));

            }
            _ = cancel_token.cancelled() => {
               return 0 ;
            }
        }
    }
}
