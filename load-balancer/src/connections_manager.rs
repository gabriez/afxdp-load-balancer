use std::{collections::HashMap, sync::Arc};

use crossbeam_channel::unbounded;
use log::{error, info, warn};
use network_types::{ip::Ipv4Hdr, tcp};
use tokio::{sync, sync::RwLock, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{connections_balancer::BackendSelector, TcpFlags, TcpFlagsEnum, TcpState};

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

    // This port refers to the dst port of the TCP packet received from the client.
    client_dst_port: u16,

    // This addresses are the destination addresses to which the proxy port maps
    destination_port: u16,
    destination_ip: [u8; 4],

    tx_flag: sync::watch::Sender<TcpUpdateState>,
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

    /// Closes a connection and cleans up the corresponding NAT entry. It takes the proxy port as a parameter, checks if a NAT entry exists for the given port, and if it does, it removes the NAT entry from the nat_map, removes the client mapping from the client_map, releases the proxy port back to the ports pool, and returns the removed NAT entry. If no NAT entry exists for the given port, it returns an error indicating that the connection was not found.
    pub fn close_connection(&mut self, port: u16) -> Result<NatEntry, NatTableError> {
        // Implementation for closing a connection and cleaning up NAT entries

        if let Some(nat_entry) = self.nat_map.remove(&port) {
            self.client_map
                .remove(&ClientKey::new(nat_entry.client_ip, nat_entry.client_port));
            self.ports_pool.release_port(port);
            return Ok(nat_entry);
        } else {
            return Err(NatTableError::ConnectionNotFound);
        }
    }

    pub fn new_conn(
        &mut self,
        client_port: u16,
        client_ip: [u8; 4],
        client_dst_port: u16,
        destination_port: u16,
        destination_ip: [u8; 4],
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
            client_dst_port,
            destination_port,
            destination_ip,
            tx_flag: sync::watch::channel(TcpUpdateState {
                flag: TcpFlagsEnum::SYN,
                origin: TcpPacketOrigin::Client,
            })
            .0,
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

    pub fn client_key_exists(&self, key: &ClientKey) -> bool {
        self.client_map.contains_key(key)
    }

    pub fn nat_entry_exists(&self, port: u16) -> bool {
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
        state: TcpState::SynReceived,
        // The current state of the TCP connection, used to manage the connection lifecycle
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

#[derive(Debug)]
pub struct RedirectionAddress {
    pub origin_port: u16,
    pub dest_ip: [u8; 4],
    pub dest_port: u16,
}

/// AddressProvider structure provides an API to interact with the NatTable and control TCP connections state.
/// It holds a reference to the shared NAT table and a channel sender to send new connection events to the connections state manager.
pub struct AddressProvider {
    nat_table: SharedNatTable,
    tx_new_conn: tokio::sync::mpsc::Sender<TcpNewConn>,
    backends: Arc<RwLock<dyn BackendSelector + 'static + Send>>,
}

impl AddressProvider {
    pub fn new(
        nat_table: SharedNatTable,
        tx_new_conn: tokio::sync::mpsc::Sender<TcpNewConn>,
        backends: Arc<RwLock<dyn BackendSelector + 'static + Send>>,
    ) -> Self {
        Self {
            nat_table,
            tx_new_conn,
            backends,
        }
    }

    pub fn check_origin(&self, ip: [u8; 4], port: u16) -> TcpPacketOrigin {
        let backends = self.backends.blocking_read();
        if backends.backend_exist(ip, port) {
            TcpPacketOrigin::Backend
        } else {
            TcpPacketOrigin::Client
        }
    }

    pub fn get_redirection_addr(
        &self,
        ipv4_hdr: &Ipv4Hdr,
        tcp_hdr: &tcp::TcpHdr,
    ) -> Option<RedirectionAddress> {
        let origin = self.check_origin(ipv4_hdr.src_addr, tcp_hdr.src_port);
        match origin {
            TcpPacketOrigin::Client => {
                if let Some((addr, tx)) =
                    self.get_backend_address(ipv4_hdr.src_addr, tcp_hdr.source)
                {
                    // tx.send(values::tcp::TcpUpdateState {
                    //     flag: TcpFlagsEnum::SYN,
                    //     origin: TcpPacketOrigin::Client,
                    // })
                    return Some(addr);
                }

                self.new_connection(ipv4_hdr.src_addr, tcp_hdr.source, tcp_hdr.dest)
            }
            TcpPacketOrigin::Backend => {
                if let Some((addr, tx)) = self.get_client_address(tcp_hdr.dest) {
                    //  tx.send(values::tcp::TcpUpdateState {
                    //         flag: TcpFlagsEnum::SYN,
                    //         origin: TcpPacketOrigin::Backend,
                    //     })
                    return Some(addr);
                }
                None
            }
        }
    }

    pub fn new_connection(
        &self,
        client_ip: [u8; 4],
        client_port: u16,
        client_dst_port: u16,
    ) -> Option<RedirectionAddress> {
        let destination = {
            let mut backends = self.backends.blocking_write();
            backends.select_backend()
        };
        if let Some((destination_ip, destination_port)) = destination {
            let mut lock_nat_table = self.nat_table.blocking_write();
            match lock_nat_table.new_conn(
                client_port,
                client_ip,
                client_dst_port,
                destination_port,
                destination_ip,
            ) {
                Ok((proxy_port, nat_entry)) => {
                    let tcp_new_conn = TcpNewConn {
                        proxy_port,
                        flag: TcpFlagsEnum::SYN,
                        origin: TcpPacketOrigin::Client,
                        rx_flag: nat_entry.tx_flag.subscribe(),
                    };
                    if let Err(e) = self.tx_new_conn.blocking_send(tcp_new_conn) {
                        error!(
                            "Failed to send new connection event to state manager: {}",
                            e
                        );
                    }
                    let mut backends = self.backends.blocking_write();
                    backends.increase_conn(destination_ip, destination_port);
                    Some(RedirectionAddress {
                        origin_port: proxy_port,
                        dest_ip: destination_ip,
                        dest_port: destination_port,
                    })
                }
                Err(e) => {
                    error!(
                        "Failed to create new NAT entry for client {}:{} -> {}:{} : {}",
                        client_ip
                            .iter()
                            .map(|b| b.to_string())
                            .collect::<Vec<String>>()
                            .join("."),
                        client_port,
                        destination_ip
                            .iter()
                            .map(|b| b.to_string())
                            .collect::<Vec<String>>()
                            .join("."),
                        destination_port,
                        e
                    );
                    None
                }
            }
        } else {
            warn!(
                "No backend available for new connection from client {}:{} -> {}:{}",
                client_ip
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<String>>()
                    .join("."),
                client_port,
                "N/A",
                "N/A"
            );
            None
        }
    }

    pub fn get_backend_address(
        &self,
        ip: [u8; 4],
        port: u16,
    ) -> Option<(RedirectionAddress, sync::watch::Sender<TcpUpdateState>)> {
        let client_key = ClientKey::new(ip, port);
        let mut lock_nat_table = self.nat_table.blocking_read();

        if lock_nat_table.client_key_exists(&client_key) {
            if let Some(proxy_port) = lock_nat_table.get_connection_port(&client_key) {
                if let Some(nat_entry) = lock_nat_table.get_nat_entry(proxy_port) {
                    return Some((
                        RedirectionAddress {
                            origin_port: proxy_port,
                            dest_ip: nat_entry.destination_ip,
                            dest_port: nat_entry.destination_port,
                        },
                        nat_entry.tx_flag.clone(),
                    ));
                }
            }
        }

        None
    }

    pub fn get_client_address(
        &self,
        proxy_port: u16,
    ) -> Option<(RedirectionAddress, sync::watch::Sender<TcpUpdateState>)> {
        let lock_nat_table = self.nat_table.blocking_read();

        if let Some(nat_entry) = lock_nat_table.get_nat_entry(proxy_port) {
            return Some((
                RedirectionAddress {
                    origin_port: nat_entry.client_dst_port,
                    dest_ip: nat_entry.client_ip,
                    dest_port: nat_entry.client_port,
                },
                nat_entry.tx_flag.clone(),
            ));
        }

        None
    }
}

pub trait RouteAddress {
    fn get_backend_address(&self, ip: [u8; 4], port: u16) -> Option<RedirectionAddress>;
    fn get_client_address(&self, proxy_port: u16) -> Option<RedirectionAddress>;
    fn check_origin(&self, ip: [u8; 4], port: u16) -> TcpPacketOrigin;
}
