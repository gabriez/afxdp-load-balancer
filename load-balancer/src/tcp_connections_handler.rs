use {
    std::{collections::HashMap, fmt, sync::Arc},
    tokio::{self, sync::RwLock, task::JoinHandle},
};

const MIN_PORT: u16 = 32768;
const MAX_PORT: u16 = 60999;

// The TCP flags.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod TcpFlags {
    /// CWR – Congestion Window Reduced (CWR) flag is set by the sending
    /// host to indicate that it received a TCP segment with the ECE flag set
    /// and had responded in congestion control mechanism (added to header by RFC 3168).
    pub const CWR: u8 = 0b10000000;
    /// ECE – ECN-Echo has a dual role, depending on the value of the
    /// SYN flag. It indicates:
    /// If the SYN flag is set (1), that the TCP peer is ECN capable.
    /// If the SYN flag is clear (0), that a packet with Congestion Experienced
    /// flag set (ECN=11) in IP header received during normal transmission
    /// (added to header by RFC 3168).
    pub const ECE: u8 = 0b01000000;
    /// URG – indicates that the Urgent pointer field is significant.
    pub const URG: u8 = 0b00100000;
    /// ACK – indicates that the Acknowledgment field is significant.
    /// All packets after the initial SYN packet sent by the client should have this flag set.
    pub const ACK: u8 = 0b00010000;
    /// PSH – Push function. Asks to push the buffered data to the receiving application.
    pub const PSH: u8 = 0b00001000;
    /// RST – Reset the connection.
    pub const RST: u8 = 0b00000100;
    /// SYN – Synchronize sequence numbers. Only the first packet sent from each end
    /// should have this flag set.
    pub const SYN: u8 = 0b00000010;
    /// FIN – No more data from sender.
    pub const FIN: u8 = 0b00000001;
}

/// State of TCP connection.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TcpState::Closed => "CLOSED",
                TcpState::Listen => "LISTEN",
                TcpState::SynSent => "SYN_SENT",
                TcpState::SynReceived => "SYN_RCVD",
                TcpState::Established => "ESTABLISHED",
                TcpState::FinWait1 => "FIN_WAIT_1",
                TcpState::FinWait2 => "FIN_WAIT_2",
                TcpState::CloseWait => "CLOSE_WAIT",
                TcpState::Closing => "CLOSING",
                TcpState::LastAck => "LAST_ACK",
                TcpState::TimeWait => "TIME_WAIT",
                TcpState::DeleteTcb => "DELETE_TCB",
            }
        )
    }
}

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

#[derive(Hash, Eq, PartialEq)]
pub struct NatEntry {
    // These addresses are the origin addresses from which the connection starts
    client_port: u16,
    client_ip: [u8; 4],

    // This addresses are the destination addresses to which the proxy port maps
    destination_port: u16,
    destination_ip: [u8; 4],
    last_seen: u64,
    state: TcpState,
}

#[derive(Hash, Eq, PartialEq)]
pub struct ClientKey {
    client_ip: [u8; 4],
    client_port: u16,
}

/// NAT Table structure to hold active NAT entries and mappings
pub struct NatTable {
    nat_map: HashMap<u16, NatEntry>,
    client_map: HashMap<ClientKey, u16>,
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

    pub fn close_connection(&mut self) {
        // Implementation for closing a connection and cleaning up NAT entries
        todo!()
    }

    pub fn open_connection(&mut self) {
        // Implementation for opening a new connection and creating NAT entries
        todo!()
    }

    pub fn get_nat_entry(&self, port: u16) -> Option<&NatEntry> {
        self.nat_map.get(&port)
    }

    pub fn connection_exists(&self, client_ip: [u8; 4], client_port: u16) -> bool {
        let key = ClientKey {
            client_ip,
            client_port,
        };
        self.client_map.contains_key(&key)
    }

    pub fn get_active_connections(&self) -> usize {
        self.nat_map.len()
    }

    pub fn get_connection_port(&self, client_ip: [u8; 4], client_port: u16) -> Option<u16> {
        let key = ClientKey {
            client_ip,
            client_port,
        };
        self.client_map.get(&key).cloned()
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new(PortsPool::new(MIN_PORT, MAX_PORT))
    }
}

pub struct ConnectionsManager {
    nat_table: SharedNatTable,
}

impl ConnectionsManager {
    pub fn build(nat_table: SharedNatTable) -> Self {
        Self { nat_table }
    }

    pub fn get_nat_table(&self) -> SharedNatTable {
        Arc::clone(&self.nat_table)
    }

    pub fn check_connections(&self) -> JoinHandle<()> {
        // Implementation for checking and managing connections
        tokio::task::spawn(async move {
            // Connection checking logic goes here
        })
    }
}

// TODO: Still to be implemented. I need to study how to manage connections and the best patterns to follow in this case.
// I can use this guide: https://www.rfc-editor.org/rfc/rfc793.html and this one too https://medium.com/@itherohit/tcp-connection-establishment-an-in-depth-exploration-46031ef69908
// Also, I could check how other load balancers do it, like HAProxy and NGINX.
