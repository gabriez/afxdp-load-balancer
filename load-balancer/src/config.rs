use std::{net::SocketAddr, path::Path};

use serde::Deserialize;
use tokio::fs::read_to_string;

// We are not gonna implement extensive validation here because this is just a PoC
// In the next part we are going to implement a proper config parser with validation
// and error handling taking into account all what-if scenarios and structures to store
// the configuration in somekind of global memory for easy access across the application.
// Probably, most of this data will be present in NatTable structure, but I'd like to
// separate responsabilities so NatTable isn't full of this code

#[derive(Deserialize, Debug)]
pub struct Config {
    pub rx_ports: Vec<u16>,
    pub backends_addresses: Vec<SocketAddr>,
    pub nat_ports_range: (u16, u16),
}

impl Config {
    pub async fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let json_file = read_to_string(path.as_ref())
            .await
            .expect("Failed to read config file");
        serde_json::from_str::<Self>(&json_file).map_err(anyhow::Error::from)
    }
}
