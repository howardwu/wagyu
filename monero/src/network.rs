//! Monero network prefixes and enums
use std::fmt;

/// The Network enum represents the different types of Networks we can create MoneroWallets for.
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub enum Network {
    /// Monero Mainnet
    Mainnet,
    /// Monero Testnet
    Testnet,
    /// Error
    Error,
}

/// Returns the prefix for a given network
pub fn get_prefix(network: &Network) -> Option<&'static [u8]> {
    match network {
        Network::Testnet => Some(&[0x35]),
        Network::Mainnet => Some(&[0x12]),
        Network::Error => Some(&[0x00]), // fix
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Network::Mainnet => write!(f, "Mainnet"),
            Network::Testnet => write!(f, "Testnet"),
            _ => write!(f, "Error"),
        }
    }
}
