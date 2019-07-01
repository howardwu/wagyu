//! Monero network prefixes and enums
use crate::traits::Network;

/// Returns the prefix for a given network
pub fn get_prefix(network: &Network) -> Option<&'static [u8]> {
    match network {
        Network::Testnet => Some(&[0x35]),
        Network::Mainnet => Some(&[0x12]),
    }
}
