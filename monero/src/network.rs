use serde::Serialize;
use std::fmt;

/// The Network enum represents the different types of Networks we can create MoneroWallets for.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Network {
    Mainnet,
    Testnet,
}

pub const MAINNET_ADDRESS_BYTE: u8 = 0x12;
pub const TESTNET_ADDRESS_BYTE: u8 = 0x35;

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Network::Mainnet => write!(f, "Mainnet"),
            Network::Testnet => write!(f, "Testnet"),
        }
    }
}
