use serde::Serialize;
use std::fmt;

/// The Network enum represents the different types of Networks we can create BitcoinWallets for
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub enum Network {
    Mainnet,
    Testnet,
    Error,
}

pub const MAINNET_BYTE: u8 = 0x80;
pub const TESTNET_BYTE: u8 = 0xEF;

pub const MAINNET_ADDRESS_BYTES: [u8; 2] = [0x1C, 0xB8];
pub const TESTNET_ADDRESS_BYTES: [u8; 2] = [0x1D, 0x25];

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Network::Mainnet => write!(f, "Mainnet"),
            Network::Testnet => write!(f, "Testnet"),
            _ => write!(f, "Error"),
        }
    }
}
