use std::fmt;

/// The Network enum represents the different types of Networks we can create BitcoinWallets for
#[derive(Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Error,
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
