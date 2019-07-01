use std::fmt;
use std::fmt::Display;

use serde::Serialize;
use serde_json::to_string_pretty;

/// The Network enum represents the different types of Networks for cryptocurrencies
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Default for Network {
    fn default() -> Self {
        Network::Mainnet
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Network::Mainnet => write!(f, "Mainnet"),
            Network::Testnet => write!(f, "Testnet"),
        }
    }
}

pub trait Wallet: Sized + Serialize + Display {
    /// Generates a new uncompressed Wallet for a given `network`
    fn new(config: &Config) -> Self;

    /// Recovers a Wallet from a Wallet Import Format string (a private key string)
    fn from_wif(private_key_wif: &str) -> Self;

    fn to_json(&self) -> String {
        to_string_pretty(&self).unwrap()
    }
}

#[derive(Default)]
pub struct Config {
    pub compressed: bool,
    pub p2pkh: bool,
    pub p2wpkh_p2sh: bool,
    pub network: Network,
}
