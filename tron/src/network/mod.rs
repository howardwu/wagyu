use wagyu_model::{ChildIndex, Network};


pub mod mainnet;
pub use self::mainnet::*;

pub mod testnet;
pub use self::testnet::*;

/// The interface for an Tron network.
pub trait TronNetwork: Network {
    const CHAIN_ID: u32;
    const NETWORK_ID: u32;
    const HD_PURPOSE: ChildIndex = ChildIndex::Hardened(44);
    const HD_COIN_TYPE: ChildIndex;

    /// Returns the address prefix of the given network.
    fn address_prefix() -> u8;
}
