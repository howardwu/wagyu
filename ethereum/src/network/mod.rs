use wagyu_model::{ChildIndex, Network};

pub mod goerli;
pub use self::goerli::*;

pub mod kovan;
pub use self::kovan::*;

pub mod mainnet;
pub use self::mainnet::*;

pub mod rinkeby;
pub use self::rinkeby::*;

pub mod ropsten;
pub use self::ropsten::*;

/// The interface for an Ethereum network.
pub trait EthereumNetwork: Network {
    const CHAIN_ID: u32;
    const NETWORK_ID: u32;
    const HD_PURPOSE: ChildIndex = ChildIndex::Hardened(44);
    const HD_COIN_TYPE: ChildIndex;
}
