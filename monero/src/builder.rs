//! A WalletBuilder helps construct a MoneroWallet
use network::Network;
use wallet::MoneroWallet;

#[derive(Debug)]
/// Builds a Monero mainnet or testnet wallet
pub struct WalletBuilder {
    testnet: bool,
}

impl WalletBuilder {
    /// generates a new walletbuilder
    pub fn new() -> WalletBuilder {
        WalletBuilder {
            testnet: false, 
        }
    }

    /// Use Network::Testnet when build is called
    pub fn testnet(&mut self) -> &mut WalletBuilder {
        self.testnet = true;
        self
    }

    /// Use Network::Mainnet when build is called
    pub fn mainnet(&mut self) -> &mut WalletBuilder {
        self.testnet = false;
        self
    }

    /// construct a MoneroWallet
    pub fn build(&self) -> MoneroWallet {
        let network = if self.testnet {
            Network::Testnet
        } else {
            Network::Mainnet
        };

        MoneroWallet::new(network).unwrap()
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_build() {
//         let mut builder = WalletBuilder::new();
//         let wallet = builder.build();

//     }
// }
