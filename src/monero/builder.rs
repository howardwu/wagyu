//! A WalletBuilder helps construct a MoneroWallet
use crate::monero::network::Network;
use crate::monero::wallet::MoneroWallet;

#[derive(Debug)]
/// Builds a Monero mainnet or testnet wallet
pub struct WalletBuilder {
    testnet: bool,
}

impl WalletBuilder {
    /// generates a new walletbuilder
    pub fn new() -> WalletBuilder {
        WalletBuilder { testnet: false }
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

        MoneroWallet::new(&network)
    }

    /// build a monero wallet from a testnet option flag
    pub fn build_from_options(testnet: bool) -> MoneroWallet {
        let network = if testnet {
            Network::Testnet
        } else {
            Network::Mainnet
        };

        MoneroWallet::new(&network)
    }

    /// build a monero wallet from a testnet option and count flag
    pub fn build_many_from_options(testnet: bool, count: usize) -> Vec<MoneroWallet> {
        let mut wallets = Vec::with_capacity(count);
        for _ in 0..count {
            wallets.push(WalletBuilder::build_from_options(testnet));
        }

        wallets
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_build_testnet() {
//         let mut builder = WalletBuilder::new();
//         let wallet = builder.testnet().build();
//         assert_eq!(*wallet.network(), Network::Testnet)

//     }
// }
