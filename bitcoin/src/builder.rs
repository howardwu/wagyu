use network::Network;
use wallet::BitcoinWallet;

/// A WalletBuilder helps to construct a BitcoinWallet
#[derive(Default)]
pub struct WalletBuilder {
    compressed: bool,
    testnet: bool,
}

impl WalletBuilder {
    pub fn new() -> WalletBuilder {
        WalletBuilder {
            compressed: false,
            testnet: false,
        }
    }

    /// Use the compressed option when the build function is called
    pub fn compressed(&mut self) -> &mut WalletBuilder {
        self.compressed = true;
        self
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

    /// Finally, construct a BitcoinWallet from the selected options
    pub fn build(&self) -> BitcoinWallet {
        let network = if self.testnet {
            Network::Testnet
        } else {
            Network::Mainnet
        };

        if self.compressed {
            BitcoinWallet::new_compressed(network)
        } else {
            BitcoinWallet::new(network)
        }
    }

    pub fn build_from_options(compressed: bool, testnet: bool) -> BitcoinWallet {
        let network = if testnet {
            Network::Testnet
        } else {
            Network::Mainnet
        };

        if compressed {
            BitcoinWallet::new_compressed(network)
        } else {
            BitcoinWallet::new(network)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_compressed() {
        let mut builder = WalletBuilder::new();
        let wallet = builder.compressed().build();
        assert_eq!(*wallet.compressed(), true);
    }

    #[test]
    fn test_build_testnet() {
        let mut builder = WalletBuilder::new();
        let wallet = builder.testnet().build();
        assert_eq!(*wallet.network(), Network::Testnet);
    }

    #[test]
    fn test_build_compressed_testnet() {
        let mut builder = WalletBuilder::new();
        let wallet = builder.compressed().testnet().build();
        assert_eq!(*wallet.compressed(), true);
        assert_eq!(*wallet.network(), Network::Testnet);
    }

    #[test]
    fn test_build_uncompressed_mainnet() {
        let builder = WalletBuilder::new();
        let wallet = builder.build();
        assert_eq!(*wallet.compressed(), false);
        assert_eq!(*wallet.network(), Network::Mainnet);
    }
}
