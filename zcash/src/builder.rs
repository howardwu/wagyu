use network::Network;
use wallet::ZcashWallet;

/// A WalletBuilder helps to construct a ZcashWallet
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

    /// Finally, construct a ZcashWallet from the selected options
    pub fn build(&self) -> ZcashWallet {
        let network = if self.testnet {
            Network::Testnet
        } else {
            Network::Mainnet
        };

        if self.compressed {
            ZcashWallet::new_compressed(network)
        } else {
            ZcashWallet::new(network)
        }
    }

    pub fn build_from_options(compressed: bool, testnet: bool) -> ZcashWallet {
        let network = if testnet {
            Network::Testnet
        } else {
            Network::Mainnet
        };

        if compressed {
            ZcashWallet::new_compressed(network)
        } else {
            ZcashWallet::new(network)
        }
    }

    pub fn build_many_from_options(
        compressed: bool,
        testnet: bool,
        count: usize,
    ) -> Vec<ZcashWallet> {
        let mut wallets = Vec::with_capacity(count);
        for _ in 0..count {
            wallets.push(WalletBuilder::build_from_options(compressed, testnet));
        }

        wallets
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
