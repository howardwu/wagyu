use crate::traits::{Config, Wallet};
use traits::Network;

/// A WalletBuilder helps to construct a Wallet
pub struct WalletBuilder {
    pub config: Config,
}

impl WalletBuilder {
    pub fn new() -> WalletBuilder {
        WalletBuilder {
            config: Default::default(),
        }
    }

    /// Use the compressed option when the build function is called
    pub fn compressed(&mut self) -> &mut WalletBuilder {
        self.config.compressed = true;
        self
    }

    /// Use Network::Testnet when build is called
    pub fn testnet(&mut self) -> &mut WalletBuilder {
        self.config.network = Network::Testnet;
        self
    }

    /// Use Network::Mainnet when build is called
    pub fn mainnet(&mut self) -> &mut WalletBuilder {
        self.config.network = Network::Mainnet;
        self
    }

    /// If the currency supports it, create a p2pkh wallet when build is called
    pub fn p2pkh(&mut self) -> &mut WalletBuilder {
        if self.config.p2wpkh_p2sh {
            self.config.p2wpkh_p2sh = false;
            self.config.compressed = false;
        }
        self.config.p2pkh = true;
        self
    }

    /// If the currency supports it, create a p2wpkh_p2sh wallet when build is called
    pub fn p2wpkh_p2sh(&mut self) -> &mut WalletBuilder {
        self.config.p2wpkh_p2sh = true;
        self.config.compressed = true;
        self.config.p2pkh = false;
        self
    }

    /// Finally, construct a Wallet from the selected options
    pub fn build<T: Wallet>(config: Config) -> T {
        T::new(&config)
    }

    /// Finally, construct a Vector of Wallets from the selected options
    pub fn build_many_from_options<T: Wallet>(config: Config, count: usize) -> Vec<T> {
        let mut wallets = Vec::with_capacity(count);
        for _ in 0..count {
            wallets.push(T::new(&config));
        }

        wallets
    }
}
