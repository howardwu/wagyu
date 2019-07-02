use wallet::EthereumWallet;

/// A WalletBuilder helps to construct a EthereumWallet
#[derive(Default)]
pub struct WalletBuilder {}

impl WalletBuilder {
    pub fn new() -> WalletBuilder {
        WalletBuilder {}
    }

    /// Construct an EthereumWallet
    pub fn build() -> EthereumWallet {
        EthereumWallet::new()
    }

    pub fn build_many_from_options(count: usize) -> Vec<EthereumWallet> {
        let mut wallets = Vec::with_capacity(count);
        for _ in 0..count {
            wallets.push(WalletBuilder::build());
        }
        wallets
    }
}
