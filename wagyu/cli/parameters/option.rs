// Format
// (argument, conflicts, possible_values)

// Global

pub const COUNT: (&str, &[&'static str], &[&'static str]) = (
    "[count] -c --count=[count] 'Generates a specified number of wallets'",
    &[],
    &[],
);
pub const FORMAT_BITCOIN: (&str, &[&'static str], &[&'static str]) = (
    "[format] -f --format=[format] 'Generates a wallet with a specified format'",
    &[],
    &["bech32", "legacy", "segwit"],
);
pub const NETWORK_BITCOIN: (&str, &[&'static str], &[&'static str]) = (
    "[network] -n --network=[network] 'Generates a wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
);
pub const NETWORK_MONERO: (&str, &[&'static str], &[&'static str]) = (
    "[network] -n --network=[network] 'Generates a wallet for a specified network'",
    &[],
    &["mainnet", "stagenet", "testnet"],
);
pub const NETWORK_ZCASH: (&str, &[&'static str], &[&'static str]) = (
    "[network] -n --network=[network] 'Generates a wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
);

// Import

pub const ADDRESS: (&str, &[&'static str], &[&'static str]) = (
    "[address] --address=[address] 'Imports a partial wallet for a specified address'",
    &["count", "private key", "network", "public key"],
    &[],
);
pub const FORMAT_IMPORT_BITCOIN: (&str, &[&'static str], &[&'static str]) = (
    "[format] -f --format=[format] 'Imports a wallet with a specified format'",
    &[],
    &["bech32", "legacy", "segwit"],
);
pub const NETWORK_IMPORT_BITCOIN: (&str, &[&'static str], &[&'static str]) = (
    "[network] -n --network=[network] 'Imports a wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
);
pub const PRIVATE: (&str, &[&'static str], &[&'static str]) = (
    "[private key] --private=[private key] 'Imports a wallet for a specified private key'",
    &["address", "count", "network", "public key"],
    &[],
);
pub const PUBLIC: (&str, &[&'static str], &[&'static str]) = (
    "[public key] --public=[public key] 'Imports a partial wallet for a specified public key'",
    &["address", "count", "private key"],
    &[],
);

// HD

pub const DERIVATION_BITCOIN: (&str, &[&'static str], &[&'static str]) = (
    "[derivation] -d --derivation=[\"path\"] 'Generates an HD wallet for a specified derivation path (in quotes) [possible values: bip32, bip44, bip49, \"<custom path>\"]'",
    &[],
    &[],
);
pub const DERIVATION_ETHEREUM: (&str, &[&'static str], &[&'static str]) = (
    "[derivation] -d --derivation=[\"path\"] 'Generates an HD wallet for a specified derivation path (in quotes) [possible values: ethereum, keepkey, ledger-legacy, ledger-live, trezor, \"<custom path>\"]'",
    &[],
    &[],
);
pub const FORMAT_HD_BITCOIN: (&str, &[&'static str], &[&'static str]) = (
    "[format] -f --format=[format] 'Generates an HD wallet with a specified format'",
    &[],
    &["bech32", "legacy", "segwit"],
);
pub const NETWORK_HD_BITCOIN: (&str, &[&'static str], &[&'static str]) = (
    "[network] -n --network=[network] 'Generates an HD wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
);
pub const PASSWORD_HD: (&str, &[&'static str], &[&'static str]) = (
    "[password] -p --password=[password] 'Generates an HD wallet with a specified password'",
    &[],
    &[],
);
pub const WORD_COUNT: (&str, &[&'static str], &[&'static str]) = (
    "[word count] -w --word-count=[word count] 'Generates an HD wallet with a specified word count'",
    &[],
    &["12", "15", "18", "21", "24"],
);

// Import HD

pub const ACCOUNT: (&str, &[&'static str], &[&'static str]) = (
    "[account] -a --account=[account] 'Imports an HD wallet for a specified account number for bip44 and bip49 derivations'",
    &[],
    &[],
);
pub const CHAIN: (&str, &[&'static str], &[&'static str]) = (
    "[chain] -c --chain=[chain] 'Imports an HD wallet for a specified (external/internal) chain for bip44 and bip49 derivations'",
    &[],
    &["0", "1"],
);
pub const DERIVATION_IMPORT_BITCOIN: (&str, &[&'static str], &[&'static str]) = (
    "[derivation] -d --derivation=[\"path\"] 'Imports an HD wallet for a specified derivation path [possible values: bip32, bip44, bip49, \"<custom path>\"]'",
    &[],
    &[],
);
pub const DERIVATION_IMPORT_ETHEREUM: (&str, &[&'static str], &[&'static str]) = (
    "[derivation] -d --derivation=[\"path\"] 'Imports an HD wallet for a specified derivation path [possible values: ethereum, keepkey, ledger-legacy, ledger-live, trezor, \"<custom path>\"]'",
    &[],
    &[],
);
pub const EXTENDED_PUBLIC: (&str, &[&'static str], &[&'static str]) = (
    "[extended public] --extended-public=[extended public] 'Imports a partial HD wallet for a specified extended public key'",
    &["count", "extended private", "mnemonic", "password"],
    &[],
);
pub const EXTENDED_PRIVATE: (&str, &[&'static str], &[&'static str]) = (
    "[extended private] --extended-private=[extended private] 'Imports a partial HD wallet for a specified extended private key'",
    &["count", "extended public", "mnemonic", "password"],
    &[],
);
pub const FORMAT_IMPORT_HD_BITCOIN: (&str, &[&'static str], &[&'static str]) = (
    "[format] -f --format=[format] 'Imports an HD wallet with a specified format'",
    &[],
    &["bech32", "legacy", "segwit"],
);
pub const NETWORK_IMPORT_HD_BITCOIN: (&str, &[&'static str], &[&'static str]) = (
    "[network] -n --network=[network] 'Imports an HD wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
);
pub const INDEX: (&str, &[&'static str], &[&'static str]) = (
    "[index] -i --index=[index] 'Imports an HD wallet for a specified index'",
    &[],
    &[],
);
pub const MNEMONIC: (&str, &[&'static str], &[&'static str]) = (
    "[mnemonic] -m --mnemonic=[\"mnemonic\"] 'Imports an HD wallet for a specified mnemonic (in quotes)'",
    &["count", "extended private", "extended public"],
    &[],
);
pub const PASSWORD_IMPORT_HD: (&str, &[&'static str], &[&'static str]) = (
    "[password] -p --password=[password] 'Imports an HD wallet with a specified password'",
    &["extended private", "extended public"],
    &[],
);
