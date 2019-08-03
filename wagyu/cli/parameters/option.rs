// Format
// (argument, conflicts, possible_values)

// Global

pub const COUNT: (&str, &[&'static str], &[&'static str]) = (
    "[count] -c --count=[count] 'Generates a specified number of wallets'",
    &[],
    &[],
);
pub const BITCOIN_FORMAT: (&str, &[&'static str], &[&'static str]) = (
    "[format] -f --format=[format] 'Generates a wallet with a specified format'",
    &[],
    &["bech32", "legacy", "segwit"],
);
pub const BITCOIN_NETWORK: (&str, &[&'static str], &[&'static str]) = (
    "[network] -n --network=[network] 'Generates a wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
);
pub const MONERO_NETWORK: (&str, &[&'static str], &[&'static str]) = (
    "[network] -n --network=[network] 'Generates a wallet for a specified network'",
    &[],
    &["mainnet", "stagenet", "testnet"],
);
pub const ZCASH_NETWORK: (&str, &[&'static str], &[&'static str]) = (
    "[network] -n --network=[network] 'Generates a wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
);

// Import

pub const ADDRESS: (&str, &[&'static str], &[&'static str]) = (
    "[address] --address=[address] 'Imports a partial wallet for a specified address'",
    &["count", "private key", "public key"],
    &[],
);
pub const PRIVATE: (&str, &[&'static str], &[&'static str]) = (
    "[private key] --private=[private key] 'Imports a wallet for a specified private key'",
    &["address", "count", "public key"],
    &[],
);
pub const PUBLIC: (&str, &[&'static str], &[&'static str]) = (
    "[public key] --public=[public key] 'Imports a partial wallet for a specified public key'",
    &["address", "count", "private key"],
    &[],
);

// HD

pub const DERIVATION: (&str, &[&'static str], &[&'static str]) = (
    "[derivation] -d --derivation=[path] 'Generates an HD wallet for a specified derivation path'",
    &[],
    &[],
);
pub const PASSWORD_GENERATE: (&str, &[&'static str], &[&'static str]) = (
    "[password] -p --password=[password] 'Generates an HD wallet with a specified password'",
    &[],
    &[],
);
pub const WORD_COUNT: (&str, &[&'static str], &[&'static str]) = (
    "[word count] -w --word-count=[word count] 'Generates an HD wallet with a specified word count'",
    &[],
    &["12", "15", "18", "21", "24"],
);

// HD Import

pub const DERIVATION_IMPORT: (&str, &[&'static str], &[&'static str]) = (
    "[derivation] -d --derivation=[path] 'Imports an HD wallet for a specified derivation path'",
    &[],
    &[],
);
pub const EXTENDED_PUBLIC: (&str, &[&'static str], &[&'static str]) = (
    "[extended public] --extended-public=[extended public] 'Imports a partial HD wallet for a specified extended public key'",
    &["count", "extended private", "mnemonic"],
    &[],
);
pub const EXTENDED_PRIVATE: (&str, &[&'static str], &[&'static str]) = (
    "[extended private] --extended-private=[extended private] 'Imports a partial HD wallet for a specified extended private key'",
    &["count", "extended public", "mnemonic"],
    &[],
);
pub const INDEX: (&str, &[&'static str], &[&'static str]) = (
    "[index] --index=[index] 'Imports an HD wallet for a specified index'",
    &[],
    &[],
);
pub const MNEMONIC: (&str, &[&'static str], &[&'static str]) = (
    "[mnemonic] --mnemonic=[mnemonic] 'Imports an HD wallet for a specified mnemonic (in quotes)'",
    &["count", "extended private", "extended public"],
    &[],
);
pub const PASSWORD_IMPORT: (&str, &[&'static str], &[&'static str]) = (
    "[password] -p --password=[password] 'Imports an HD wallet with a specified password'",
    &[],
    &[],
);
