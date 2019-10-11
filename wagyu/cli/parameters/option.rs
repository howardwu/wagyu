use crate::cli::types::*;

// Format
// (argument, conflicts, possible_values, requires)

// Global

pub const COUNT: OptionType = (
    "[count] -c --count=[count] 'Generates a specified number of wallets'",
    &[],
    &[],
    &[],
);
pub const DIVERSIFIER_ZCASH: OptionType = (
    "[diversifier] --diversifier=[diversifier] 'Generates a wallet with a specified Sapling address diversifier'",
    &[],
    &[],
    &[],
);
pub const FORMAT_BITCOIN: OptionType = (
    "[format] -f --format=[format] 'Generates a wallet with a specified format'",
    &[],
    &["bech32", "legacy", "segwit"],
    &[],
);
pub const FORMAT_ZCASH: OptionType = (
    "[format] -f --format=[format] 'Generates a wallet with a specified format'",
    &[],
    &["sapling", "sprout", "transparent"],
    &[],
);
pub const INTEGRATED_MONERO: OptionType = (
    "[integrated] -i --integrated=[PaymentID] 'Generates a wallet with a specified payment ID'",
    &["subaddress"],
    &[],
    &[],
);
pub const LANGUAGE_MONERO: OptionType = (
    "[language] -l --language=[language] 'Generates a wallet with a specified language'",
    &[],
    &[
        "chinese_simplified",
        "dutch",
        "english",
        "esperanto",
        "french",
        "german",
        "italian",
        "japanese",
        "lojban",
        "portuguese",
        "russian",
        "spanish",
    ],
    &[],
);
pub const NETWORK_BITCOIN: OptionType = (
    "[network] -n --network=[network] 'Generates a wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
    &[],
);
pub const NETWORK_MONERO: OptionType = (
    "[network] -n --network=[network] 'Generates a wallet for a specified network'",
    &[],
    &["mainnet", "stagenet", "testnet"],
    &[],
);
pub const NETWORK_ZCASH: OptionType = (
    "[network] -n --network=[network] 'Generates a wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
    &[],
);
pub const SUBADDRESS_MONERO: OptionType = (
    "[subaddress] -s --subaddress=[Major Index][Minor Index] 'Generates a wallet with a specified major and minor index'",
    &["address", "integrated", "private view"],
    &[],
    &[],
);

// Import

pub const ADDRESS: OptionType = (
    "[address] --address=[address] 'Imports a partial wallet for a specified address'",
    &["count", "network", "private", "public"],
    &[],
    &[],
);
pub const DIVERSIFIER_IMPORT_ZCASH: OptionType = (
    "[diversifier] --diversifier=[diversifier] 'Imports a wallet with a specified Sapling address diversifier'",
    &["address"],
    &[],
    &[],
);
pub const FORMAT_IMPORT_BITCOIN: OptionType = (
    "[format] -f --format=[format] 'Imports a wallet with a specified format'",
    &[],
    &["bech32", "legacy", "segwit"],
    &[],
);
pub const INTEGRATED_IMPORT_MONERO: OptionType = (
    "[integrated] -i --integrated=[PaymentID] 'Imports a wallet with a specified payment ID'",
    &["address", "private view", "subaddress"],
    &[],
    &[],
);
pub const LANGUAGE_IMPORT_MONERO: OptionType = (
    "[language] -l --language=[language] 'Imports a wallet with a specified mnemonic language (requires private spend key)'",
    &[],
    &["chinese_simplified", "dutch", "english", "esperanto", "french", "german", "italian", "japanese", "lojban", "portuguese", "russian", "spanish"],
    &["private spend"],
);
pub const MNEMONIC_IMPORT_MONERO: OptionType = (
    "[mnemonic] -m --mnemonic=[\"mnemonic\"] 'Imports a wallet for a specified mnemonic (in quotes)'",
    &[
        "address",
        "count",
        "public spend",
        "public view",
        "private spend",
        "private view",
    ],
    &[],
    &[],
);
pub const NETWORK_IMPORT_BITCOIN: OptionType = (
    "[network] -n --network=[network] 'Imports a wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
    &[],
);
pub const NETWORK_IMPORT_MONERO: OptionType = (
    "[network] -n --network=[network] 'Imports a wallet for a specified network'",
    &[],
    &["mainnet", "stagenet", "testnet"],
    &[],
);
pub const PRIVATE: OptionType = (
    "[private] --private=[private key] 'Imports a wallet for a specified private key'",
    &["address", "count", "network", "public"],
    &[],
    &[],
);
pub const PRIVATE_SPEND_KEY_MONERO: OptionType = (
    "[private spend] --private-spend=[private spend key] 'Imports a wallet for a specified private spend key'",
    &["address", "count", "public spend", "public view", "private view"],
    &[],
    &[],
);
pub const PRIVATE_VIEW_KEY_MONERO: OptionType = (
    "[private view] --private-view=[private view key] 'Imports a partial wallet for a specified private view key'",
    &["address", "count", "public spend", "public view", "private spend"],
    &[],
    &[],
);
pub const PUBLIC: OptionType = (
    "[public] --public=[public key] 'Imports a partial wallet for a specified public key'",
    &["address", "count", "private"],
    &[],
    &[],
);
pub const PUBLIC_SPEND_KEY_MONERO: OptionType = (
    "[public spend] --public-spend=[public spend key] 'Imports a partial wallet for a specified public spend key'",
    &["address", "count"],
    &[],
    &["public view"],
);
pub const PUBLIC_VIEW_KEY_MONERO: OptionType = (
    "[public view] --public-view=[public view key] 'Imports a partial wallet for a specified public view key'",
    &["address", "count"],
    &[],
    &["public spend"],
);
pub const SUBADDRESS_IMPORT_MONERO: OptionType = (
    "[subaddress] -s --subaddress=[Major Index][Minor Index] 'Imports a wallet with a specified major and minor index'",
    &["integrated"],
    &[],
    &[],
);

// HD

pub const DERIVATION_BITCOIN: OptionType = (
    "[derivation] -d --derivation=[\"path\"] 'Generates an HD wallet for a specified derivation path (in quotes) [possible values: bip32, bip44, bip49, \"<custom path>\"]'",
    &[],
    &[],
    &[],
);
pub const DERIVATION_ETHEREUM: OptionType = (
    "[derivation] -d --derivation=[\"path\"] 'Generates an HD wallet for a specified derivation path (in quotes) [possible values: ethereum, keepkey, ledger-legacy, ledger-live, trezor, \"<custom path>\"]'",
    &[],
    &[],
    &[],
);
pub const DERIVATION_ZCASH: OptionType = (
    "[derivation] -d --derivation=[\"path\"] 'Generates an HD wallet for a specified derivation path (in quotes) [possible values: zip32, \"<custom path>\"]'",
    &[],
    &[],
    &[],
);
pub const DIVERSIFIER_HD_ZCASH: OptionType = (
    "[diversifier] --diversifier=[diversifier] 'Generates an HD wallet with a specified Sapling address diversifier'",
    &[],
    &[],
    &[],
);
pub const LANGUAGE_HD: OptionType = (
    "[language] -l --language=[language] 'Generates an HD wallet with a specified language'",
    &[],
    &[
        "chinese_simplified",
        "chinese_traditional",
        "english",
        "french",
        "italian",
        "japanese",
        "korean",
        "spanish",
    ],
    &[],
);
pub const NETWORK_HD_BITCOIN: OptionType = (
    "[network] -n --network=[network] 'Generates an HD wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
    &[],
);
pub const NETWORK_HD_ZCASH: OptionType = (
    "[network] -n --network=[network] 'Generates an HD wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
    &[],
);
pub const PASSWORD_HD: OptionType = (
    "[password] -p --password=[password] 'Generates an HD wallet with a specified password'",
    &[],
    &[],
    &[],
);
pub const WORD_COUNT: OptionType = (
    "[word count] -w --word-count=[word count] 'Generates an HD wallet with a specified word count'",
    &[],
    &["12", "15", "18", "21", "24"],
    &[],
);

// Import HD

pub const ACCOUNT: OptionType = (
    "[account] -a --account=[account] 'Imports an HD wallet for a specified account number for bip44 and bip49 derivations'",
    &[],
    &[],
    &[],
);
pub const CHAIN: OptionType = (
    "[chain] -c --chain=[chain] 'Imports an HD wallet for a specified (external/internal) chain for bip44 and bip49 derivations'",
    &[],
    &["0", "1"],
    &[],
);
pub const DERIVATION_IMPORT_BITCOIN: OptionType = (
    "[derivation] -d --derivation=[\"path\"] 'Imports an HD wallet for a specified derivation path (in quotes) [possible values: bip32, bip44, bip49, \"<custom path>\"]'",
    &[],
    &[],
    &[],
);
pub const DERIVATION_IMPORT_ETHEREUM: OptionType = (
    "[derivation] -d --derivation=[\"path\"] 'Imports an HD wallet for a specified derivation path (in quotes) [possible values: ethereum, keepkey, ledger-legacy, ledger-live, trezor, \"<custom path>\"]'",
    &[],
    &[],
    &[],
);
pub const DERIVATION_IMPORT_ZCASH: OptionType = (
    "[derivation] -d --derivation=[\"path\"] 'Imports an HD wallet for a specified derivation path (in quotes) [possible values: zip32, \"<custom path>\"]'",
    &[],
    &[],
    &[],
);
pub const DIVERSIFIER_IMPORT_HD_ZCASH: OptionType = (
    "[diversifier] --diversifier=[diversifier] 'Imports an HD wallet with a specified Sapling address diversifier'",
    &[],
    &[],
    &[],
);
pub const EXTENDED_PUBLIC: OptionType = (
    "[extended public] --extended-public=[extended public] 'Imports a partial HD wallet for a specified extended public key'",
    &["account", "count", "extended private", "index", "mnemonic", "password"],
    &[],
    &[],
);
pub const EXTENDED_PRIVATE: OptionType = (
    "[extended private] --extended-private=[extended private] 'Imports a partial HD wallet for a specified extended private key'",
    &["count", "extended public", "mnemonic", "password"],
    &[],
    &[],
);

pub const NETWORK_IMPORT_HD_BITCOIN: OptionType = (
    "[network] -n --network=[network] 'Imports an HD wallet for a specified network'",
    &[],
    &["mainnet", "testnet"],
    &[],
);
pub const INDEX: OptionType = (
    "[index] -i --index=[index] 'Imports an HD wallet for a specified index'",
    &[],
    &[],
    &[],
);
pub const MNEMONIC: OptionType = (
    "[mnemonic] -m --mnemonic=[\"mnemonic\"] 'Imports an HD wallet for a specified mnemonic (in quotes)'",
    &["count", "extended private", "extended public"],
    &[],
    &[],
);
pub const PASSWORD_IMPORT_HD: OptionType = (
    "[password] -p --password=[password] 'Imports an HD wallet with a specified password'",
    &["extended private", "extended public"],
    &[],
    &[],
);
