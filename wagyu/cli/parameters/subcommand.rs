use crate::cli::{option, types::*};

use clap::AppSettings;

// Format
// (name, about, options, settings)

pub const HD_BITCOIN: SubCommandType = (
    "hd",
    "Generates an HD wallet (include -h for more options)",
    &[
        option::COUNT,
        option::DERIVATION_BITCOIN,
        option::LANGUAGE_HD,
        option::NETWORK_HD_BITCOIN,
        option::PASSWORD_HD,
        option::WORD_COUNT,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
    ],
);

pub const HD_ETHEREUM: SubCommandType = (
    "hd",
    "Generates an HD wallet (include -h for more options)",
    &[
        option::COUNT,
        option::DERIVATION_ETHEREUM,
        option::INDEX_HD,
        option::INDICES_HD,
        option::LANGUAGE_HD,
        option::PASSWORD_HD,
        option::WORD_COUNT,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
    ],
);

pub const HD_ZCASH: SubCommandType = (
    "hd",
    "Generates an HD wallet (include -h for more options)",
    &[
        option::COUNT,
        option::DERIVATION_ZCASH,
        option::DIVERSIFIER_IMPORT_ZCASH,
        option::NETWORK_HD_ZCASH,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
    ],
);

pub const HD_TRON: SubCommandType = (
    "hd",
    "Generates an HD wallet (include -h for more options)",
    &[
        option::COUNT,
        option::DERIVATION_TRON,
        option::NETWORK_TRON,
        option::INDEX_HD,
        option::INDICES_HD,
        option::LANGUAGE_HD,
        option::PASSWORD_HD,
        option::WORD_COUNT,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
    ],
);

pub const IMPORT_BITCOIN: SubCommandType = (
    "import",
    "Imports a wallet (include -h for more options)",
    &[
        option::ADDRESS,
        option::FORMAT_IMPORT_BITCOIN,
        option::NETWORK_IMPORT_BITCOIN,
        option::PRIVATE,
        option::PUBLIC,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const IMPORT_ETHEREUM: SubCommandType = (
    "import",
    "Imports a wallet (include -h for more options)",
    &[option::ADDRESS, option::PRIVATE, option::PUBLIC],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const IMPORT_MONERO: SubCommandType = (
    "import",
    "Imports a wallet (include -h for more options)",
    &[
        option::ADDRESS,
        option::INTEGRATED_IMPORT_MONERO,
        option::LANGUAGE_IMPORT_MONERO,
        option::MNEMONIC_IMPORT_MONERO,
        option::NETWORK_IMPORT_MONERO,
        option::PRIVATE_SPEND_KEY_MONERO,
        option::PRIVATE_VIEW_KEY_MONERO,
        option::PUBLIC_SPEND_KEY_MONERO,
        option::PUBLIC_VIEW_KEY_MONERO,
        option::SUBADDRESS_IMPORT_MONERO,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const IMPORT_ZCASH: SubCommandType = (
    "import",
    "Imports a wallet (include -h for more options)",
    &[
        option::ADDRESS,
        option::DIVERSIFIER_IMPORT_ZCASH,
        option::PRIVATE,
        option::PUBLIC,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const IMPORT_TRON: SubCommandType = (
    "import",
    "Imports a wallet (include -h for more options)",
    &[option::ADDRESS, option::PRIVATE, option::PUBLIC],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const IMPORT_HD_BITCOIN: SubCommandType = (
    "import-hd",
    "Imports an HD wallet (include -h for more options)",
    &[
        option::ACCOUNT,
        option::CHAIN,
        option::DERIVATION_IMPORT_BITCOIN,
        option::EXTENDED_PUBLIC,
        option::EXTENDED_PRIVATE,
        option::NETWORK_IMPORT_HD_BITCOIN,
        option::INDEX_IMPORT_HD,
        option::MNEMONIC,
        option::PASSWORD_IMPORT_HD,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const IMPORT_HD_ETHEREUM: SubCommandType = (
    "import-hd",
    "Imports an HD wallet (include -h for more options)",
    &[
        option::DERIVATION_IMPORT_ETHEREUM,
        option::EXTENDED_PUBLIC,
        option::EXTENDED_PRIVATE,
        option::INDEX_IMPORT_HD,
        option::INDICES_IMPORT_HD,
        option::MNEMONIC,
        option::PASSWORD_IMPORT_HD,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const IMPORT_HD_ZCASH: SubCommandType = (
    "import-hd",
    "Imports an HD wallet (include -h for more options)",
    &[
        option::ACCOUNT,
        option::DERIVATION_IMPORT_ZCASH,
        option::DIVERSIFIER_IMPORT_HD_ZCASH,
        option::EXTENDED_PUBLIC,
        option::EXTENDED_PRIVATE,
        option::INDEX_IMPORT_HD,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const IMPORT_HD_TRON: SubCommandType = (
    "import-hd",
    "Imports an HD wallet (include -h for more options)",
    &[
        option::DERIVATION_IMPORT_TRON,
        option::EXTENDED_PUBLIC,
        option::EXTENDED_PRIVATE,
        option::INDEX_IMPORT_HD,
        option::INDICES_IMPORT_HD,
        option::MNEMONIC,
        option::PASSWORD_IMPORT_HD,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const TRANSACTION_BITCOIN: SubCommandType = (
    "transaction",
    "Generates a Bitcoin transaction (include -h for more options)",
    &[
        option::CREATE_RAW_TRANSACTION_BITCOIN,
        option::SIGN_RAW_TRANSACTION_BITCOIN,
        option::TRANSACTION_LOCK_TIME_BITCOIN,
        option::TRANSACTION_VERSION_BITCOIN,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const TRANSACTION_ETHEREUM: SubCommandType = (
    "transaction",
    "Generates a Ethereum transaction (include -h for more options)",
    &[
        option::CREATE_RAW_TRANSACTION_ETHEREUM,
        option::SIGN_RAW_TRANSACTION_ETHEREUM,
        option::TRANSACTION_NETWORK_ETHEREUM,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const TRANSACTION_ZCASH: SubCommandType = (
    "transaction",
    "Generates a Zcash transaction (include -h for more options)",
    &[
        option::CREATE_RAW_TRANSACTION_ZCASH,
        option::SIGN_RAW_TRANSACTION_ZCASH,
        option::TRANSACTION_EXPIRY_HEIGHT_ZCASH,
        option::TRANSACTION_LOCK_TIME_ZCASH,
        option::TRANSACTION_VERSION_ZCASH,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const TRANSACTION_TRON: SubCommandType = (
    "transaction",
    "Generates a Tron transaction (include -h for more options)",
    &[
        option::CREATE_RAW_TRANSACTION_TRON,
        option::SIGN_RAW_TRANSACTION_TRON,
        option::TRANSACTION_NETWORK_TRON,
    ],
    &[
        AppSettings::ColoredHelp,
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);