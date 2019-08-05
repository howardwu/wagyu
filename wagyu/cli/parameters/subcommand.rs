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
        option::FORMAT_HD_BITCOIN,
        option::NETWORK_HD_BITCOIN,
        option::PASSWORD_HD,
        option::WORD_COUNT,
    ],
    &[AppSettings::DisableHelpSubcommand, AppSettings::DisableVersion],
);

pub const HD_ETHEREUM: SubCommandType = (
    "hd",
    "Generates an HD wallet (include -h for more options)",
    &[
        option::COUNT,
        option::DERIVATION_ETHEREUM,
        option::PASSWORD_HD,
        option::WORD_COUNT,
    ],
    &[AppSettings::DisableHelpSubcommand, AppSettings::DisableVersion],
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
    &[AppSettings::DisableHelpSubcommand, AppSettings::DisableVersion],
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
        option::MNEMONIC_IMPORT_MONERO,
        option::NETWORK_IMPORT_MONERO,
        option::PRIVATE_SPEND_KEY_MONERO,
        option::PRIVATE_VIEW_KEY_MONERO,
        option::PUBLIC_SPEND_KEY_MONERO,
        option::PUBLIC_VIEW_KEY_MONERO,
        option::SUBADDRESS_IMPORT_MONERO
    ],
    &[
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
        option::FORMAT_IMPORT_HD_BITCOIN,
        option::NETWORK_IMPORT_HD_BITCOIN,
        option::INDEX,
        option::MNEMONIC,
        option::PASSWORD_IMPORT_HD,
    ],
    &[
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
        option::INDEX,
        option::MNEMONIC,
        option::PASSWORD_IMPORT_HD,
    ],
    &[
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
        option::INDEX,
    ],
    &[
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);
