use crate::cli::{option, types::*};

use clap::AppSettings;

// Format
// (name, about, options, settings)

pub const HD_BITCOIN: (NameType, AboutType, &'static [OptionType], &'static [AppSettings]) = (
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

pub const HD_ETHEREUM: (NameType, AboutType, &'static [OptionType], &'static [AppSettings]) = (
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

pub const IMPORT_BITCOIN: (NameType, AboutType, &'static [OptionType], &'static [AppSettings]) = (
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

pub const IMPORT_ETHEREUM: (NameType, AboutType, &'static [OptionType], &'static [AppSettings]) = (
    "import",
    "Imports a wallet (include -h for more options)",
    &[
        option::ADDRESS,
        option::PRIVATE,
        option::PUBLIC,
    ],
    &[
        AppSettings::DisableHelpSubcommand,
        AppSettings::DisableVersion,
        AppSettings::ArgRequiredElseHelp,
    ],
);

pub const IMPORT_HD_BITCOIN: (NameType, AboutType, &'static [OptionType], &'static [AppSettings]) = (
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

pub const IMPORT_HD_ETHEREUM: (NameType, AboutType, &'static [OptionType], &'static [AppSettings]) = (
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
