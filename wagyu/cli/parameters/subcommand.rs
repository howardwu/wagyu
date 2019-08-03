use crate::cli::option;

// Format
// (name, about, options)

pub const HD: (&str, &str, &[(&str, &[&'static str], &[&'static str])]) = (
    "hd",
    "Generates an HD wallet (include -h for more options)",
    &[option::DERIVATION, option::PASSWORD_GENERATE, option::WORD_COUNT],
);

pub const IMPORT: (&str, &str, &[(&str, &[&'static str], &[&'static str])]) = (
    "import",
    "Imports a wallet (include -h for more options)",
    &[option::ADDRESS, option::PRIVATE, option::PUBLIC],
);

pub const IMPORT_HD: (&str, &str, &[(&str, &[&'static str], &[&'static str])]) = (
    "import-hd",
    "Imports an HD wallet (include -h for more options)",
    &[
        option::DERIVATION_IMPORT,
        option::EXTENDED_PUBLIC,
        option::EXTENDED_PRIVATE,
        option::INDEX,
        option::MNEMONIC,
        option::PASSWORD_IMPORT,
    ],
);
