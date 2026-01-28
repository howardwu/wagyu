use crate::model::{
    AddressError, AmountError, DerivationPathError, ExtendedPrivateKeyError, ExtendedPublicKeyError, MnemonicError,
    PrivateKeyError, PublicKeyError, TransactionError,
};

pub mod bitcoin;
pub mod ethereum;
pub mod monero;
pub mod tron;

pub mod parameters;
pub use self::parameters::*;

use types::*;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

use crate::model::no_std::{format, String, Vec};

pub trait CLI {
    type Options;

    const NAME: NameType;
    const ABOUT: AboutType;
    const FLAGS: &'static [FlagType];
    const OPTIONS: &'static [OptionType];
    const SUBCOMMANDS: &'static [SubCommandType];

    #[cfg_attr(tarpaulin, skip)]
    #[allow(clippy::new_ret_no_self)]
    fn new<'a, 'b>() -> App<'a, 'b> {
        let flags = &Self::FLAGS
            .iter()
            .map(|a| Arg::from_usage(a).global(true))
            .collect::<Vec<Arg<'static, 'static>>>();
        let options = &Self::OPTIONS
            .iter()
            .map(|a| match !a.2.is_empty() {
                true => Arg::from_usage(a.0)
                    .conflicts_with_all(a.1)
                    .possible_values(a.2)
                    .requires_all(a.3),
                false => Arg::from_usage(a.0).conflicts_with_all(a.1).requires_all(a.3),
            })
            .collect::<Vec<Arg<'static, 'static>>>();
        let subcommands = Self::SUBCOMMANDS
            .iter()
            .map(|s| {
                SubCommand::with_name(s.0)
                    .about(s.1)
                    .args(
                        &s.2.iter()
                            .map(|a| match !a.2.is_empty() {
                                true => Arg::from_usage(a.0)
                                    .conflicts_with_all(a.1)
                                    .possible_values(a.2)
                                    .requires_all(a.3),
                                false => Arg::from_usage(a.0).conflicts_with_all(a.1).requires_all(a.3),
                            })
                            .collect::<Vec<Arg<'static, 'static>>>(),
                    )
                    .settings(s.3)
            })
            .collect::<Vec<App<'static, 'static>>>();

        SubCommand::with_name(Self::NAME)
            .about(Self::ABOUT)
            .settings(&[
                AppSettings::ColoredHelp,
                AppSettings::DisableHelpSubcommand,
                AppSettings::DisableVersion,
            ])
            .args(flags)
            .args(options)
            .subcommands(subcommands)
    }

    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Result<Self::Options, CLIError>;

    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) -> Result<(), CLIError>;
}

#[derive(Debug, thiserror::Error)]
pub enum CLIError {
    #[error("{0}")]
    AddressError(#[from] AddressError),

    #[error("{0}")]
    AmountError(#[from] AmountError),

    #[error("{0}: {1}")]
    Crate(&'static str, String),

    #[error("{0}")]
    DerivationPathError(#[from] DerivationPathError),

    #[error("{0}")]
    ExtendedPrivateKeyError(#[from] ExtendedPrivateKeyError),

    #[error("{0}")]
    ExtendedPublicKeyError(#[from] ExtendedPublicKeyError),

    #[error("invalid derived mnemonic for a given private spend key")]
    InvalidMnemonicForPrivateSpendKey,

    #[error("{0}")]
    PrivateKeyError(#[from] PrivateKeyError),

    #[error("{0}")]
    PublicKeyError(#[from] PublicKeyError),

    #[error("{0}")]
    MnemonicError(#[from] MnemonicError),

    #[error("{0}")]
    TransactionError(#[from] TransactionError),

    #[error("unsupported mnemonic language")]
    UnsupportedLanguage,
}

impl From<core::num::ParseIntError> for CLIError {
    fn from(error: core::num::ParseIntError) -> Self {
        CLIError::Crate("parse_int", format!("{:?}", error))
    }
}

impl From<hex::FromHexError> for CLIError {
    fn from(error: hex::FromHexError) -> Self {
        CLIError::Crate("hex", format!("{:?}", error))
    }
}

impl From<serde_json::error::Error> for CLIError {
    fn from(error: serde_json::error::Error) -> Self {
        CLIError::Crate("serde_json", format!("{:?}", error))
    }
}
