use crate::model::{
    AddressError, AmountError, DerivationPathError, ExtendedPrivateKeyError, ExtendedPublicKeyError, MnemonicError,
    PrivateKeyError, PublicKeyError, TransactionError,
};

pub mod bitcoin;
pub mod ethereum;
pub mod monero;
pub mod zcash;

pub mod parameters;
pub use self::parameters::*;

use types::*;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

pub trait CLI {
    type Options;

    const NAME: NameType;
    const ABOUT: AboutType;
    const FLAGS: &'static [FlagType];
    const OPTIONS: &'static [OptionType];
    const SUBCOMMANDS: &'static [SubCommandType];

    #[cfg_attr(tarpaulin, skip)]
    fn new<'a, 'b>() -> App<'a, 'b> {
        let flags = &Self::FLAGS
            .iter()
            .map(|a| Arg::from_usage(a).global(true))
            .collect::<Vec<Arg<'static, 'static>>>();
        let options = &Self::OPTIONS
            .iter()
            .map(|a| match a.2.len() > 0 {
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
                            .map(|a| match a.2.len() > 0 {
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

#[derive(Debug, Fail)]
pub enum CLIError {
    #[fail(display = "{}", _0)]
    AddressError(AddressError),

    #[fail(display = "{}", _0)]
    AmountError(AmountError),

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "{}", _0)]
    DerivationPathError(DerivationPathError),

    #[fail(display = "{}", _0)]
    ExtendedPrivateKeyError(ExtendedPrivateKeyError),

    #[fail(display = "{}", _0)]
    ExtendedPublicKeyError(ExtendedPublicKeyError),

    #[fail(display = "invalid derived mnemonic for a given private spend key")]
    InvalidMnemonicForPrivateSpendKey,

    #[fail(display = "{}", _0)]
    PrivateKeyError(PrivateKeyError),

    #[fail(display = "{}", _0)]
    PublicKeyError(PublicKeyError),

    #[fail(display = "{}", _0)]
    MnemonicError(MnemonicError),

    #[fail(display = "{}", _0)]
    TransactionError(TransactionError),

    #[fail(display = "unsupported mnemonic language")]
    UnsupportedLanguage,
}

impl From<AddressError> for CLIError {
    fn from(error: AddressError) -> Self {
        CLIError::AddressError(error)
    }
}

impl From<AmountError> for CLIError {
    fn from(error: AmountError) -> Self {
        CLIError::AmountError(error)
    }
}

impl From<core::num::ParseIntError> for CLIError {
    fn from(error: core::num::ParseIntError) -> Self {
        CLIError::Crate("parse_int", format!("{:?}", error))
    }
}

impl From<DerivationPathError> for CLIError {
    fn from(error: DerivationPathError) -> Self {
        CLIError::DerivationPathError(error)
    }
}

impl From<ExtendedPrivateKeyError> for CLIError {
    fn from(error: ExtendedPrivateKeyError) -> Self {
        CLIError::ExtendedPrivateKeyError(error)
    }
}

impl From<ExtendedPublicKeyError> for CLIError {
    fn from(error: ExtendedPublicKeyError) -> Self {
        CLIError::ExtendedPublicKeyError(error)
    }
}

impl From<hex::FromHexError> for CLIError {
    fn from(error: hex::FromHexError) -> Self {
        CLIError::Crate("hex", format!("{:?}", error))
    }
}

impl From<MnemonicError> for CLIError {
    fn from(error: MnemonicError) -> Self {
        CLIError::MnemonicError(error)
    }
}

impl From<PrivateKeyError> for CLIError {
    fn from(error: PrivateKeyError) -> Self {
        CLIError::PrivateKeyError(error)
    }
}

impl From<PublicKeyError> for CLIError {
    fn from(error: PublicKeyError) -> Self {
        CLIError::PublicKeyError(error)
    }
}

impl From<serde_json::error::Error> for CLIError {
    fn from(error: serde_json::error::Error) -> Self {
        CLIError::Crate("serde_json", format!("{:?}", error))
    }
}

impl From<TransactionError> for CLIError {
    fn from(error: TransactionError) -> Self {
        CLIError::TransactionError(error)
    }
}
