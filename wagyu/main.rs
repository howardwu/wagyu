//! # Wagyu CLI
//!
//! A command-line tool to generate cryptocurrency wallets.

use wagyu::cli::bitcoin::BitcoinCLI;
use wagyu::cli::ethereum::EthereumCLI;
use wagyu::cli::monero::MoneroCLI;
use wagyu::cli::update::UpdateCLI;
use wagyu::cli::zcash::ZcashCLI;
use wagyu::cli::{CLIError, CLI};

use clap::{App, AppSettings, crate_version};

const VAPP_VERSION: &str = concat!("v", crate_version!());

#[cfg_attr(tarpaulin, skip)]
fn main() -> Result<(), CLIError> {
    let arguments = App::new("wagyu")
        .version(VAPP_VERSION)
        .about("Generate a wallet for Bitcoin, Ethereum, Monero, and Zcash")
        .author("Aleo <hello@aleo.org>")
        .settings(&[
            AppSettings::ColoredHelp,
            AppSettings::DisableHelpSubcommand,
            AppSettings::DisableVersion,
            AppSettings::SubcommandRequiredElseHelp,
        ])
        .subcommands(vec![
            BitcoinCLI::new(),
            EthereumCLI::new(),
            MoneroCLI::new(),
            ZcashCLI::new(),
            UpdateCLI::new(),
        ])
        .set_term_width(0)
        .get_matches();

    UpdateCLI::version_check();

    match arguments.subcommand() {
        ("bitcoin", Some(arguments)) => BitcoinCLI::print(BitcoinCLI::parse(arguments)?),
        ("ethereum", Some(arguments)) => EthereumCLI::print(EthereumCLI::parse(arguments)?),
        ("monero", Some(arguments)) => MoneroCLI::print(MoneroCLI::parse(arguments)?),
        ("zcash", Some(arguments)) => ZcashCLI::print(ZcashCLI::parse(arguments)?),
        ("update", Some(arguments)) => UpdateCLI::print(UpdateCLI::parse(arguments)?),
        _ => unreachable!(),
    }
}
