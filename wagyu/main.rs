//! # Wagyu CLI
//!
//! A command-line tool to generate cryptocurrency wallets.

use wagyu::cli::bitcoin::BitcoinCLI;
use wagyu::cli::ethereum::EthereumCLI;
use wagyu::cli::monero::MoneroCLI;
use wagyu::cli::zcash::ZcashCLI;
use wagyu::cli::{CLIError, CLI};
use wagyu::remote_update;

use clap::{App, AppSettings, SubCommand, crate_version};

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
            SubCommand::with_name("update").about("Auto update to latest version"),
        ])
        .set_term_width(0)
        .get_matches();

    let latest_version = remote_update::version_check();

    match arguments.subcommand() {
        ("bitcoin", Some(arguments)) => BitcoinCLI::print(BitcoinCLI::parse(arguments)?),
        ("ethereum", Some(arguments)) => EthereumCLI::print(EthereumCLI::parse(arguments)?),
        ("monero", Some(arguments)) => MoneroCLI::print(MoneroCLI::parse(arguments)?),
        ("zcash", Some(arguments)) => ZcashCLI::print(ZcashCLI::parse(arguments)?),
        ("update", Some(_)) => {
            if latest_version != "" {
                remote_update::run();
            }
            Ok(())
        },
        _ => unreachable!(),
    }
}
