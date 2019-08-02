//! # Wagyu CLI
//!
//! A command-line tool to generate cryptocurrency wallets.

use wagyu::cli::bitcoin::BitcoinCLI;
use wagyu::cli::ethereum::EthereumCLI;
use wagyu::cli::monero::MoneroCLI;
use wagyu::cli::zcash::ZcashCLI;
use wagyu::cli::CLI;

use clap::{App, AppSettings};

#[cfg_attr(tarpaulin, skip)]
fn main() {
    let arguments = App::new("wagyu")
        .version("v0.6.0")
        .about("Generate a wallet for Bitcoin, Ethereum, Monero, and Zcash")
        .author("Argus <team@argus.dev>")
        .settings(&[
            AppSettings::SubcommandRequiredElseHelp,
            AppSettings::DisableHelpSubcommand,
            AppSettings::DisableVersion,
        ])
        .subcommands(vec![
            BitcoinCLI::new(),
            EthereumCLI::new(),
            MoneroCLI::new(),
            ZcashCLI::new(),
        ])
        .after_help("")
        .get_matches();

    match arguments.subcommand() {
        ("bitcoin", Some(arguments)) => BitcoinCLI::print(BitcoinCLI::parse(arguments)),
        ("ethereum", Some(arguments)) => EthereumCLI::parse(arguments),
        ("monero", Some(arguments)) => MoneroCLI::parse(arguments),
        ("zcash", Some(arguments)) => ZcashCLI::parse(arguments),
        _ => unreachable!(),
    };
}
