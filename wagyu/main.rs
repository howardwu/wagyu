//! # Wagyu CLI
//!
//! A command-line tool to generate cryptocurrency wallets.

use wagyu::cli::{
    bitcoin::BitcoinCLI, ethereum::EthereumCLI, monero::MoneroCLI, tron::TronCLI, zcash::ZcashCLI, CLIError, CLI,
};

use clap::{App, AppSettings};

#[cfg_attr(tarpaulin, skip)]
fn main() -> Result<(), CLIError> {
    let arguments = App::new("wagyu")
        .version("v0.6.3")
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
            TronCLI::new(),
            ZcashCLI::new(),
        ])
        .set_term_width(0)
        .get_matches();

    match arguments.subcommand() {
        ("bitcoin", Some(arguments)) => BitcoinCLI::print(BitcoinCLI::parse(arguments)?),
        ("ethereum", Some(arguments)) => EthereumCLI::print(EthereumCLI::parse(arguments)?),
        ("monero", Some(arguments)) => MoneroCLI::print(MoneroCLI::parse(arguments)?),
        ("tron", Some(arguments)) => TronCLI::print(TronCLI::parse(arguments)?),
        ("zcash", Some(arguments)) => ZcashCLI::print(ZcashCLI::parse(arguments)?),
        _ => unreachable!(),
    }
}
