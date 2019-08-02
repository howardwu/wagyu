use crate::model::Address;
use crate::model::ExtendedPrivateKey;

use zcash::address::Format as ZcashFormat;
use zcash::{
    Mainnet as ZcashMainnet, SpendingKey, Testnet as ZcashTestnet, ZcashAddress, ZcashDerivationPath,
    ZcashExtendedPrivateKey, ZcashNetwork, ZcashPrivateKey,
};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use rand::rngs::StdRng;
use rand::Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

pub struct ZcashCLI;

impl ZcashCLI {
    #[cfg_attr(tarpaulin, skip)]
    pub fn new<'a, 'b>() -> App<'a, 'b> {
        // Generic wallet arguments
        let arg_count = Arg::from_usage("[count] -c --count=[count] 'Generates a specified number of wallets'");
        let arg_json = Arg::from_usage("[json] -j --json 'Prints the generated wallet(s) in JSON format'");
        let arg_network =
            Arg::from_usage("[network] -n --network=[network] 'Generates a wallet for a specified network\n'")
                .possible_values(&["mainnet", "testnet"]);

        // Wallet import arguments
        let arg_derivation = Arg::from_usage(
            "[derivation] -d --derivation=[path] 'Generates an HD wallet for a specified derivation path'",
        );
        let arg_import_private_key =
            Arg::from_usage("[import] -i --import=[private key] 'Generates a wallet for a specified private key'")
                .conflicts_with_all(&["count", "word_count"]);

        // Zcash specific arguments
        let arg_shielded = Arg::from_usage("[shielded] --shielded 'Generate a wallet with a shielded address'");

        // Subcommands
        let extended_private_key_subcommand = SubCommand::with_name("extended_private_key")
            .about("Generate a wallet from an extended key (include -h for more options)")
            .settings(&[AppSettings::DisableHelpSubcommand, AppSettings::DisableVersion])
            .arg(
                &arg_import_private_key
                    .to_owned()
                    .number_of_values(1)
                    .value_name("extended private key")
                    .help("Generate a wallet by importing an extended private key"),
            )
            .arg(&arg_derivation)
            .after_help("");

        SubCommand::with_name("zcash")
            .about("Generates a Zcash wallet (include -h for more options)")
            .settings(&[AppSettings::DisableHelpSubcommand, AppSettings::DisableVersion])
            .arg(&arg_network)
            .arg(&arg_count)
            .arg(&arg_json)
            .arg(&arg_shielded)
            .subcommand(extended_private_key_subcommand.to_owned())
            .after_help("")
    }

    /// Handle all CLI arguments and flags for Zcash
    #[cfg_attr(tarpaulin, skip)]
    pub fn parse(arguments: &ArgMatches) {
        let zcash_address_type = if arguments.is_present("shielded") {
            ZcashFormat::Sapling(None)
        } else {
            ZcashFormat::P2PKH
        };

        let network = match arguments.value_of("network") {
            Some("testnet") => "testnet",
            _ => "mainnet",
        };

        let mut zcash_options = ZcashOptions {
            private_key: None,
            extended_private_key_values: None,
            count: clap::value_t!(arguments.value_of("count"), usize).unwrap_or_else(|_e| 1),
            network: network.to_owned(),
            format: zcash_address_type,
            json: arguments.is_present("json"),
        };

        match arguments.subcommand() {
            ("private_key", Some(private_key_matches)) => {
                zcash_options.private_key = private_key_matches.value_of("import").map(|s| s.to_string());
            }
            ("extended_private_key", Some(xpriv_matches)) => {
                let path = xpriv_matches.value_of("path").map(|s| s.to_string());
                let key = xpriv_matches.value_of("import").map(|s| s.to_string());
                zcash_options.extended_private_key_values = Some(ExtendedPrivateKeyValues { key, path });
            }
            _ => {}
        };

        match network {
            "testnet" => Self::print::<ZcashTestnet>(zcash_options),
            _ => Self::print::<ZcashMainnet>(zcash_options),
        };
    }

    /// Generate the Zcash wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print<N: ZcashNetwork>(zcash_options: ZcashOptions) {
        for _ in 0..zcash_options.count {
            let wallet = match zcash_options.extended_private_key_values.to_owned() {
                None => {
                    let private_key = match zcash_options.private_key.to_owned() {
                        None => {
                            let rng = &mut StdRng::from_entropy();
                            match zcash_options.format {
                                ZcashFormat::P2PKH => ZcashPrivateKey::<N>::new_p2pkh(rng).unwrap(),
                                _ => ZcashPrivateKey::<N>::new_sapling(rng).unwrap(),
                            }
                        }
                        Some(key) => ZcashPrivateKey::<N>::from_str(&key).unwrap(),
                    };

                    let address = ZcashAddress::<N>::from_private_key(&private_key, &zcash_options.format).unwrap();
                    let address_format = address.format().to_string();
                    let address_format: Vec<String> = address_format.split(" ").map(|s| s.to_owned()).collect();
                    let diversifier: Option<String> = match ZcashAddress::<N>::get_diversifier(&address.to_string()) {
                        Ok(diversifier) => Some(hex::encode(diversifier)),
                        _ => None,
                    };

                    match private_key.to_spending_key() {
                        SpendingKey::P2PKH(p2pkh_spending_key) => GenericWallet {
                            private_key: Some(private_key.to_string()),
                            address: address.to_string(),
                            diversifier,
                            format: Some(address_format[0].to_owned()),
                            network: Some(zcash_options.network.to_owned()),
                            compressed: Some(p2pkh_spending_key.is_compressed()),
                            ..Default::default()
                        },
                        _ => GenericWallet {
                            private_key: Some(private_key.to_string()),
                            address: address.to_string(),
                            diversifier,
                            format: Some(address_format[0].to_owned()),
                            network: Some(zcash_options.network.to_owned()),
                            ..Default::default()
                        },
                    }
                }
                Some(wallet_extended) => {
                    let extended_private_key = match (wallet_extended.key, wallet_extended.path) {
                        (None, None) => {
                            let seed: [u8; 32] = StdRng::from_entropy().gen();
                            ZcashExtendedPrivateKey::<N>::new_master(&seed, &zcash_options.format).unwrap()
                        }
                        (Some(key), None) => ZcashExtendedPrivateKey::<N>::from_str(&key).unwrap(),
                        (None, Some(path)) => {
                            let seed: [u8; 32] = StdRng::from_entropy().gen();
                            ZcashExtendedPrivateKey::<N>::new(
                                &seed,
                                &zcash_options.format,
                                &ZcashDerivationPath::from_str(&path).unwrap(),
                            )
                            .unwrap()
                        }
                        (Some(key), Some(path)) => ZcashExtendedPrivateKey::<N>::from_str(&key)
                            .unwrap()
                            .derive(&ZcashDerivationPath::from_str(&path).unwrap())
                            .unwrap(),
                    };

                    let private_key = extended_private_key.to_private_key();
                    let address = ZcashAddress::<N>::from_private_key(&private_key, &zcash_options.format).unwrap();
                    let address_format: Vec<String> =
                        address.format().to_string().split(" ").map(|s| s.to_owned()).collect();
                    let diversifier: Option<String> = match ZcashAddress::<N>::get_diversifier(&address.to_string()) {
                        Ok(diversifier) => Some(hex::encode(diversifier)),
                        _ => None,
                    };
                    match private_key.to_spending_key() {
                        SpendingKey::P2PKH(p2pkh_spending_key) => GenericWallet {
                            extended_private_key: Some(extended_private_key.to_string()),
                            private_key: Some(private_key.to_string()),
                            address: address.to_string(),
                            diversifier,
                            format: Some(address_format[0].to_owned()),
                            network: Some(zcash_options.network.to_owned()),
                            compressed: Some(p2pkh_spending_key.is_compressed()),
                            ..Default::default()
                        },
                        _ => GenericWallet {
                            private_key: Some(private_key.to_string()),
                            address: address.to_string(),
                            diversifier,
                            format: Some(address_format[0].to_owned()),
                            network: Some(zcash_options.network.to_owned()),
                            ..Default::default()
                        },
                    }
                }
            };

            if zcash_options.json {
                println!("{}\n", serde_json::to_string_pretty(&wallet).unwrap())
            } else {
                println!("{}\n", wallet);
            };
        }
    }
}

/// Represents custom options for a Zcash wallet
#[derive(Serialize, Clone, Debug)]
struct ZcashOptions {
    pub private_key: Option<String>,
    pub extended_private_key_values: Option<ExtendedPrivateKeyValues>,
    pub count: usize,
    pub network: String,
    pub format: ZcashFormat,
    pub json: bool,
}

/// Represents values to derive extended private keys
#[derive(Serialize, Clone, Debug)]
struct ExtendedPrivateKeyValues {
    pub key: Option<String>,
    pub path: Option<String>,
}

/// Represents a generic wallet to output
#[derive(Serialize, Debug, Default)]
struct GenericWallet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_private_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_keys: Option<String>,

    pub address: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub diversifier: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed: Option<bool>,
}

#[cfg_attr(tarpaulin, skip)]
impl Display for GenericWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = [
            match &self.path {
                Some(path) => format!("      Path:                 {}\n", path),
                _ => "".to_owned(),
            },
            match &self.mnemonic {
                Some(mnemonic) => format!("      Mnemonic:             {}\n", mnemonic),
                _ => "".to_owned(),
            },
            match &self.extended_private_key {
                Some(extended_private_key) => format!("      Extended private key: {}\n", extended_private_key),
                _ => "".to_owned(),
            },
            match &self.private_key {
                Some(private_key) => format!("      Private key:          {}\n", private_key),
                _ => "".to_owned(),
            },
            match &self.private_keys {
                Some(private_keys) => format!("      Private spend/view:   {}\n", private_keys),
                _ => "".to_owned(),
            },
            format!("      Address:              {}\n", self.address),
            match &self.diversifier {
                Some(diversifier) => format!("      Diversifier:          {}\n", diversifier),
                _ => "".to_owned(),
            },
            match &self.format {
                Some(format) => format!("      Format:               {}\n", format),
                _ => "".to_owned(),
            },
            match &self.network {
                Some(network) => format!("      Network:              {}\n", network),
                _ => "".to_owned(),
            },
            match &self.compressed {
                Some(compressed) => format!("      Compressed:           {}\n", compressed),
                _ => "".to_owned(),
            },
        ]
        .concat();

        // Removes final new line character
        let output = output[..output.len() - 1].to_owned();
        write!(f, "\n{}", output)
    }
}
