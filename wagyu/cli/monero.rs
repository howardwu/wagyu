use crate::model::Address;
use crate::model::Mnemonic;
use crate::model::PrivateKey;

use monero::address::Format as MoneroFormat;
use monero::{
    English as MoneroEnglish, Mainnet as MoneroMainnet, MoneroAddress, MoneroMnemonic, MoneroNetwork, MoneroPrivateKey,
    Testnet as MoneroTestnet,
};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display, str::FromStr};

pub struct MoneroCLI;

impl MoneroCLI {
    #[cfg_attr(tarpaulin, skip)]
    pub fn new<'a, 'b>() -> App<'a, 'b> {
        // Generic wallet arguments
        let arg_count = Arg::from_usage("[count] -c --count=[count] 'Generates a specified number of wallets'");
        let arg_json = Arg::from_usage("[json] -j --json 'Prints the generated wallet(s) in JSON format'");
        let arg_network =
            Arg::from_usage("[network] -n --network=[network] 'Generates a wallet for a specified network\n'")
                .possible_values(&["mainnet", "testnet"]);

        // Wallet import arguments
        let arg_import_private_key =
            Arg::from_usage("[import] -i --import=[private key] 'Generates a wallet for a specified private key'")
                .conflicts_with_all(&["count", "word_count"]);

        // Monero specific arguments
        let arg_integrated = Arg::from_usage("[integrated] --integrated=[PaymentID] 'Generate a wallet with an integrated address - Requires a paymentID'")
            .conflicts_with("subaddress");
        let arg_subaddress = Arg::from_usage("[subaddress] --subaddress=[Major Index][MinorIndex] 'Generate a wallet with a subaddress - Requires a major (account) and minor index'")
            .conflicts_with("integrated");

        let monero_mnemonic_subcommand = SubCommand::with_name("mnemonic")
            .about("Generate a wallet using mnemonics (include -h for more options)")
            .settings(&[AppSettings::DisableHelpSubcommand, AppSettings::DisableVersion])
            .arg(
                &arg_import_private_key
                    .to_owned()
                    .number_of_values(1)
                    .value_name("mnemonic")
                    .help("Generate a wallet by importing a mnemonic (in quotes)"),
            )
            .after_help("");

        SubCommand::with_name("monero")
            .about("Generates a Monero wallet (include -h for more options)")
            .settings(&[AppSettings::DisableHelpSubcommand, AppSettings::DisableVersion])
            .arg(&arg_count)
            .arg(&arg_json)
            .arg(&arg_network)
            .arg(&arg_integrated)
            .arg(&arg_subaddress)
            .subcommand(monero_mnemonic_subcommand.to_owned())
            .after_help("")
    }

    /// Handle all CLI arguments and flags for Monero
    #[cfg_attr(tarpaulin, skip)]
    pub fn parse(arguments: &ArgMatches) {
        let monero_address_type = match (arguments.values_of("subaddress"), arguments.value_of("integrated")) {
            (Some(indexes), None) => {
                let indexes: Vec<u32> = indexes
                    .into_iter()
                    .map(|index| index.to_owned().parse().unwrap())
                    .collect();
                MoneroFormat::Subaddress(indexes[0], indexes[1])
            }
            (None, Some(payment_id_string)) => {
                let mut payment_id = [0u8; 8];
                payment_id.copy_from_slice(&hex::decode(payment_id_string).unwrap());
                MoneroFormat::Integrated(payment_id)
            }
            (None, None) => MoneroFormat::Standard,
            _ => unreachable!(),
        };

        let network = match arguments.value_of("network") {
            Some("testnet") => "testnet",
            _ => "mainnet",
        };

        let mut monero_options = MoneroOptions {
            private_key: None,
            mnemonic_values: None,
            count: clap::value_t!(arguments.value_of("count"), usize).unwrap_or_else(|_e| 1),
            network: network.to_owned(),
            format: monero_address_type,
            json: arguments.is_present("json"),
        };

        match arguments.subcommand() {
            ("private_key", Some(private_key_matches)) => {
                monero_options.private_key = private_key_matches.value_of("import").map(|s| s.to_string());
            }
            ("mnemonic", Some(mnemonic_matches)) => {
                const DEFAULT_WORD_COUNT: u8 = 25;
                let password: String = mnemonic_matches.value_of("password").unwrap_or("").to_owned();
                let path = mnemonic_matches.value_of("path").map(|s| s.to_string());
                monero_options.mnemonic_values = match mnemonic_matches.value_of("import") {
                    Some(phrase) => Some(HdValues {
                        word_count: None,
                        mnemonic: Some(phrase.to_owned()),
                        password: Some(password),
                        path,
                    }),
                    None => Some(HdValues {
                        word_count: Some(DEFAULT_WORD_COUNT),
                        mnemonic: Some("".to_owned()),
                        password: Some(password),
                        path,
                    }),
                };
            }
            _ => {}
        };

        match network {
            "testnet" => Self::print::<MoneroTestnet>(monero_options),
            _ => Self::print::<MoneroMainnet>(monero_options),
        };
    }

    /// Generate the Monero wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print<N: MoneroNetwork>(monero_options: MoneroOptions) {
        for _ in 0..monero_options.count {
            let wallet = match monero_options.mnemonic_values.to_owned() {
                None => {
                    let private_key = match monero_options.private_key.to_owned() {
                        None => MoneroPrivateKey::<N>::new(&mut StdRng::from_entropy()).unwrap(),
                        Some(key) => MoneroPrivateKey::<N>::from_str(&key).unwrap(),
                    };

                    let address = MoneroAddress::from_private_key(&private_key, &monero_options.format).unwrap();

                    GenericWallet {
                        private_keys: Some(private_key.to_string()),
                        address: address.to_string(),
                        network: Some(monero_options.network.to_owned()),
                        format: Some(monero_options.format.to_string()),
                        ..Default::default()
                    }
                }
                Some(mnemonic_values) => {
                    type W = MoneroEnglish;
                    let mnemonic = match mnemonic_values.word_count {
                        Some(_) => MoneroMnemonic::<N, W>::new(&mut StdRng::from_entropy()).unwrap(),
                        None => MoneroMnemonic::<N, W>::from_phrase(&mnemonic_values.mnemonic.unwrap()).unwrap(),
                    };

                    let private_key = mnemonic.to_private_key(None).unwrap();
                    let address = MoneroAddress::from_private_key(&private_key, &monero_options.format).unwrap();

                    GenericWallet {
                        mnemonic: Some(mnemonic.to_string()),
                        private_keys: Some(private_key.to_string()),
                        address: address.to_string(),
                        network: Some(monero_options.network.to_owned()),
                        format: Some(monero_options.format.to_string()),
                        ..Default::default()
                    }
                }
            };

            if monero_options.json {
                println!("{}\n", serde_json::to_string_pretty(&wallet).unwrap())
            } else {
                println!("{}\n", wallet);
            };
        }
    }
}

/// Represents custom options for a Monero wallet
#[derive(Serialize, Clone, Debug)]
struct MoneroOptions {
    pub private_key: Option<String>,
    pub mnemonic_values: Option<HdValues>,
    pub count: usize,
    pub network: String,
    pub format: MoneroFormat,
    pub json: bool,
}

/// Represents values to derive HD wallets
#[derive(Serialize, Clone, Debug)]
struct HdValues {
    pub mnemonic: Option<String>,
    pub password: Option<String>,
    pub path: Option<String>,
    pub word_count: Option<u8>,
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
