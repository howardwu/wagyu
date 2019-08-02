use crate::model::Address;
use crate::model::ExtendedPrivateKey;
use crate::model::MnemonicExtended;
use crate::model::PrivateKey;

use ethereum::{
    English as EthereumEnglish, EthereumAddress, EthereumDerivationPath, EthereumMnemonic, EthereumPrivateKey,
};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display, marker::PhantomData, str::FromStr};

pub struct EthereumCLI;

impl EthereumCLI {
    #[cfg_attr(tarpaulin, skip)]
    pub fn new<'a, 'b>() -> App<'a, 'b> {
        // Generic wallet arguments
        let arg_count = Arg::from_usage("[count] -c --count=[count] 'Generates a specified number of wallets'");
        let arg_json = Arg::from_usage("[json] -j --json 'Prints the generated wallet(s) in JSON format'");

        // Wallet import arguments
        let arg_derivation = Arg::from_usage(
            "[derivation] -d --derivation=[path] 'Generates an HD wallet for a specified derivation path'",
        );
        let arg_import_private_key =
            Arg::from_usage("[import] -i --import=[private key] 'Generates a wallet for a specified private key'")
                .conflicts_with_all(&["count", "word_count"]);
        let arg_import_mnemonic = Arg::from_usage(
            "[import] -i --import=[mnemonic] 'Generates an HD wallet for a specified mnemonic (in quotes)'",
        )
        .conflicts_with_all(&["count", "word_count"]);
        let arg_password =
            Arg::from_usage("[password] -p --password=[password] 'Generates an HD wallet with a specified password'");
        let arg_word_count = Arg::from_usage(
            "[word count] -w --word_count=[word count] 'Generates an HD wallet with a specified word count'",
        )
        .conflicts_with("import");

        // Subcommands
        let hd_subcommand = SubCommand::with_name("hd")
            .about("Generates an HD wallet (include -h for more options)")
            .settings(&[AppSettings::DisableHelpSubcommand, AppSettings::DisableVersion])
            .arg(&arg_derivation)
            .arg(&arg_import_mnemonic)
            .arg(&arg_password)
            .after_help("");

        SubCommand::with_name("ethereum")
            .about("Generates an Ethereum wallet (include -h for more options)")
            .settings(&[AppSettings::DisableHelpSubcommand, AppSettings::DisableVersion])
            .arg(&arg_count)
            .arg(&arg_json)
            .subcommand(hd_subcommand.to_owned().arg(&arg_word_count))
            .after_help("")
    }

    /// Handle all CLI arguments and flags for Ethereum
    #[cfg_attr(tarpaulin, skip)]
    pub fn parse(arguments: &ArgMatches) {
        let mut ethereum_options = EthereumOptions {
            private_key: None,
            mnemonic_values: None,
            count: clap::value_t!(arguments.value_of("count"), usize).unwrap_or_else(|_e| 1),
            json: arguments.is_present("json"),
        };

        match arguments.subcommand() {
            ("private_key", Some(private_key_matches)) => {
                ethereum_options.private_key = private_key_matches.value_of("import").map(|s| s.to_string());
            }
            ("mnemonic", Some(mnemonic_matches)) => {
                const DEFAULT_WORD_COUNT: u8 = 12;
                let password: String = mnemonic_matches.value_of("password").unwrap_or("").to_owned();
                let path = mnemonic_matches.value_of("path").map(|s| s.to_string());
                ethereum_options.mnemonic_values = match (
                    mnemonic_matches.value_of("import"),
                    mnemonic_matches.value_of("word count"),
                ) {
                    (Some(phrase), _) => Some(HdValues {
                        word_count: None,
                        mnemonic: Some(phrase.to_owned()),
                        password: Some(password),
                        path,
                    }),
                    (None, Some(word_count)) => Some(HdValues {
                        word_count: Some(word_count.parse().unwrap()),
                        mnemonic: Some("".to_owned()),
                        password: Some(password),
                        path,
                    }),
                    (None, None) => Some(HdValues {
                        word_count: Some(DEFAULT_WORD_COUNT),
                        mnemonic: Some("".to_owned()),
                        password: Some(password),
                        path,
                    }),
                };
            }
            _ => {}
        };

        Self::print(ethereum_options);
    }

    /// Generate the Ethereum wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(ethereum_options: EthereumOptions) {
        for _ in 0..ethereum_options.count {
            let wallet = match ethereum_options.mnemonic_values.to_owned() {
                None => {
                    let private_key = match ethereum_options.private_key.to_owned() {
                        None => EthereumPrivateKey::new(&mut StdRng::from_entropy()).unwrap(),
                        Some(key) => EthereumPrivateKey::from_str(&key).unwrap(),
                    };

                    let address = EthereumAddress::from_private_key(&private_key, &PhantomData).unwrap();

                    GenericWallet {
                        private_key: Some(private_key.to_string()),
                        address: address.to_string(),
                        ..Default::default()
                    }
                }
                Some(mnemonic_values) => {
                    type W = EthereumEnglish;
                    let mnemonic = match mnemonic_values.word_count {
                        Some(word_count) => {
                            EthereumMnemonic::<W>::new(word_count, &mut StdRng::from_entropy()).unwrap()
                        }
                        None => EthereumMnemonic::<W>::from_phrase(&mnemonic_values.mnemonic.unwrap()).unwrap(),
                    };

                    let master_xpriv_key = mnemonic
                        .to_extended_private_key(Some(&mnemonic_values.password.unwrap()))
                        .unwrap();
                    let extended_private_key = match mnemonic_values.path {
                        Some(path) => master_xpriv_key
                            .derive(&EthereumDerivationPath::from_str(&path).unwrap())
                            .unwrap(),
                        None => master_xpriv_key,
                    };

                    let private_key = extended_private_key.to_private_key();
                    let address = EthereumAddress::from_private_key(&private_key, &PhantomData).unwrap();

                    GenericWallet {
                        mnemonic: Some(mnemonic.to_string()),
                        extended_private_key: Some(extended_private_key.to_string()),
                        private_key: Some(private_key.to_string()),
                        address: address.to_string(),
                        ..Default::default()
                    }
                }
            };

            if ethereum_options.json {
                println!("{}\n", serde_json::to_string_pretty(&wallet).unwrap());
            } else {
                println!("{}\n", wallet);
            }
        }
    }
}

/// Represents custom options for an Ethereum wallet
#[derive(Serialize, Clone, Debug)]
struct EthereumOptions {
    pub private_key: Option<String>,
    pub mnemonic_values: Option<HdValues>,
    pub count: usize,
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
