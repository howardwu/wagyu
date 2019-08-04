use crate::cli::{flag, option, subcommand, types::*, CLI};
use crate::ethereum::{
    English as EthereumEnglish, EthereumAddress, EthereumDerivationPath, EthereumMnemonic, EthereumPrivateKey,
    EthereumPublicKey,
};
use crate::model::{ExtendedPrivateKey, ExtendedPublicKey, MnemonicExtended, PrivateKey, PublicKey};

use clap::ArgMatches;
use ethereum::{EthereumExtendedPrivateKey, EthereumExtendedPublicKey};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display, marker::PhantomData, str::FromStr};

/// Represents custom options for a Ethereum wallet
#[derive(Serialize, Clone, Debug)]
pub struct EthereumOptions {
    pub wallet_values: Option<WalletValues>,
    pub hd_values: Option<HdValues>,
    pub count: usize,
    pub json: bool,
}

/// Represents values to derive standard wallets
#[derive(Serialize, Clone, Debug)]
pub struct WalletValues {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub address: Option<String>,
}

/// Represents values to derive HD wallets
#[derive(Serialize, Clone, Debug, Default)]
pub struct HdValues {
    pub account: Option<String>,
    pub change: Option<String>,
    pub extended_private_key: Option<String>,
    pub extended_public_key: Option<String>,
    pub index: Option<String>,
    pub mnemonic: Option<String>,
    pub password: Option<String>,
    pub path: Option<String>,
    pub word_count: Option<u8>,
}

/// Represents a generic wallet to output
#[derive(Serialize, Debug, Default)]
struct EthereumWallet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub address: String,
}

#[cfg_attr(tarpaulin, skip)]
impl Display for EthereumWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = [
            match &self.path {
                Some(path) => format!("      Path:                 {}\n", path),
                _ => "".to_owned(),
            },
            match &self.password {
                Some(password) => format!("      Password:             {}\n", password),
                _ => "".to_owned(),
            },
            match &self.mnemonic {
                Some(mnemonic) => format!("      Mnemonic:             {}\n", mnemonic),
                _ => "".to_owned(),
            },
            match &self.extended_private_key {
                Some(extended_private_key) => format!("      Extended Private Key: {}\n", extended_private_key),
                _ => "".to_owned(),
            },
            match &self.extended_public_key {
                Some(extended_public_key) => format!("      Extended Public Key:  {}\n", extended_public_key),
                _ => "".to_owned(),
            },
            match &self.private_key {
                Some(private_key) => format!("      Private Key:          {}\n", private_key),
                _ => "".to_owned(),
            },
            match &self.public_key {
                Some(private_key) => format!("      Public Key:           {}\n", private_key),
                _ => "".to_owned(),
            },
            format!("      Address:              {}\n", self.address),
        ]
        .concat();

        // Removes final new line character
        let output = output[..output.len() - 1].to_owned();
        write!(f, "\n{}", output)
    }
}

pub struct EthereumCLI;

impl CLI for EthereumCLI {
    type Options = EthereumOptions;

    const NAME: NameType = "ethereum";
    const ABOUT: AboutType = "Generates a Ethereum wallet (include -h for more options)";
    const FLAGS: &'static [FlagType] = &[flag::JSON];
    const OPTIONS: &'static [OptionType] = &[option::COUNT];
    const SUBCOMMANDS: &'static [SubCommandType] = &[subcommand::HD_ETHEREUM, subcommand::IMPORT_ETHEREUM, subcommand::IMPORT_HD_ETHEREUM];

    /// Handle all CLI arguments and flags for Ethereum
    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Self::Options {
        let mut options = EthereumOptions {
            wallet_values: None,
            hd_values: None,
            count: clap::value_t!(arguments.value_of("count"), usize).unwrap_or_else(|_e| 1),
            json: arguments.is_present("json"),
        };

        match arguments.subcommand() {
            ("hd", Some(hd_matches)) => {
                let password = hd_matches.value_of("password").map(|s| s.to_string());
                let path = hd_matches.value_of("derivation").map(|s| s.to_string());
                let word_count = hd_matches.value_of("word count").map(|s| s.parse().unwrap());

                options.count = clap::value_t!(hd_matches.value_of("count"), usize).unwrap_or(options.count);
                options.json = options.json || hd_matches.is_present("json");
                options.hd_values = Some(HdValues {
                    word_count,
                    mnemonic: None,
                    password,
                    path,
                    ..Default::default()
                });
            }
            ("import", Some(import_matches)) => {
                let address = import_matches.value_of("address").map(|s| s.to_string());
                let public_key = import_matches.value_of("public key").map(|s| s.to_string());
                let private_key = import_matches.value_of("private key").map(|s| s.to_string());

                options.json = options.json || import_matches.is_present("json");
                options.wallet_values = Some(WalletValues { address, public_key, private_key });
            }
            ("import-hd", Some(import_hd_matches)) => {
                let account = import_hd_matches.value_of("account").map(|i| i.to_string());
                let change = import_hd_matches.value_of("change").map(|i| i.to_string());
                let extended_private_key = import_hd_matches.value_of("extended private").map(|s| s.to_string());
                let extended_public_key = import_hd_matches.value_of("extended public").map(|s| s.to_string());
                let index = import_hd_matches.value_of("index").map(|i| i.to_string());
                let mnemonic = import_hd_matches.value_of("mnemonic").map(|s| s.to_string());
                let password = import_hd_matches.value_of("password").map(|s| s.to_string());
                let path = import_hd_matches.value_of("derivation").map(|s| s.to_string());

                options.json = options.json || import_hd_matches.is_present("json");
                options.hd_values = Some(HdValues {
                    account,
                    change,
                    extended_private_key,
                    extended_public_key,
                    index,
                    mnemonic,
                    password,
                    path,
                    ..Default::default()
                });
            }
            _ => {}
        };

        options
    }

    /// Generate the Ethereum wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) {
        for _ in 0..options.count {
            let wallet = match (options.wallet_values.to_owned(), options.hd_values.to_owned()) {
                (None, None) => {
                    let private_key = EthereumPrivateKey::new(&mut StdRng::from_entropy()).unwrap();
                    let public_key = private_key.to_public_key();
                    let address = public_key.to_address(&PhantomData).unwrap();

                    EthereumWallet {
                        private_key: Some(private_key.to_string()),
                        public_key: Some(public_key.to_string()),
                        address: address.to_string(),
                        ..Default::default()
                    }
                }
                (Some(wallet_values), None) => {
                    match (
                        wallet_values.private_key.clone(),
                        wallet_values.public_key.clone(),
                        wallet_values.address.clone(),
                    ) {
                        (Some(private_key), None, None) => match EthereumPrivateKey::from_str(&private_key) {
                            Ok(private_key) => {
                                let public_key = private_key.to_public_key();
                                let address = public_key.to_address(&PhantomData).unwrap();

                                EthereumWallet {
                                    private_key: Some(private_key.to_string()),
                                    public_key: Some(public_key.to_string()),
                                    address: address.to_string(),
                                    ..Default::default()
                                }
                            }
                            Err(_) => {
                                let private_key = EthereumPrivateKey::from_str(&private_key).unwrap();
                                let public_key = private_key.to_public_key();
                                let address = public_key.to_address(&PhantomData).unwrap();

                                EthereumWallet {
                                    private_key: Some(private_key.to_string()),
                                    public_key: Some(public_key.to_string()),
                                    address: address.to_string(),
                                    ..Default::default()
                                }
                            }
                        },
                        (None, Some(public_key), None) => {
                            let public_key = EthereumPublicKey::from_str(&public_key).unwrap();
                            let address = public_key.to_address(&PhantomData).unwrap();

                            EthereumWallet {
                                public_key: Some(public_key.to_string()),
                                address: address.to_string(),
                                ..Default::default()
                            }
                        }
                        (None, None, Some(address)) => match EthereumAddress::from_str(&address) {
                            Ok(address) => EthereumWallet {
                                address: address.to_string(),
                                ..Default::default()
                            },
                            Err(_) => {
                                let address = EthereumAddress::from_str(&address).unwrap();
                                EthereumWallet {
                                    address: address.to_string(),
                                    ..Default::default()
                                }
                            }
                        },
                        _ => unreachable!(),
                    }
                }
                (None, Some(hd_values)) => {
                    type W = EthereumEnglish;
                    const DEFAULT_WORD_COUNT: u8 = 12;

                    let index = hd_values.index.unwrap_or("0".to_string());

                    let mut path: Option<String> = match hd_values.path.as_ref().map(String::as_str) {
                        Some("ethereum") => Some(format!("m/44'/60'/0'/{}", index)),
                        Some("keepkey") => Some(format!("m/44'/60'/{}'/0", index)),
                        Some("ledger-legacy") => Some(format!("m/44'/60'/0'/{}", index)),
                        Some("ledger-live") => Some(format!("m/44'/60'/{}'/0/0", index)),
                        Some("trezor") => Some(format!("m/44'/60'/0'/{}", index)),
                        Some(custom_path) => Some(custom_path.to_string()),
                        None => Some(format!("m/44'/60'/0'/{}", index)) // Default - ethereum
                    };

                    let word_count = match hd_values.word_count {
                        Some(word_count) => word_count,
                        None => DEFAULT_WORD_COUNT,
                    };

                    let password = hd_values.password.as_ref().map(String::as_str);
                    let (mnemonic, extended_private_key, extended_public_key) = match (
                        hd_values.mnemonic,
                        hd_values.extended_private_key,
                        hd_values.extended_public_key,
                    ) {
                        (None, None, None) => {
                            let mnemonic = EthereumMnemonic::<W>::new(word_count, &mut StdRng::from_entropy()).unwrap();
                            let master_xpriv_key = mnemonic.to_extended_private_key(password).unwrap();
                            let extended_private_key = master_xpriv_key
                                .derive(&EthereumDerivationPath::from_str(&path.clone().unwrap()).unwrap())
                                .unwrap();
                            let extended_public_key = extended_private_key.to_extended_public_key();

                            (Some(mnemonic), Some(extended_private_key), extended_public_key)
                        }
                        (Some(mnemonic), None, None) => {
                            let mnemonic = EthereumMnemonic::<W>::from_phrase(&mnemonic).unwrap();
                            let master_xpriv_key = mnemonic.to_extended_private_key(password).unwrap();
                            let extended_private_key = master_xpriv_key
                                .derive(&EthereumDerivationPath::from_str(&path.clone().unwrap()).unwrap())
                                .unwrap();
                            let extended_public_key = extended_private_key.to_extended_public_key();

                            (Some(mnemonic), Some(extended_private_key), extended_public_key)
                        }
                        (None, Some(extended_private_key), None) => {
                            let mut extended_private_key =
                                EthereumExtendedPrivateKey::from_str(&extended_private_key).unwrap();
                            if hd_values.path.is_some() {
                                extended_private_key = extended_private_key
                                    .derive(&EthereumDerivationPath::from_str(&path.clone().unwrap()).unwrap())
                                    .unwrap();
                            } else {
                                path = None;
                            }
                            let extended_public_key = extended_private_key.to_extended_public_key();
                            (None, Some(extended_private_key), extended_public_key)
                        }
                        (None, None, Some(extended_public_key)) => {
                            let mut extended_public_key =
                                EthereumExtendedPublicKey::from_str(&extended_public_key).unwrap();
                            if hd_values.path.is_some() {
                                extended_public_key = extended_public_key
                                    .derive(&EthereumDerivationPath::from_str(&path.clone().unwrap()).unwrap())
                                    .unwrap();
                            } else {
                                path = None;
                            }
                            (None, None, extended_public_key)
                        }
                        _ => unreachable!(),
                    };

                    let private_key = match extended_private_key.clone() {
                        Some(extended_private_key) => Some(extended_private_key.to_private_key().to_string()),
                        None => None,
                    };
                    let public_key = extended_public_key.to_public_key();
                    let address = public_key.to_address(&PhantomData).unwrap();

                    EthereumWallet {
                        path,
                        password: hd_values.password,
                        mnemonic: mnemonic.map(|key| key.to_string()),
                        extended_private_key: extended_private_key.map(|key| key.to_string()),
                        extended_public_key: Some(extended_public_key.to_string()),
                        private_key,
                        public_key: Some(public_key.to_string()),
                        address: address.to_string(),
                        ..Default::default()
                    }
                }
                _ => unreachable!(),
            };

            if options.json {
                println!("{}\n", serde_json::to_string_pretty(&wallet).unwrap());
            } else {
                println!("{}\n", wallet);
            }
        }
    }
}
