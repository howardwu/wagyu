use crate::bitcoin::{
    address::Format as BitcoinFormat, BitcoinAddress, BitcoinDerivationPath, BitcoinMnemonic, BitcoinNetwork,
    BitcoinPrivateKey, BitcoinPublicKey, English as BitcoinEnglish, Mainnet as BitcoinMainnet, Testnet as BitcoinTestnet,
};
use crate::cli::{flag, option, subcommand, types::*, CLI};
use crate::model::{ExtendedPrivateKey,ExtendedPublicKey, MnemonicExtended, PrivateKey, PublicKey};

use clap::ArgMatches;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display, str::FromStr};
use bitcoin::{BitcoinExtendedPrivateKey, BitcoinExtendedPublicKey};

/// Represents custom options for a Bitcoin wallet
#[derive(Serialize, Clone, Debug)]
pub struct BitcoinOptions {
    pub wallet_values: Option<WalletValues>,
    pub hd_values: Option<HdValues>,
    pub count: usize,
    pub network: String,
    pub format: BitcoinFormat,
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
struct BitcoinWallet {
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed: Option<bool>,
}

#[cfg_attr(tarpaulin, skip)]
impl Display for BitcoinWallet {
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

pub struct BitcoinCLI;

impl CLI for BitcoinCLI {
    type Options = BitcoinOptions;

    const NAME: NameType = "bitcoin";
    const ABOUT: AboutType = "Generates a Bitcoin wallet (include -h for more options)";
    const FLAGS: &'static [FlagType] = &[flag::JSON];
    const OPTIONS: &'static [OptionType] = &[option::COUNT, option::BITCOIN_FORMAT, option::BITCOIN_NETWORK];
    const SUBCOMMANDS: &'static [SubCommandType] = &[subcommand::HD, subcommand::IMPORT, subcommand::IMPORT_HD];

    /// Handle all CLI arguments and flags for Bitcoin
    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Self::Options {
        let mut format = arguments.value_of("format");
        let network = match arguments.value_of("network") {
            Some("testnet") => "testnet",
            _ => "mainnet",
        };

        let mut options = BitcoinOptions {
            wallet_values: None,
            hd_values: None,
            count: clap::value_t!(arguments.value_of("count"), usize).unwrap_or_else(|_e| 1),
            network: network.to_owned(),
            format: BitcoinFormat::P2PKH,
            json: arguments.is_present("json"),
        };

        match arguments.subcommand() {
            ("hd", Some(hd_matches)) => {
                let password = hd_matches.value_of("password").map(|s| s.to_string());
                let path = hd_matches.value_of("derivation").map(|s| s.to_string());
                let word_count = hd_matches.value_of("word count").map(|s| s.parse().unwrap());

                format = hd_matches.value_of("format").or(format);
                options.count = clap::value_t!(hd_matches.value_of("count"), usize).unwrap_or(options.count);
                options.json = options.json || hd_matches.is_present("json");
                options.network = hd_matches.value_of("network").unwrap_or(&options.network).to_string();

                options.hd_values = Some(HdValues {
                    word_count,
                    mnemonic: None,
                    password,
                    path,
                    ..Default::default()
                });
            },
            ("import", Some(import_matches)) => {
                let address = import_matches.value_of("address").map(|s| s.to_string());
                let public_key = import_matches.value_of("public key").map(|s| s.to_string());
                let private_key = import_matches.value_of("private key").map(|s| s.to_string());

                format = import_matches.value_of("format").or(format);
                options.json = options.json || import_matches.is_present("json");
                options.network = import_matches.value_of("network").unwrap_or(&options.network).to_string();

                options.wallet_values = Some(WalletValues {
                    address,
                    public_key,
                    private_key,
                });
            },
            ("import-hd", Some(import_hd_matches)) => {
                let account = import_hd_matches.value_of("account").map(|i| i.to_string());
                let change = import_hd_matches.value_of("change").map(|i| i.to_string());
                let extended_private_key = import_hd_matches.value_of("extended private").map(|s| s.to_string());
                let extended_public_key = import_hd_matches.value_of("extended public").map(|s| s.to_string());
                let index = import_hd_matches.value_of("index").map(|i| i.to_string());
                let mnemonic = import_hd_matches.value_of("mnemonic").map(|s| s.to_string());
                let password = import_hd_matches.value_of("password").map(|s| s.to_string());
                let path = import_hd_matches.value_of("derivation").map(|s| s.to_string());

                format = import_hd_matches.value_of("format").or(format);
                options.json = options.json || import_hd_matches.is_present("json");
                options.network = import_hd_matches.value_of("network").unwrap_or(&options.network).to_string();

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
            },
            _ => {}
        };

        options.format = match format {
            Some("segwit") => BitcoinFormat::P2SH_P2WPKH,
            Some("bech32") => BitcoinFormat::Bech32,
            _ =>  BitcoinFormat::P2PKH,
        };

        options
    }

    /// Generate the Bitcoin wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) {
        match options.network.as_str() {
            "testnet" => output::<BitcoinTestnet>(options),
            _ => output::<BitcoinMainnet>(options),
        };

        fn output<N: BitcoinNetwork>(options: BitcoinOptions) {
            for _ in 0..options.count {
                let wallet = match (options.wallet_values.to_owned(), options.hd_values.to_owned()) {
                    (None, None) => {
                        let private_key = BitcoinPrivateKey::<N>::new(&mut StdRng::from_entropy()).unwrap();
                        let public_key = private_key.to_public_key();
                        let address = public_key.to_address(&options.format).unwrap();

                        BitcoinWallet {
                            private_key: Some(private_key.to_string()),
                            public_key: Some(public_key.to_string()),
                            address: address.to_string(),
                            network: Some(options.network.to_owned()),
                            format: Some(address.format().to_string()),
                            compressed: Some(private_key.is_compressed()),
                            ..Default::default()
                        }
                    },
                    (Some(wallet_values), None) => {
                        match (wallet_values.private_key.clone(), wallet_values.public_key.clone(), wallet_values.address.clone()) {
                            (Some(private_key), None, None) => {
                                match BitcoinPrivateKey::<BitcoinMainnet>::from_str(&private_key) {
                                    Ok(private_key) => {
                                        let public_key = private_key.to_public_key();
                                        let address = public_key.to_address(&options.format).unwrap();

                                        BitcoinWallet {
                                            private_key: Some(private_key.to_string()),
                                            public_key: Some(public_key.to_string()),
                                            address: address.to_string(),
                                            network: Some("mainnet".to_string()),
                                            format: Some(options.format.to_string()),
                                            compressed: Some(private_key.is_compressed()),
                                            ..Default::default()
                                        }
                                    },
                                    Err(_) => {
                                        let private_key = BitcoinPrivateKey::<BitcoinTestnet>::from_str(&private_key).unwrap();
                                        let public_key = private_key.to_public_key();
                                        let address = public_key.to_address(&options.format).unwrap();

                                        BitcoinWallet {
                                            private_key: Some(private_key.to_string()),
                                            public_key: Some(public_key.to_string()),
                                            address: address.to_string(),
                                            network: Some("testnet".to_string()),
                                            format: Some(address.format().to_string()),
                                            compressed: Some(private_key.is_compressed()),
                                            ..Default::default()
                                        }
                                    },
                                }
                            },
                            (None, Some(public_key), None) => {
                                let public_key = BitcoinPublicKey::<N>::from_str(&public_key).unwrap();
                                let address = public_key.to_address(&options.format).unwrap();

                                BitcoinWallet {
                                    public_key: Some(public_key.to_string()),
                                    address: address.to_string(),
                                    network: Some(options.network.to_string()),
                                    format: Some(address.format().to_string()),
                                    ..Default::default()
                                }
                            },
                            (None, None, Some(address)) => {
                                match BitcoinAddress::<BitcoinMainnet>::from_str(&address) {
                                    Ok(address) => {
                                        BitcoinWallet {
                                            address: address.to_string(),
                                            network: Some("mainnet".to_string()),
                                            format: Some(address.format().to_string()),
                                            ..Default::default()
                                        }
                                    }
                                    Err(_) => {
                                        let address = BitcoinAddress::<BitcoinTestnet>::from_str(&address).unwrap();
                                        BitcoinWallet {
                                            address: address.to_string(),
                                            network: Some("testnet".to_string()),
                                            format: Some(address.format().to_string()),
                                            ..Default::default()
                                        }
                                    }
                                }
                            },
                            _ => unreachable!(),
                        }
                    }
                    (None, Some(hd_values)) => {
                        type W = BitcoinEnglish;
                        const DEFAULT_WORD_COUNT: u8 = 12;

                        let mut format = options.format.clone();
                        let account = hd_values.account.unwrap_or("0".to_string());
                        let change = hd_values.change.unwrap_or("0".to_string());
                        let index = hd_values.index.unwrap_or("0".to_string());

                        let mut path: Option<String> =  match hd_values.path.as_ref().map(String::as_str) {
                            Some("bip32") => {
                                Some(format!("m/0'/0'/{}'", index))
                            },
                            Some("bip44") => {
                                Some(format!("m/44'/0'/{}'/{}/{}'", account, change, index))
                            },
                            Some("bip49") => {
                                format = BitcoinFormat::P2SH_P2WPKH;
                                Some(format!("m/49'/0'/{}'/{}/{}'", account, change, index))
                            },
                            Some(custom_path) => {
                                Some(custom_path.to_string())
                            },
                            None => { // Default - bip32
                                Some(format!("m/0'/0'/{}'", index))
                            },
                        };

                        let word_count = match hd_values.word_count {
                            Some(word_count) => word_count,
                            None => DEFAULT_WORD_COUNT,
                        };

                        let password = hd_values.password.as_ref().map(String::as_str);
                        let (mnemonic, extended_private_key, extended_public_key) =
                            match (hd_values.mnemonic, hd_values.extended_private_key, hd_values.extended_public_key) {
                                (None, None, None) => {
                                    let mnemonic = BitcoinMnemonic::<N, W>::new(word_count, &mut StdRng::from_entropy()).unwrap();
                                    let master_xpriv_key = mnemonic.to_extended_private_key(password).unwrap();
                                    let extended_private_key = master_xpriv_key.derive(&BitcoinDerivationPath::from_str(&path.clone().unwrap()).unwrap()).unwrap();
                                    let extended_public_key = extended_private_key.to_extended_public_key();

                                    (Some(mnemonic), Some(extended_private_key), extended_public_key)
                                },
                                (Some(mnemonic), None, None) => {
                                    let mnemonic = BitcoinMnemonic::<N, W>::from_phrase(&mnemonic).unwrap();
                                    let master_xpriv_key = mnemonic.to_extended_private_key(password).unwrap();
                                    let extended_private_key = master_xpriv_key.derive(&BitcoinDerivationPath::from_str(&path.clone().unwrap()).unwrap()).unwrap();
                                    let extended_public_key = extended_private_key.to_extended_public_key();

                                    (Some(mnemonic), Some(extended_private_key), extended_public_key)
                                },
                                (None, Some(extended_private_key), None) => {
                                    let mut extended_private_key = BitcoinExtendedPrivateKey::from_str(&extended_private_key).unwrap();
                                    if hd_values.path.is_some() {
                                        extended_private_key = extended_private_key.derive(&BitcoinDerivationPath::from_str(&path.clone().unwrap()).unwrap()).unwrap();
                                    } else {
                                        path = None;
                                    }
                                    let extended_public_key = extended_private_key.to_extended_public_key();
                                    (None, Some(extended_private_key), extended_public_key)
                                },
                                (None, None, Some(extended_public_key)) => {
                                    let mut extended_public_key = BitcoinExtendedPublicKey::from_str(&extended_public_key).unwrap();
                                    if hd_values.path.is_some() {
                                        extended_public_key = extended_public_key.derive(&BitcoinDerivationPath::from_str(&path.clone().unwrap()).unwrap()).unwrap();
                                    } else {
                                        path = None;
                                    }
                                    (None, None, extended_public_key)
                                },
                                _ => unreachable!(),
                            };

                        let (private_key, compressed) = match extended_private_key.clone() {
                            Some(extended_private_key) => {
                                let private_key = extended_private_key.to_private_key();
                                (Some(private_key.to_string()), Some(private_key.is_compressed()))
                            },
                            None => (None, None),
                        };

                        let public_key = extended_public_key.to_public_key();
                        let address = public_key.to_address(&format).unwrap();

                        BitcoinWallet {
                            path,
                            password: hd_values.password,
                            mnemonic: mnemonic.map(|key| key.to_string()),
                            extended_private_key: extended_private_key.map(|key| key.to_string()),
                            extended_public_key: Some(extended_public_key.to_string()),
                            private_key,
                            public_key: Some(public_key.to_string()),
                            address: address.to_string(),
                            network: Some(options.network.to_owned()),
                            format: Some(address.format().to_string()),
                            compressed,
                            ..Default::default()
                        }
                    },
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
}
