use crate::bitcoin::{
    address::Format as BitcoinFormat, BitcoinAddress, BitcoinDerivationPath,
    BitcoinExtendedPrivateKey, BitcoinExtendedPublicKey, BitcoinMnemonic, BitcoinNetwork,
    BitcoinPrivateKey, BitcoinPublicKey, BitcoinWordlist, Mainnet as BitcoinMainnet,
    Testnet as BitcoinTestnet, wordlist::*,
};
use crate::cli::{flag, option, subcommand, types::*, CLI, CLIError};
use crate::model::{ExtendedPrivateKey, ExtendedPublicKey, MnemonicExtended, PrivateKey, PublicKey};

use clap::ArgMatches;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display, str::FromStr};

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
    pub chain: Option<String>,
    pub extended_private_key: Option<String>,
    pub extended_public_key: Option<String>,
    pub index: Option<String>,
    pub language: Option<String>,
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
                Some(path) => format!("      Path                 {}\n", path),
                _ => "".to_owned(),
            },
            match &self.password {
                Some(password) => format!("      Password             {}\n", password),
                _ => "".to_owned(),
            },
            match &self.mnemonic {
                Some(mnemonic) => format!("      Mnemonic             {}\n", mnemonic),
                _ => "".to_owned(),
            },
            match &self.extended_private_key {
                Some(extended_private_key) => format!("      Extended Private Key {}\n", extended_private_key),
                _ => "".to_owned(),
            },
            match &self.extended_public_key {
                Some(extended_public_key) => format!("      Extended Public Key  {}\n", extended_public_key),
                _ => "".to_owned(),
            },
            match &self.private_key {
                Some(private_key) => format!("      Private Key          {}\n", private_key),
                _ => "".to_owned(),
            },
            match &self.public_key {
                Some(public_key) => format!("      Public Key           {}\n", public_key),
                _ => "".to_owned(),
            },
            format!("      Address              {}\n", self.address),
            match &self.format {
                Some(format) => format!("      Format               {}\n", format),
                _ => "".to_owned(),
            },
            match &self.network {
                Some(network) => format!("      Network              {}\n", network),
                _ => "".to_owned(),
            },
            match &self.compressed {
                Some(compressed) => format!("      Compressed           {}\n", compressed),
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
    const OPTIONS: &'static [OptionType] = &[option::COUNT, option::FORMAT_BITCOIN, option::NETWORK_BITCOIN];
    const SUBCOMMANDS: &'static [SubCommandType] = &[
        subcommand::HD_BITCOIN,
        subcommand::IMPORT_BITCOIN,
        subcommand::IMPORT_HD_BITCOIN,
    ];

    /// Handle all CLI arguments and flags for Bitcoin
    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Result<Self::Options, CLIError> {
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
                let language = hd_matches.value_of("language").map(|s| s.to_string());
                let password = hd_matches.value_of("password").map(|s| s.to_string());
                let path = hd_matches.value_of("derivation").map(|s| s.to_string());
                let word_count = hd_matches.value_of("word count").map(|s| s.parse::<u8>().unwrap());

                format = hd_matches.value_of("format").or(format);
                options.count = clap::value_t!(hd_matches.value_of("count"), usize).unwrap_or(options.count);
                options.json |= hd_matches.is_present("json");
                options.network = hd_matches.value_of("network").unwrap_or(&options.network).to_string();

                options.hd_values = Some(HdValues {
                    language,
                    mnemonic: None,
                    password,
                    path,
                    word_count,
                    ..Default::default()
                });
            }
            ("import", Some(import_matches)) => {
                let address = import_matches.value_of("address").map(|s| s.to_string());
                let public_key = import_matches.value_of("public key").map(|s| s.to_string());
                let private_key = import_matches.value_of("private key").map(|s| s.to_string());

                format = import_matches.value_of("format").or(format);
                options.json |= import_matches.is_present("json");
                options.network = import_matches
                    .value_of("network")
                    .unwrap_or(&options.network)
                    .to_string();

                options.wallet_values = Some(WalletValues {
                    address,
                    public_key,
                    private_key,
                });
            }
            ("import-hd", Some(import_hd_matches)) => {
                let account = import_hd_matches.value_of("account").map(|i| i.to_string());
                let chain = import_hd_matches.value_of("chain").map(|i| i.to_string());
                let extended_private_key = import_hd_matches.value_of("extended private").map(|s| s.to_string());
                let extended_public_key = import_hd_matches.value_of("extended public").map(|s| s.to_string());
                let index = import_hd_matches.value_of("index").map(|i| i.to_string());
                let mnemonic = import_hd_matches.value_of("mnemonic").map(|s| s.to_string());
                let password = import_hd_matches.value_of("password").map(|s| s.to_string());
                let path = import_hd_matches.value_of("derivation").map(|s| s.to_string());

                format = import_hd_matches.value_of("format").or(format);
                options.json |= import_hd_matches.is_present("json");
                options.network = import_hd_matches
                    .value_of("network")
                    .unwrap_or(&options.network)
                    .to_string();

                options.hd_values = Some(HdValues {
                    account,
                    chain,
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

        options.format = match format {
            Some("segwit") => BitcoinFormat::P2SH_P2WPKH,
            Some("bech32") => BitcoinFormat::Bech32,
            _ => BitcoinFormat::P2PKH,
        };

        Ok(options)
    }

    /// Generate the Bitcoin wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) -> Result<(), CLIError> {

        fn output<N: BitcoinNetwork>(options: BitcoinOptions) -> Result<(), CLIError> {
            for _ in 0..options.count {
                let wallet = match (options.wallet_values.to_owned(), options.hd_values.to_owned()) {
                    (None, None) => {
                        let private_key = BitcoinPrivateKey::<N>::new(&mut StdRng::from_entropy())?;
                        let public_key = private_key.to_public_key();
                        let address = public_key.to_address(&options.format)?;

                        BitcoinWallet {
                            private_key: Some(private_key.to_string()),
                            public_key: Some(public_key.to_string()),
                            address: address.to_string(),
                            network: Some(options.network.to_owned()),
                            format: Some(address.format().to_string()),
                            compressed: Some(private_key.is_compressed()),
                            ..Default::default()
                        }
                    }
                    (Some(wallet_values), None) => {

                        fn process_private_key<N: BitcoinNetwork>(private_key: &str, format: &BitcoinFormat) -> Result<BitcoinWallet, CLIError> {
                            match BitcoinPrivateKey::<N>::from_str(&private_key) {
                                Ok(private_key) => {
                                    let public_key = private_key.to_public_key();
                                    let address = public_key.to_address(format)?;

                                    Ok(BitcoinWallet {
                                        private_key: Some(private_key.to_string()),
                                        public_key: Some(public_key.to_string()),
                                        address: address.to_string(),
                                        network: Some(N::NAME.to_string()),
                                        format: Some(format.to_string()),
                                        compressed: Some(private_key.is_compressed()),
                                        ..Default::default()
                                    })
                                },
                                Err(error) => Err(CLIError::PrivateKeyError(error)),
                            }
                        }

                        fn process_address<N: BitcoinNetwork>(address: &str) -> Result<BitcoinWallet, CLIError> {
                            match BitcoinAddress::<N>::from_str(&address) {
                                Ok(address) => {
                                    Ok(BitcoinWallet {
                                        address: address.to_string(),
                                        network: Some(N::NAME.to_string()),
                                        format: Some(address.format().to_string()),
                                        ..Default::default()
                                    })
                                },
                                Err(error) => Err(CLIError::AddressError(error)),
                            }
                        }

                        match (
                            wallet_values.private_key.as_ref(),
                            wallet_values.public_key.as_ref(),
                            wallet_values.address.as_ref(),
                        ) {
                            (Some(private_key), None, None) => {
                                let main = process_private_key::<BitcoinMainnet>(&private_key, &options.format);
                                let test = process_private_key::<BitcoinTestnet>(&private_key, &options.format);
                                main.or(test)?
                            },
                            (None, Some(public_key), None) => {
                                let public_key = BitcoinPublicKey::<N>::from_str(&public_key)?;
                                let address = public_key.to_address(&options.format)?;

                                BitcoinWallet {
                                    public_key: Some(public_key.to_string()),
                                    address: address.to_string(),
                                    network: Some(options.network.to_string()),
                                    format: Some(address.format().to_string()),
                                    ..Default::default()
                                }
                            }
                            (None, None, Some(address)) => {
                                let main = process_address::<BitcoinMainnet>(&address);
                                let test = process_address::<BitcoinTestnet>(&address);
                                main.or(test)?
                            },
                            _ => unreachable!(),
                        }
                    }
                    (None, Some(hd_values)) => {

                        fn process_mnemonic<BN: BitcoinNetwork, BW: BitcoinWordlist>(mnemonic: Option<String>, word_count: u8, password: &Option<&str>)
                            -> Result<(String, BitcoinExtendedPrivateKey<BN>), CLIError> {
                            let mnemonic = match mnemonic {
                                Some(mnemonic) => BitcoinMnemonic::<BN, BW>::from_phrase(&mnemonic)?,
                                None => BitcoinMnemonic::<BN, BW>::new(word_count, &mut StdRng::from_entropy())?,
                            };
                            let master_extended_private_key = mnemonic.to_extended_private_key(*password)?;
                            Ok((mnemonic.to_string(), master_extended_private_key))
                        }

                        const DEFAULT_WORD_COUNT: u8 = 12;
                        let mut format = options.format.clone();
                        let account = hd_values.account.unwrap_or("0".to_string());
                        let chain = hd_values.chain.unwrap_or("0".to_string());
                        let index = hd_values.index.unwrap_or("0".to_string());

                        let path: String = match hd_values.path.as_ref().map(String::as_str) {
                            Some("bip32") => format!("m/0'/0'/{}'", index),
                            Some("bip44") => format!("m/44'/0'/{}'/{}/{}'", account, chain, index),
                            Some("bip49") => {
                                format = BitcoinFormat::P2SH_P2WPKH;
                                format!("m/49'/0'/{}'/{}/{}'", account, chain, index)
                            }
                            Some(custom_path) => custom_path.to_string(),
                            None => format!("m/0'/0'/{}'", index), // Default - bip32
                        };

                        let mut final_path = Some(path.to_string());

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
                                let (mnemonic, master_extended_private_key)
                                    = match hd_values.language.as_ref().map(String::as_str) {
                                    Some("chinese_simplified") => process_mnemonic::<N, ChineseSimplified>(None, word_count, &password)?,
                                    Some("chinese_traditional") => process_mnemonic::<N, ChineseTraditional>(None, word_count, &password)?,
                                    Some("english") => process_mnemonic::<N, English>(None, word_count, &password)?,
                                    Some("french") => process_mnemonic::<N, French>(None, word_count, &password)?,
                                    Some("italian") => process_mnemonic::<N, Italian>(None, word_count, &password)?,
                                    Some("japanese") => process_mnemonic::<N, Japanese>(None, word_count, &password)?,
                                    Some("korean") => process_mnemonic::<N, Korean>(None, word_count, &password)?,
                                    Some("spanish") => process_mnemonic::<N, Spanish>(None, word_count, &password)?,
                                    _ => process_mnemonic::<N, English>(None, word_count, &password)?, // Default language - English
                                };

                                let extended_private_key = master_extended_private_key
                                    .derive(&BitcoinDerivationPath::from_str(&path)?)?;
                                let extended_public_key = extended_private_key.to_extended_public_key();

                                (Some(mnemonic), Some(extended_private_key), extended_public_key)
                            }
                            (Some(mnemonic), None, None) => {
                                let (mnemonic, master_extended_private_key) =
                                    process_mnemonic::<N, ChineseSimplified>(Some(mnemonic.to_owned()), word_count, &password)
                                    .or(process_mnemonic::<N, ChineseTraditional>(Some(mnemonic.to_owned()), word_count, &password))
                                    .or(process_mnemonic::<N, English>(Some(mnemonic.to_owned()), word_count, &password))
                                    .or(process_mnemonic::<N, French>(Some(mnemonic.to_owned()), word_count, &password))
                                    .or(process_mnemonic::<N, Italian>(Some(mnemonic.to_owned()), word_count, &password))
                                    .or(process_mnemonic::<N, Japanese>(Some(mnemonic.to_owned()), word_count, &password))
                                    .or(process_mnemonic::<N, Korean>(Some(mnemonic.to_owned()), word_count, &password))
                                    .or(process_mnemonic::<N, Spanish>(Some(mnemonic.to_owned()), word_count, &password))?;

                                let extended_private_key = master_extended_private_key.derive(&BitcoinDerivationPath::from_str(&path)?)?;
                                let extended_public_key = extended_private_key.to_extended_public_key();

                                (Some(mnemonic), Some(extended_private_key), extended_public_key)
                            }
                            (None, Some(extended_private_key), None) => {
                                let mut extended_private_key =
                                    BitcoinExtendedPrivateKey::from_str(&extended_private_key)?;

                                match hd_values.path {
                                    Some(_) => extended_private_key = extended_private_key.derive(&BitcoinDerivationPath::from_str(&path)?)?,
                                    None => final_path = None,
                                };

                                let extended_public_key = extended_private_key.to_extended_public_key();
                                (None, Some(extended_private_key), extended_public_key)
                            }
                            (None, None, Some(extended_public_key)) => {
                                let mut extended_public_key = BitcoinExtendedPublicKey::from_str(&extended_public_key)?;

                                match hd_values.path {
                                    Some(_) => extended_public_key = extended_public_key.derive(&BitcoinDerivationPath::from_str(&path)?)?,
                                    None => final_path = None,
                                };

                                (None, None, extended_public_key)
                            }
                            _ => unreachable!(),
                        };

                        let (private_key, compressed) = match extended_private_key.as_ref() {
                            Some(extended_private_key) => {
                                let private_key = extended_private_key.to_private_key();
                                (Some(private_key.to_string()), Some(private_key.is_compressed()))
                            }
                            None => (None, None),
                        };

                        let public_key = extended_public_key.to_public_key();
                        let address = public_key.to_address(&format)?;

                        BitcoinWallet {
                            path: final_path,
                            password: hd_values.password,
                            mnemonic,
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
                    }
                    _ => unreachable!(),
                };

                match options.json {
                    true => println!("{}\n", serde_json::to_string_pretty(&wallet)?),
                    false => println!("{}\n", wallet),
                };
            }

            Ok(())
        }

        match options.network.as_str() {
            "testnet" => output::<BitcoinTestnet>(options),
            _ => output::<BitcoinMainnet>(options),
        }
    }
}
