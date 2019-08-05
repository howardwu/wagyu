use crate::cli::{flag, option, subcommand, types::*, CLI, CLIError};
use crate::model::{ExtendedPrivateKey, ExtendedPublicKey, PrivateKey, PublicKey};
use crate::zcash::{
    address::Format as ZcashFormat, ZcashAddress, ZcashDerivationPath, ZcashNetwork,
    ZcashPrivateKey, ZcashPublicKey, Mainnet as ZcashMainnet, SpendingKey,
    Testnet as ZcashTestnet,
};

use zcash::{ZcashExtendedPrivateKey, ZcashExtendedPublicKey, ViewingKey};
use clap::ArgMatches;
use rand::Rng;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display, str::FromStr};

/// Represents custom options for a Zcash wallet
#[derive(Serialize, Clone, Debug)]
pub struct ZcashOptions {
    pub wallet_values: Option<WalletValues>,
    pub hd_values: Option<HdValues>,
    pub count: usize,
    pub diversifier: Option<String>,
    pub network: String,
    pub format: ZcashFormat,
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
    pub extended_private_key: Option<String>,
    pub extended_public_key: Option<String>,
    pub index: Option<String>,
}

/// Represents a generic wallet to output
#[derive(Serialize, Debug, Default)]
struct ZcashWallet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
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
    pub diversifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

#[cfg_attr(tarpaulin, skip)]
impl Display for ZcashWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = [
            match &self.path {
                Some(path) => format!("      Path:                 {}\n", path),
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
                Some(public_key) => format!("      Public Key:           {}\n", public_key),
                _ => "".to_owned(),
            },
            format!("      Address:              {}\n", self.address),
            match &self.format {
                Some(format) => format!("      Format:               {}\n", format),
                _ => "".to_owned(),
            },
            match &self.diversifier {
                Some(diversifier) => format!("      Diversifier:          {}\n", diversifier),
                _ => "".to_owned(),
            },
            match &self.network {
                Some(network) => format!("      Network:              {}\n", network),
                _ => "".to_owned(),
            },
        ]
            .concat();

        // Removes final new line character
        let output = output[..output.len() - 1].to_owned();
        write!(f, "\n{}", output)
    }
}

pub struct ZcashCLI;

impl CLI for ZcashCLI {
    type Options = ZcashOptions;

    const NAME: NameType = "zcash";
    const ABOUT: AboutType = "Generates a Zcash wallet (include -h for more options)";
    const FLAGS: &'static [FlagType] = &[flag::JSON];
    const OPTIONS: &'static [OptionType] = &[option::COUNT, option::DIVERSIFIER_ZCASH, option::FORMAT_ZCASH, option::NETWORK_ZCASH];
    const SUBCOMMANDS: &'static [SubCommandType] = &[
        subcommand::HD_ZCASH,
        subcommand::IMPORT_ZCASH,
        subcommand::IMPORT_HD_ZCASH,
    ];

    /// Handle all CLI arguments and flags for Zcash
    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Result<Self::Options, CLIError> {
        let mut format = arguments.value_of("format");
        let network = match arguments.value_of("network") {
            Some("testnet") => "testnet",
            _ => "mainnet",
        };

        let mut options = ZcashOptions {
            wallet_values: None,
            hd_values: None,
            count: clap::value_t!(arguments.value_of("count"), usize).unwrap_or_else(|_e| 1),
            diversifier: arguments.value_of("diversifier").map(|s| s.to_string()),
            network: network.to_owned(),
            format: ZcashFormat::P2PKH,
            json: arguments.is_present("json"),
        };

        match arguments.subcommand() {
            ("hd", Some(hd_matches)) => {
                format = hd_matches.value_of("format").or(format);
                options.count = clap::value_t!(hd_matches.value_of("count"), usize).unwrap_or(options.count);
                options.diversifier = hd_matches.value_of("diversifier").map(|s| s.to_string()).or(options.diversifier);
                options.json |= hd_matches.is_present("json");
                options.network = hd_matches.value_of("network").unwrap_or(&options.network).to_string();

                options.hd_values = Some(HdValues {
                    ..Default::default()
                });
            }
            ("import", Some(import_matches)) => {
                let address = import_matches.value_of("address").map(|s| s.to_string());
                let public_key = import_matches.value_of("public key").map(|s| s.to_string());
                let private_key = import_matches.value_of("private key").map(|s| s.to_string());

                options.diversifier = import_matches.value_of("diversifier").map(|s| s.to_string()).or(options.diversifier);
                options.json |= import_matches.is_present("json");
//                options.network = import_matches
//                    .value_of("network")
//                    .unwrap_or(&options.network)
//                    .to_string();

                options.wallet_values = Some(WalletValues {
                    address,
                    public_key,
                    private_key,
                });
            }
            ("import-hd", Some(import_hd_matches)) => {
                let account = import_hd_matches.value_of("account").map(|i| i.to_string());
                let extended_private_key = import_hd_matches.value_of("extended private").map(|s| s.to_string());
                let extended_public_key = import_hd_matches.value_of("extended public").map(|s| s.to_string());
                let index = import_hd_matches.value_of("index").map(|i| i.to_string());

                format = import_hd_matches.value_of("format").or(format);
                options.diversifier = import_hd_matches.value_of("diversifier").map(|s| s.to_string()).or(options.diversifier);
                options.json |= import_hd_matches.is_present("json");
                options.network = import_hd_matches
                    .value_of("network")
                    .unwrap_or(&options.network)
                    .to_string();

                options.hd_values = Some(HdValues {
                    account,
                    extended_private_key,
                    extended_public_key,
                    index,
                    ..Default::default()
                });
            }
            _ => {}
        };

        options.format = match format {
            Some("sapling") => {
                match options.diversifier.as_ref() {
                    Some(div) => {
                        let mut diversifier =  [0u8; 11];
                        diversifier.copy_from_slice(&hex::decode(div)?);
                        ZcashFormat::Sapling(Some(diversifier))
                    }
                    None => ZcashFormat::Sapling(None),
                }
            },
            Some("sprout") => ZcashFormat::Sprout,
            _ => ZcashFormat::P2PKH,
        };

        Ok(options)
    }

    /// Generate the Zcash wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) -> Result<(), CLIError> {

        fn output<N: ZcashNetwork>(options: ZcashOptions) -> Result<(), CLIError> {
            for _ in 0..options.count {
                let wallet = match (options.wallet_values.to_owned(), options.hd_values.to_owned()) {
                    (None, None) => {
                        let private_key = match options.format {
                            ZcashFormat::Sapling(_) => ZcashPrivateKey::<N>::new_sapling(&mut StdRng::from_entropy())?,
                            ZcashFormat::Sprout => ZcashPrivateKey::<N>::new_sprout(&mut StdRng::from_entropy())?,
                            ZcashFormat::P2PKH => ZcashPrivateKey::<N>::new_p2pkh(&mut StdRng::from_entropy())?,
                            _ => unreachable!()
                        };
                        let public_key = private_key.to_public_key();
                        let address = public_key.to_address(&options.format)?;
                        let address_format: Vec<String> = address.format().to_string().split(" ").map(|s| s.to_owned()).collect();
                        let diversifier: Option<String> = match ZcashAddress::<N>::get_diversifier(&address.to_string()) {
                            Ok(diversifier) => Some(hex::encode(diversifier)),
                            _ => None,
                        };

                        ZcashWallet {
                            private_key: Some(private_key.to_string()),
                            public_key: Some(public_key.to_string()),
                            address: address.to_string(),
                            network: Some(options.network.to_owned()),
                            format: Some(address_format[0].to_string()),
                            diversifier,
                            ..Default::default()
                        }
                    }
                    (Some(wallet_values), None) => {
                        fn process_private_key<N:ZcashNetwork>(private_key: &str, diversifier: &Option<String>) -> Result<Option<ZcashWallet>, CLIError> {
                            match ZcashPrivateKey::<N>::from_str(&private_key) {
                                Ok(private_key) => {
                                    let format = match private_key.to_spending_key() {
                                        SpendingKey::P2PKH(_) => ZcashFormat::P2PKH,
                                        SpendingKey::P2SH(_) => ZcashFormat::P2SH,
                                        SpendingKey::Sprout(_) => ZcashFormat::Sprout,
                                        SpendingKey::Sapling(_) => {
                                            match diversifier {
                                                Some(div) => {
                                                    let mut diversifier =  [0u8; 11];
                                                    diversifier.copy_from_slice(&hex::decode(div)?);
                                                    ZcashFormat::Sapling(Some(diversifier))
                                                },
                                                None => ZcashFormat::Sapling(None),
                                            }
                                        },
                                    };

                                    let public_key = private_key.to_public_key();
                                    let address = public_key.to_address(&format)?;
                                    let address_format: Vec<String> = address.format().to_string().split(" ").map(|s| s.to_owned()).collect();
                                    let diversifier: Option<String> = match ZcashAddress::<N>::get_diversifier(&address.to_string()) {
                                        Ok(diversifier) => Some(hex::encode(diversifier)),
                                        _ => None,
                                    };

                                    Ok(Some(ZcashWallet {
                                        private_key: Some(private_key.to_string()),
                                        public_key: Some(public_key.to_string()),
                                        address: address.to_string(),
                                        network: Some(N::NAME.to_string()),
                                        format: Some(address_format[0].to_string()),
                                        diversifier,
                                        ..Default::default()
                                    }))
                                }
                                _ => Ok(None),
                            }
                        }

                        fn process_public_key<N:ZcashNetwork>(public_key: &str, diversifier: &Option<String>) -> Result<Option<ZcashWallet>, CLIError> {
                            match ZcashPublicKey::<N>::from_str(&public_key) {
                                Ok(public_key) => {
                                    let format = match public_key.to_viewing_key() {
                                        ViewingKey::P2PKH(_) => ZcashFormat::P2PKH,
                                        ViewingKey::P2SH(_) => ZcashFormat::P2SH,
                                        ViewingKey::Sprout(_) => ZcashFormat::Sprout,
                                        ViewingKey::Sapling(_) => {
                                            match diversifier {
                                                Some(div) => {
                                                    let mut diversifier =  [0u8; 11];
                                                    diversifier.copy_from_slice(&hex::decode(div)?);
                                                    ZcashFormat::Sapling(Some(diversifier))
                                                },
                                                None => ZcashFormat::Sapling(None),
                                            }
                                        },
                                    };

                                    let address = public_key.to_address(&format)?;
                                    let address_format: Vec<String> = address.format().to_string().split(" ").map(|s| s.to_owned()).collect();
                                    let diversifier: Option<String> = match ZcashAddress::<N>::get_diversifier(&address.to_string()) {
                                        Ok(diversifier) => Some(hex::encode(diversifier)),
                                        _ => None,
                                    };

                                    Ok(Some(ZcashWallet {
                                        public_key: Some(public_key.to_string()),
                                        address: address.to_string(),
                                        network: Some(N::NAME.to_string()),
                                        format: Some(address_format[0].to_string()),
                                        diversifier,
                                        ..Default::default()
                                    }))
                                }
                                _ => Ok(None),
                            }
                        }

                        fn process_address<N: ZcashNetwork>(address: &str) -> Option<ZcashWallet> {
                            match ZcashAddress::<N>::from_str(&address) {
                                Ok(address) => {
                                    let address_format: Vec<String> = address.format().to_string().split(" ").map(|s| s.to_owned()).collect();
                                    let diversifier: Option<String> = match ZcashAddress::<N>::get_diversifier(&address.to_string()) {
                                        Ok(diversifier) => Some(hex::encode(diversifier)),
                                        _ => None,
                                    };

                                    Some(ZcashWallet {
                                        address: address.to_string(),
                                        network: Some(N::NAME.to_string()),
                                        format: Some(address_format[0].to_string()),
                                        diversifier,
                                        ..Default::default()
                                    })
                                },
                                _ => None,
                            }
                        }

                        match (
                            wallet_values.private_key.as_ref(),
                            wallet_values.public_key.as_ref(),
                            wallet_values.address.as_ref(),
                        ) {
                            (Some(private_key), None, None) => {
                                let sapling_check = process_private_key::<N>(&private_key, &options.diversifier)?; // No network prefix for sapling private key
                                let main = process_private_key::<ZcashMainnet>(&private_key, &options.diversifier)?;
                                let test = process_private_key::<ZcashTestnet>(&private_key, &options.diversifier)?;
                                sapling_check.or(main).or(test).unwrap()
                            }
                            (None, Some(public_key), None) => {
                                let sapling_check = process_public_key::<N>(&public_key, &options.diversifier)?; // No network prefix for sapling public key
                                let main = process_public_key::<ZcashMainnet>(&public_key, &options.diversifier)?;
                                let test = process_public_key::<ZcashTestnet>(&public_key, &options.diversifier)?;
                                sapling_check.or(main).or(test).unwrap()
                            }
                            (None, None, Some(address)) => {
                                let main = process_address::<ZcashMainnet>(&address);
                                let test = process_address::<ZcashTestnet>(&address);
                                main.or(test).unwrap()
                            },
                            _ => unreachable!(),
                        }
                    }
                    (None, Some(hd_values)) => {
                        let format = options.format.clone();
                        let account = hd_values.account.unwrap_or("0".to_string());
                        let index = hd_values.index.unwrap_or("0".to_string());
                        let path: Option<String> = Some(format!("m/44'/133'/{}'/{}", account, index));

                        let (extended_private_key, extended_public_key) = match (
                            hd_values.extended_private_key,
                            hd_values.extended_public_key,
                        ) {
                            (None, None) => {
                                let rng = &mut StdRng::from_entropy();
                                let seed: [u8; 32] = rng.gen();
                                let path = ZcashDerivationPath::from_str(&path.as_ref().unwrap())?;
                                let extended_private_key = ZcashExtendedPrivateKey::<N>::new(&seed, &ZcashFormat::Sapling(None), &path)?;
                                let extended_public_key = extended_private_key.to_extended_public_key();
                                (Some(extended_private_key), extended_public_key)
                            }
                            (Some(extended_private_key), None) => {
                                let mut extended_private_key = ZcashExtendedPrivateKey::from_str(&extended_private_key)?;
                                extended_private_key = extended_private_key
                                    .derive(&ZcashDerivationPath::from_str(&path.as_ref().unwrap())?)?;
                                let extended_public_key = extended_private_key.to_extended_public_key();
                                (Some(extended_private_key), extended_public_key)
                            }
                            (None, Some(extended_public_key)) => {
                                let mut extended_public_key =
                                    ZcashExtendedPublicKey::from_str(&extended_public_key)?;
                                extended_public_key = extended_public_key
                                    .derive(&ZcashDerivationPath::from_str(&path.as_ref().unwrap())?)?;
                                (None, extended_public_key)
                            }
                            _ => unreachable!(),
                        };

                        let private_key = match extended_private_key.as_ref() {
                            Some(extended_private_key) => {
                                let private_key = extended_private_key.to_private_key();
                                Some(private_key.to_string())
                            }
                            None => None,
                        };

                        let public_key = extended_public_key.to_public_key();
                        let address = public_key.to_address(&format)?;

                        ZcashWallet {
                            path,
                            extended_private_key: extended_private_key.map(|key| key.to_string()),
                            extended_public_key: Some(extended_public_key.to_string()),
                            private_key,
                            public_key: Some(public_key.to_string()),
                            address: address.to_string(),
                            network: Some(options.network.to_owned()),
                            format: Some(address.format().to_string()),
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
            "testnet" => output::<ZcashTestnet>(options),
            _ => output::<ZcashMainnet>(options),
        }
    }
}
