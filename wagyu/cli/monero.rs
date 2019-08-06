use crate::cli::{flag, option, subcommand, types::*, CLI, CLIError};
use crate::model::{Mnemonic, PrivateKey, PublicKey};
use crate::monero::{
    address::Format as MoneroFormat, Mainnet as MoneroMainnet, MoneroAddress,
    MoneroMnemonic, MoneroNetwork, MoneroPrivateKey, MoneroPublicKey, Stagenet as MoneroStagenet,
    Testnet as MoneroTestnet, wordlist::*
};

use clap::ArgMatches;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display, str::FromStr};
use monero::MoneroWordlist;

/// Represents custom options for a Monero wallet
#[derive(Serialize, Clone, Debug)]
pub struct MoneroOptions {
    pub wallet_values: Option<WalletValues>,
    pub count: usize,
    pub language: Option<String>,
    pub network: String,
    pub format: MoneroFormat,
    pub json: bool,
}

/// Represents values to derive standard wallets
#[derive(Serialize, Clone, Debug)]
pub struct WalletValues {
    pub mnemonic: Option<String>,
    pub private_spend_key: Option<String>,
    pub private_view_key: Option<String>,
    pub public_spend_key: Option<String>,
    pub public_view_key: Option<String>,
    pub address: Option<String>,
}

/// Represents a generic wallet to output
#[derive(Serialize, Debug, Default)]
struct MoneroWallet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_spend_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_view_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_spend_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_view_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

#[cfg_attr(tarpaulin, skip)]
impl Display for MoneroWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = [
            match &self.mnemonic {
                Some(mnemonic) => format!("      Mnemonic             {}\n", mnemonic),
                _ => "".to_owned(),
            },
            match &self.private_spend_key {
                Some(private_spend_key) => format!("      Private Spend Key    {}\n", private_spend_key),
                _ => "".to_owned(),
            },
            match &self.private_view_key {
                Some(private_view_key) => format!("      Private View Key     {}\n", private_view_key),
                _ => "".to_owned(),
            },
            match &self.public_spend_key {
                Some(public_spend_key) => format!("      Public Spend Key     {}\n", public_spend_key),
                _ => "".to_owned(),
            },
            match &self.public_view_key {
                Some(public_view_key) => format!("      Public View Key      {}\n", public_view_key),
                _ => "".to_owned(),
            },
            match &self.address {
                Some(address) => format!("      Address              {}\n", address),
                _ => "".to_owned(),
            },
            match &self.format {
                Some(format) => format!("      Format               {}\n", format),
                _ => "".to_owned(),
            },
            match &self.payment_id {
                Some(payment_id) => format!("      Payment ID           {}\n", payment_id),
                _ => "".to_owned(),
            },
            match &self.network {
                Some(network) => format!("      Network              {}\n", network),
                _ => "".to_owned(),
            },
        ]
        .concat();

        // Removes final new line character
        let output = output[..output.len() - 1].to_owned();
        write!(f, "\n{}", output)
    }
}

pub struct MoneroCLI;

impl CLI for MoneroCLI {
    type Options = MoneroOptions;

    const NAME: NameType = "monero";
    const ABOUT: AboutType = "Generates a Monero wallet (include -h for more options)";
    const FLAGS: &'static [FlagType] = &[flag::JSON];
    const OPTIONS: &'static [OptionType] = &[option::COUNT, option::INTEGRATED_MONERO, option::LANGUAGE_MONERO, option::NETWORK_MONERO, option::SUBADDRESS_MONERO];
    const SUBCOMMANDS: &'static [SubCommandType] = &[subcommand::IMPORT_MONERO];

    /// Handle all CLI arguments and flags for Monero
    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Result<Self::Options, CLIError> {
        let format = match (arguments.values_of("subaddress"), arguments.value_of("integrated")) {
            (Some(indices), None) => {
                let index: Vec<u32> = indices
                    .into_iter()
                    .map(|i| i.to_owned().parse::<u32>().unwrap())
                    .collect();
                MoneroFormat::Subaddress(index[0], index[1])
            }
            (None, Some(id)) => {
                let mut payment_id = [0u8; 8];
                payment_id.copy_from_slice(&hex::decode(id)?);
                MoneroFormat::Integrated(payment_id)
            }
            (None, None) => MoneroFormat::Standard,
            _ => unreachable!(),
        };

        let network = match arguments.value_of("network") {
            Some("testnet") => "testnet",
            Some("stagenet") => "stagenet",
            _ => "mainnet",
        };

        let mut options = MoneroOptions {
            wallet_values: None,
            count: clap::value_t!(arguments.value_of("count"), usize).unwrap_or_else(|_e| 1),
            language: arguments.value_of("language").map(|s| s.to_string()),
            network: network.to_owned(),
            format,
            json: arguments.is_present("json"),
        };

        match arguments.subcommand() {
            ("import", Some(import_matches)) => {
                let mnemonic = import_matches.value_of("mnemonic").map(|s| s.to_string());
                let private_spend_key = import_matches.value_of("private spend key").map(|s| s.to_string());
                let private_view_key = import_matches.value_of("private view key").map(|s| s.to_string());
                let public_spend_key = import_matches.value_of("public spend key").map(|s| s.to_string());
                let public_view_key = import_matches.value_of("public view key").map(|s| s.to_string());
                let address = import_matches.value_of("address").map(|s| s.to_string());

                options.format = match (import_matches.values_of("subaddress"), import_matches.value_of("integrated")) {
                    (Some(indices), None) => {
                        let index: Vec<u32> = indices
                            .into_iter()
                            .map(|i| i.to_owned().parse::<u32>().unwrap())
                            .collect();
                        Some(MoneroFormat::Subaddress(index[0], index[1]))
                    }
                    (None, Some(id)) => {
                        let mut payment_id = [0u8; 8];
                        payment_id.copy_from_slice(&hex::decode(id)?);
                        Some(MoneroFormat::Integrated(payment_id))
                    }
                    (None, None) => None,
                    _ => unreachable!(),
                }.or(Some(format)).unwrap();

                options.json |= import_matches.is_present("json");
                options.language = import_matches.value_of("language").map(|s| s.to_string()).or(options.language);
                options.network = import_matches
                    .value_of("network")
                    .unwrap_or(&options.network)
                    .to_string();

                options.wallet_values = Some(WalletValues {
                    mnemonic,
                    private_spend_key,
                    private_view_key,
                    public_spend_key,
                    public_view_key,
                    address,
                });
            }
            _ => {}
        };

        Ok(options)
    }

    /// Generate the Monero wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) -> Result<(), CLIError> {

        fn process_mnemonic<MN: MoneroNetwork, MW: MoneroWordlist>(mnemonic: Option<&str>, format: &MoneroFormat) -> Result<MoneroWallet, CLIError> {
            let mnemonic = match mnemonic {
                Some(mnemonic) => {
                    MoneroMnemonic::<MN, MW>::from_phrase(mnemonic)?
                },
                None => {
                    MoneroMnemonic::<MN, MW>::new(&mut StdRng::from_entropy())?
                }
            };

            let private_key = mnemonic.to_private_key(None)?;
            let private_spend_key = hex::encode(private_key.to_private_spend_key());
            let private_view_key = hex::encode(private_key.to_private_view_key());
            let public_key = private_key.to_public_key();
            let public_spend_key = hex::encode(public_key.to_public_spend_key().unwrap());
            let public_view_key = hex::encode(public_key.to_public_view_key().unwrap());
            let address = public_key.to_address(&format)?;
            let (format, payment_id) = match format {
                MoneroFormat::Integrated(payment_id)=> (Some("integrated".to_string()), Some(hex::encode(payment_id))),
                format => (Some(format.to_string()), None)
            };

            Ok(MoneroWallet {
                mnemonic: Some(mnemonic.to_string()),
                private_spend_key: Some(private_spend_key),
                private_view_key: Some(private_view_key),
                public_spend_key: Some(public_spend_key),
                public_view_key: Some(public_view_key),
                address: Some(address.to_string()),
                network: Some(MN::NAME.into()),
                format,
                payment_id,
                ..Default::default()
            })
        }

        fn output<N: MoneroNetwork>(options: MoneroOptions) -> Result<(), CLIError> {
            for _ in 0..options.count {
                let wallet = match options.wallet_values.to_owned() {
                    None => {
                        match options.language.as_ref().map(String::as_str) {
                            Some("chinese_simplified") => process_mnemonic::<N, ChineseSimplified>(None, &options.format)?,
                            Some("dutch") => process_mnemonic::<N, Dutch>(None, &options.format)?,
                            Some("english") => process_mnemonic::<N, English>(None, &options.format)?,
                            Some("esperanto") => process_mnemonic::<N, Esperanto>(None, &options.format)?,
                            Some("french") => process_mnemonic::<N, French>(None, &options.format)?,
                            Some("german") => process_mnemonic::<N, German>(None, &options.format)?,
                            Some("italian") => process_mnemonic::<N, Italian>(None, &options.format)?,
                            Some("japanese") => process_mnemonic::<N, Japanese>(None, &options.format)?,
                            Some("lojban") => process_mnemonic::<N, Lojban>(None, &options.format)?,
                            Some("portuguese") => process_mnemonic::<N, Portuguese>(None, &options.format)?,
                            Some("russian") => process_mnemonic::<N, Russian>(None, &options.format)?,
                            Some("spanish") => process_mnemonic::<N, Spanish>(None, &options.format)?,
                            _ => process_mnemonic::<N, English>(None, &options.format)?, // Default language - English
                        }
                    }
                    Some(wallet_values) => {

                        fn process_private_spend_key<MN: MoneroNetwork, MW: MoneroWordlist>(private_spend_key: &str, format: &MoneroFormat) -> Result<MoneroWallet, CLIError> {
                            match MoneroPrivateKey::<MN>::from_private_spend_key(private_spend_key, &format) {
                                Ok(private_key) => {
                                    let mut seed = [0u8; 32];
                                    seed.copy_from_slice(&hex::decode(private_spend_key)?);
                                    let mnemonic = MoneroMnemonic::<MN, MW>::from_seed(&seed)?.to_string();

                                    let public_key = private_key.to_public_key();
                                    let private_view_key = hex::encode(private_key.to_private_view_key());
                                    let public_spend_key = hex::encode(public_key.to_public_spend_key().unwrap());
                                    let public_view_key = hex::encode(public_key.to_public_view_key().unwrap());
                                    let address = public_key.to_address(&format)?;
                                    let (format, payment_id) = match format {
                                        MoneroFormat::Integrated(payment_id)=> (Some("integrated".to_string()), Some(hex::encode(payment_id))),
                                        format => (Some(format.to_string()), None)
                                    };

                                    Ok(MoneroWallet {
                                        mnemonic: Some(mnemonic),
                                        private_spend_key: Some(private_spend_key.into()),
                                        private_view_key: Some(private_view_key),
                                        public_spend_key: Some(public_spend_key),
                                        public_view_key: Some(public_view_key),
                                        address: Some(address.to_string()),
                                        network: Some(MN::NAME.into()),
                                        format,
                                        payment_id,
                                        ..Default::default()
                                    })
                                },
                                Err(error) => Err(CLIError::PrivateKeyError(error)),
                            }
                        }

                        fn process_private_view_key<MN: MoneroNetwork>(private_view_key: &str, format: &MoneroFormat) -> Result<MoneroWallet, CLIError> {
                            match MoneroPublicKey::<MN>::from_private_view_key(private_view_key, &format) {
                                Ok(public_key) =>
                                    Ok(MoneroWallet {
                                        private_view_key: Some(private_view_key.into()),
                                        public_view_key: Some(hex::encode(public_key.to_public_view_key().unwrap())),
                                        network: Some(MN::NAME.into()),
                                        ..Default::default()
                                    }),
                                Err(error) => Err(CLIError::PublicKeyError(error)),
                            }
                        }

                        fn process_public_key<MN: MoneroNetwork>(public_spend_key: &str, public_view_key: &str, format: &MoneroFormat) -> Result<MoneroWallet, CLIError> {
                            match MoneroPublicKey::<MN>::from(public_spend_key, public_view_key, &format) {
                                Ok(public_key) => {
                                    let address = public_key.to_address(&format)?;
                                    let (format, payment_id) = match format {
                                        MoneroFormat::Integrated(payment_id)=> (Some("integrated".to_string()), Some(hex::encode(payment_id))),
                                        format => (Some(format.to_string()), None)
                                    };

                                    Ok(MoneroWallet {
                                        public_spend_key: Some(public_spend_key.into()),
                                        public_view_key: Some(public_view_key.into()),
                                        address: Some(address.to_string()),
                                        network: Some(MN::NAME.into()),
                                        format,
                                        payment_id,
                                        ..Default::default()
                                    })
                                },
                                Err(error) => Err(CLIError::PublicKeyError(error)),
                            }
                        }

                        fn process_address<MN: MoneroNetwork>(address: &str) -> Result<MoneroWallet, CLIError> {
                            match MoneroAddress::<MN>::from_str(address) {
                                Ok(address) => {
                                    let (format, payment_id) = match address.format()? {
                                        MoneroFormat::Integrated(payment_id)=> (Some("integrated".to_string()), Some(hex::encode(payment_id))),
                                        format => (Some(format.to_string()), None)
                                    };

                                    Ok(MoneroWallet {
                                        address: Some(address.to_string()),
                                        network: Some(MN::NAME.into()),
                                        format,
                                        payment_id,
                                        ..Default::default()
                                    })
                                },
                                Err(error) => Err(CLIError::AddressError(error)),
                            }
                        }

                        match (
                            wallet_values.mnemonic.as_ref(),
                            wallet_values.private_spend_key.as_ref(),
                            wallet_values.private_view_key.as_ref(),
                            (wallet_values.public_spend_key.as_ref(), wallet_values.public_view_key.as_ref()),
                            wallet_values.address.as_ref(),
                        ) {
                            (Some(mnemonic), None, None, _, None) => {
                                process_mnemonic::<N, ChineseSimplified>(Some(mnemonic), &options.format)
                                    .or(process_mnemonic::<N, Dutch>(Some(mnemonic), &options.format))
                                    .or(process_mnemonic::<N, English>(Some(mnemonic), &options.format))
                                    .or(process_mnemonic::<N, Esperanto>(Some(mnemonic), &options.format))
                                    .or(process_mnemonic::<N, French>(Some(mnemonic), &options.format))
                                    .or(process_mnemonic::<N, German>(Some(mnemonic), &options.format))
                                    .or(process_mnemonic::<N, Italian>(Some(mnemonic), &options.format))
                                    .or(process_mnemonic::<N, Japanese>(Some(mnemonic), &options.format))
                                    .or(process_mnemonic::<N, Lojban>(Some(mnemonic), &options.format))
                                    .or(process_mnemonic::<N, Portuguese>(Some(mnemonic), &options.format))
                                    .or(process_mnemonic::<N, Russian>(Some(mnemonic), &options.format))
                                    .or(process_mnemonic::<N, Spanish>(Some(mnemonic), &options.format))?
                            }
                            (None, Some(private_spend_key), None, _, None) => {
                                match options.language.as_ref().map(String::as_str) {
                                    Some("chinese_simplified") => process_private_spend_key::<N, ChineseSimplified>(&private_spend_key, &options.format)?,
                                    Some("dutch") => process_private_spend_key::<N, Dutch>(&private_spend_key, &options.format)?,
                                    Some("english") => process_private_spend_key::<N, English>(&private_spend_key, &options.format)?,
                                    Some("esperanto") => process_private_spend_key::<N, Esperanto>(&private_spend_key, &options.format)?,
                                    Some("french") => process_private_spend_key::<N, French>(&private_spend_key, &options.format)?,
                                    Some("german") => process_private_spend_key::<N, German>(&private_spend_key, &options.format)?,
                                    Some("italian") => process_private_spend_key::<N, Italian>(&private_spend_key, &options.format)?,
                                    Some("japanese") => process_private_spend_key::<N, Japanese>(&private_spend_key, &options.format)?,
                                    Some("lojban") => process_private_spend_key::<N, Lojban>(&private_spend_key, &options.format)?,
                                    Some("portuguese") => process_private_spend_key::<N, Portuguese>(&private_spend_key, &options.format)?,
                                    Some("russian") => process_private_spend_key::<N, Russian>(&private_spend_key, &options.format)?,
                                    Some("spanish") => process_private_spend_key::<N, Spanish>(&private_spend_key, &options.format)?,
                                    _ => process_private_spend_key::<N, English>(&private_spend_key, &options.format)?, // Default language - English
                                }
                            }
                            (None, None, Some(private_view_key), _, None) => {
                                process_private_view_key::<N>(&private_view_key, &options.format)?
                            }
                            (None, None, None, (Some(public_spend_key), Some(public_view_key)), None) => {
                                process_public_key::<N>(&public_spend_key, &public_view_key, &options.format)?
                            }
                            (None, None, None, _, Some(address)) => {
                                let main = process_address::<MoneroMainnet>(&address);
                                let stage = process_address::<MoneroStagenet>(&address);
                                let test = process_address::<MoneroTestnet>(&address);
                                main.or(stage).or(test)?
                            }
                            _ => unreachable!(),
                        }
                    }
                };

                match options.json {
                    true => println!("{}\n", serde_json::to_string_pretty(&wallet)?),
                    false => println!("{}\n", wallet),
                };
            }

            Ok(())
        }

        match options.network.as_str() {
            "testnet" => output::<MoneroTestnet>(options),
            "stagenet" => output::<MoneroStagenet>(options),
            _ => output::<MoneroMainnet>(options),
        }
    }
}
