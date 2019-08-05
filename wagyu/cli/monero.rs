use crate::cli::{flag, option, subcommand, types::*, CLI, CLIError};
use crate::model::{Mnemonic, PrivateKey, PublicKey};
use crate::monero::{
    address::Format as MoneroFormat, English as MoneroEnglish, Mainnet as MoneroMainnet, MoneroAddress,
    MoneroMnemonic, MoneroNetwork, MoneroPrivateKey, MoneroPublicKey, Stagenet as MoneroStagenet,
    Testnet as MoneroTestnet,
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
    const OPTIONS: &'static [OptionType] = &[option::COUNT, option::INTEGRATED_MONERO, option::NETWORK_MONERO, option::SUBADDRESS_MONERO];
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

                options.json = options.json || import_matches.is_present("json");
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

        fn output<N: MoneroNetwork, W: MoneroWordlist>(options: MoneroOptions) -> Result<(), CLIError> {
            for _ in 0..options.count {
                let wallet = match options.wallet_values.to_owned() {
                    None => {
                        let mnemonic = MoneroMnemonic::<N, W>::new(&mut StdRng::from_entropy())?;
                        let private_key = mnemonic.to_private_key(None)?;
                        let public_key = private_key.to_public_key();

                        let private_spend_key = hex::encode(private_key.to_private_spend_key());
                        let private_view_key = hex::encode(private_key.to_private_view_key());
                        let public_spend_key = hex::encode(public_key.to_public_spend_key().unwrap());
                        let public_view_key = hex::encode(public_key.to_public_view_key().unwrap());
                        let address = public_key.to_address(&options.format)?;

                        MoneroWallet {
                            mnemonic: Some(mnemonic.to_string()),
                            private_spend_key: Some(private_spend_key),
                            private_view_key: Some(private_view_key),
                            public_spend_key: Some(public_spend_key),
                            public_view_key: Some(public_view_key),
                            address: Some(address.to_string()),
                            network: Some(options.network.to_owned()),
                            format: Some(options.format.to_string()),
                            ..Default::default()
                        }
                    }
                    Some(wallet_values) => {

                        fn process_private_spend_key<MN: MoneroNetwork, MW: MoneroWordlist>(private_spend_key: &str, format: &MoneroFormat) -> Result<Option<MoneroWallet>, CLIError> {
                            match MoneroPrivateKey::<MN>::from_private_spend_key(private_spend_key, &format) {
                                Ok(private_key) => {
                                    let mnemonic = match format {
                                        MoneroFormat::Standard => {
                                            let buffer = hex::decode(private_spend_key)?;
                                            let mut seed = [0u8; 32];
                                            seed.copy_from_slice(&buffer);
                                            Some(MoneroMnemonic::<MN, MW>::from_seed(&seed)?.to_string())
                                        },
                                        _ => None
                                    };
                                    let public_key = private_key.to_public_key();

                                    let private_view_key = hex::encode(private_key.to_private_view_key());
                                    let public_spend_key = hex::encode(public_key.to_public_spend_key().unwrap());
                                    let public_view_key = hex::encode(public_key.to_public_view_key().unwrap());
                                    let address = public_key.to_address(&format).unwrap();

                                    Ok(Some(MoneroWallet {
                                        mnemonic,
                                        private_spend_key: Some(private_spend_key.into()),
                                        private_view_key: Some(private_view_key),
                                        public_spend_key: Some(public_spend_key),
                                        public_view_key: Some(public_view_key),
                                        address: Some(address.to_string()),
                                        network: Some(MN::NAME.into()),
                                        format: Some(format.to_string()),
                                        ..Default::default()
                                    }))
                                },
                                _ => Ok(None)
                            }
                        }

                        fn process_private_view_key<MN: MoneroNetwork>(private_view_key: &str, format: &MoneroFormat) -> Result<Option<MoneroWallet>, CLIError> {
                            match MoneroPublicKey::<MN>::from_private_view_key(private_view_key, &format) {
                                Ok(public_key) => {
                                    let public_view_key = hex::encode(public_key.to_public_view_key().unwrap());

                                    Ok(Some(MoneroWallet {
                                        private_view_key: Some(private_view_key.into()),
                                        public_view_key: Some(public_view_key),
                                        network: Some(MN::NAME.into()),
                                        ..Default::default()
                                    }))
                                },
                                _ => Ok(None)
                            }
                        }

                        fn process_public_key<MN: MoneroNetwork>(public_spend_key: &str, public_view_key: &str, format: &MoneroFormat) -> Result<Option<MoneroWallet>, CLIError> {
                            match MoneroPublicKey::<MN>::from(public_spend_key, public_view_key, &format) {
                                Ok(public_key) => {
                                    let address = public_key.to_address(&format)?;

                                    Ok(Some(MoneroWallet {
                                        public_spend_key: Some(public_spend_key.into()),
                                        public_view_key: Some(public_view_key.into()),
                                        address: Some(address.to_string()),
                                        network: Some(MN::NAME.into()),
                                        format: Some(format.to_string()),
                                        ..Default::default()
                                    }))
                                },
                                _ => Ok(None)
                            }
                        }

                        fn process_address<MN: MoneroNetwork>(address: &str, format: &MoneroFormat) -> Result<Option<MoneroWallet>, CLIError> {
                            match MoneroAddress::<MN>::from_str(address) {
                                Ok(address) => {
                                    Ok(Some(MoneroWallet {
                                        address: Some(address.to_string()),
                                        network: Some(MN::NAME.into()),
                                        format: match *format == address.format()? {
                                            true => Some(format.to_string()),
                                            false => Some(address.format()?.to_string())
                                        },
                                        ..Default::default()
                                    }))
                                },
                                _ => Ok(None)
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
                                let mnemonic = MoneroMnemonic::<N, W>::from_phrase(&mnemonic).unwrap();
                                let private_spend_key = hex::encode(mnemonic.to_private_key(None).unwrap().to_private_spend_key());
                                process_private_spend_key::<N, W>(&private_spend_key, &options.format)?.unwrap()
                            }
                            (None, Some(private_spend_key), None, _, None) => {
                                process_private_spend_key::<N, W>(&private_spend_key, &options.format)?.unwrap()
                            }
                            (None, None, Some(private_view_key), _, None) => {
                                process_private_view_key::<N>(&private_view_key, &options.format)?.unwrap()
                            }
                            (None, None, None, (Some(public_spend_key), Some(public_view_key)), None) => {
                                process_public_key::<N>(&public_spend_key, &public_view_key, &options.format)?.unwrap()
                            }
                            (None, None, None, _, Some(address)) => {
                                let main = process_address::<MoneroMainnet>(&address, &options.format)?;
                                let stage = process_address::<MoneroStagenet>(&address, &options.format)?;
                                let test = process_address::<MoneroTestnet>(&address, &options.format)?;
                                main.or(stage).or(test).unwrap()
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
            "testnet" => output::<MoneroTestnet, MoneroEnglish>(options),
            "stagenet" => output::<MoneroStagenet, MoneroEnglish>(options),
            _ => output::<MoneroMainnet, MoneroEnglish>(options),
        }
    }
}
