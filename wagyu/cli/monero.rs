use crate::cli::{flag, option, subcommand, types::*, CLIError, CLI};
use crate::model::{Mnemonic, PrivateKey, PublicKey};
use crate::monero::{
    address::Format as MoneroFormat, wordlist::*, Mainnet as MoneroMainnet, MoneroAddress, MoneroMnemonic,
    MoneroNetwork, MoneroPublicKey, MoneroWordlist, Stagenet as MoneroStagenet, Testnet as MoneroTestnet,
};

use clap::{ArgMatches, Values};
use rand::rngs::StdRng;
use rand::Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display, str::FromStr};

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

impl MoneroWallet {
    pub fn new<N: MoneroNetwork, W: MoneroWordlist, R: Rng>(
        rng: &mut R,
        format: &MoneroFormat,
    ) -> Result<Self, CLIError> {
        let mnemonic = MoneroMnemonic::<N, W>::new(rng)?;
        let private_key = mnemonic.to_private_key(None)?;
        let private_spend_key = private_key.to_private_spend_key();
        let private_view_key = private_key.to_private_view_key();
        let public_key = private_key.to_public_key();
        let public_spend_key = public_key.to_public_spend_key().unwrap();
        let public_view_key = public_key.to_public_view_key().unwrap();
        let address = public_key.to_address(format)?;
        let (format, payment_id) = match format {
            MoneroFormat::Integrated(payment_id) => ("integrated".into(), Some(hex::encode(payment_id))),
            format => (format.to_string(), None),
        };
        Ok(Self {
            mnemonic: Some(mnemonic.to_string()),
            private_spend_key: Some(hex::encode(private_spend_key)),
            private_view_key: Some(hex::encode(private_view_key)),
            public_spend_key: Some(hex::encode(public_spend_key)),
            public_view_key: Some(hex::encode(public_view_key)),
            address: Some(address.to_string()),
            format: Some(format.to_string()),
            payment_id,
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_mnemonic<N: MoneroNetwork, W: MoneroWordlist>(
        mnemonic: &str,
        format: &MoneroFormat,
    ) -> Result<Self, CLIError> {
        let mnemonic = MoneroMnemonic::<N, W>::from_phrase(&mnemonic)?;
        let private_key = mnemonic.to_private_key(None)?;
        let private_spend_key = private_key.to_private_spend_key();
        let private_view_key = private_key.to_private_view_key();
        let public_key = private_key.to_public_key();
        let public_spend_key = public_key.to_public_spend_key().unwrap();
        let public_view_key = public_key.to_public_view_key().unwrap();
        let address = public_key.to_address(format)?;
        let (format, payment_id) = match format {
            MoneroFormat::Integrated(payment_id) => ("integrated".into(), Some(hex::encode(payment_id))),
            format => (format.to_string(), None),
        };
        Ok(Self {
            mnemonic: Some(mnemonic.to_string()),
            private_spend_key: Some(hex::encode(private_spend_key)),
            private_view_key: Some(hex::encode(private_view_key)),
            public_spend_key: Some(hex::encode(public_spend_key)),
            public_view_key: Some(hex::encode(public_view_key)),
            address: Some(address.to_string()),
            format: Some(format),
            payment_id,
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_private_spend_key<N: MoneroNetwork, W: MoneroWordlist>(
        private_spend_key: &str,
        format: &MoneroFormat,
    ) -> Result<Self, CLIError> {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hex::decode(private_spend_key)?);
        let mnemonic = MoneroMnemonic::<N, W>::from_seed(&seed)?;
        let private_key = mnemonic.to_private_key(None)?;
        if private_spend_key.to_string() != hex::encode(private_key.to_private_spend_key()) {
            return Err(CLIError::InvalidMnemonicForPrivateSpendKey);
        }
        let private_spend_key = private_key.to_private_spend_key();
        let private_view_key = private_key.to_private_view_key();
        let public_key = private_key.to_public_key();
        let public_spend_key = public_key.to_public_spend_key().unwrap();
        let public_view_key = public_key.to_public_view_key().unwrap();
        let address = public_key.to_address(format)?;
        let (format, payment_id) = match format {
            MoneroFormat::Integrated(payment_id) => ("integrated".into(), Some(hex::encode(payment_id))),
            format => (format.to_string(), None),
        };
        Ok(Self {
            private_spend_key: Some(hex::encode(private_spend_key)),
            private_view_key: Some(hex::encode(private_view_key)),
            public_spend_key: Some(hex::encode(public_spend_key)),
            public_view_key: Some(hex::encode(public_view_key)),
            address: Some(address.to_string()),
            format: Some(format),
            payment_id,
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_private_view_key<N: MoneroNetwork>(
        private_view_key: &str,
        format: &MoneroFormat,
    ) -> Result<Self, CLIError> {
        let public_key = MoneroPublicKey::<N>::from_private_view_key(private_view_key, format)?;
        let public_view_key = public_key.to_public_view_key().unwrap();
        Ok(Self {
            private_view_key: Some(private_view_key.into()),
            public_view_key: Some(hex::encode(public_view_key)),
            format: Some(format.to_string()),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_public_key<N: MoneroNetwork>(
        public_spend_key: &str,
        public_view_key: &str,
        format: &MoneroFormat,
    ) -> Result<Self, CLIError> {
        let public_key = MoneroPublicKey::<N>::from(public_spend_key, public_view_key, format)?;
        let public_spend_key = public_key.to_public_spend_key().unwrap();
        let public_view_key = public_key.to_public_view_key().unwrap();
        let address = public_key.to_address(format)?;
        let (format, payment_id) = match format {
            MoneroFormat::Integrated(payment_id) => ("integrated".into(), Some(hex::encode(payment_id))),
            format => (format.to_string(), None),
        };
        Ok(Self {
            public_spend_key: Some(hex::encode(public_spend_key)),
            public_view_key: Some(hex::encode(public_view_key)),
            address: Some(address.to_string()),
            format: Some(format),
            payment_id,
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_address<N: MoneroNetwork>(address: &str) -> Result<Self, CLIError> {
        let address = MoneroAddress::<N>::from_str(address)?;
        let (format, payment_id) = match address.format()? {
            MoneroFormat::Integrated(payment_id) => ("integrated".into(), Some(hex::encode(payment_id))),
            format => (format.to_string(), None),
        };
        Ok(Self {
            address: Some(address.to_string()),
            network: Some(N::NAME.to_string()),
            format: Some(format),
            payment_id,
            ..Default::default()
        })
    }
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

/// Represents options for a Monero wallet
#[derive(Serialize, Clone, Debug)]
pub struct MoneroOptions {
    // Standard
    count: usize,
    format: MoneroFormat,
    json: bool,
    language: String,
    network: String,
    subcommand: Option<String>,
    // Import
    address: Option<String>,
    mnemonic: Option<String>,
    private_spend_key: Option<String>,
    private_view_key: Option<String>,
    public_spend_key: Option<String>,
    public_view_key: Option<String>,
}

impl Default for MoneroOptions {
    fn default() -> Self {
        Self {
            // Standard command
            count: 1,
            format: MoneroFormat::Standard,
            json: false,
            language: "english".into(),
            network: "mainnet".into(),
            subcommand: None,
            // Import subcommand
            address: None,
            mnemonic: None,
            private_spend_key: None,
            private_view_key: None,
            public_spend_key: None,
            public_view_key: None,
        }
    }
}

impl MoneroOptions {
    fn parse(&mut self, arguments: &ArgMatches, options: &[&str]) {
        options.iter().for_each(|option| match *option {
            "address" => self.address(arguments.value_of(option)),
            "count" => self.count(clap::value_t!(arguments.value_of(*option), usize).ok()),
            "integrated" => self.integrated(arguments.value_of(option)),
            "json" => self.json(arguments.is_present(option)),
            "language" => self.language(arguments.value_of(option)),
            "mnemonic" => self.mnemonic(arguments.value_of(option)),
            "network" => self.network(arguments.value_of(option)),
            "private spend" => self.private_spend(arguments.value_of(option)),
            "private view" => self.private_view(arguments.value_of(option)),
            "public spend" => self.public_spend(arguments.value_of(option)),
            "public view" => self.public_view(arguments.value_of(option)),
            "subaddress" => self.subaddress(arguments.values_of(option)),
            _ => (),
        });
    }

    /// Sets `address` to the specified address, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn address(&mut self, argument: Option<&str>) {
        if let Some(address) = argument {
            self.address = Some(address.to_string());
        }
    }

    /// Sets `count` to the specified count, overriding its previous state.
    fn count(&mut self, argument: Option<usize>) {
        if let Some(count) = argument {
            self.count = count;
        }
    }

    /// Sets `format` to an integrated address with the specified payment ID, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn integrated(&mut self, argument: Option<&str>) {
        if let Some(id) = argument {
            let mut payment_id = [0u8; 8];
            payment_id.copy_from_slice(&hex::decode(id).unwrap());
            self.format = MoneroFormat::Integrated(payment_id);
        }
    }

    /// Sets `json` to the specified boolean value, overriding its previous state.
    fn json(&mut self, argument: bool) {
        self.json = argument;
    }

    /// Sets `language` to the specified language, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn language(&mut self, argument: Option<&str>) {
        match argument {
            Some("chinese_simplified") => self.language = "chinese_simplified".into(),
            Some("dutch") => self.language = "dutch".into(),
            Some("english") => self.language = "english".into(),
            Some("english_old") => self.language = "english_old".into(),
            Some("esperanto") => self.language = "esperanto".into(),
            Some("french") => self.language = "french".into(),
            Some("german") => self.language = "german".into(),
            Some("italian") => self.language = "italian".into(),
            Some("japanese") => self.language = "japanese".into(),
            Some("lojban") => self.language = "lojban".into(),
            Some("portuguese") => self.language = "portuguese".into(),
            Some("russian") => self.language = "russian".into(),
            Some("spanish") => self.language = "spanish".into(),
            _ => (),
        };
    }

    /// Sets `mnemonic` to the specified mnemonic, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn mnemonic(&mut self, argument: Option<&str>) {
        if let Some(mnemonic) = argument {
            self.mnemonic = Some(mnemonic.to_string());
        }
    }

    /// Sets `network` to the specified network, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn network(&mut self, argument: Option<&str>) {
        match argument {
            Some("mainnet") => self.network = "mainnet".into(),
            Some("stagenet") => self.network = "stagenet".into(),
            Some("testnet") => self.network = "testnet".into(),
            _ => (),
        };
    }

    /// Sets `private_spend_key` to the specified private spend key, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn private_spend(&mut self, argument: Option<&str>) {
        if let Some(private_spend) = argument {
            self.private_spend_key = Some(private_spend.to_string());
        }
    }

    /// Sets `private_view_key` to the specified private view key, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn private_view(&mut self, argument: Option<&str>) {
        if let Some(private_view) = argument {
            self.private_view_key = Some(private_view.to_string());
        }
    }

    /// Sets `public_spend_key` to the specified public spend key, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn public_spend(&mut self, argument: Option<&str>) {
        if let Some(public_spend) = argument {
            self.public_spend_key = Some(public_spend.to_string());
        }
    }

    /// Sets `public_view_key` to the specified public view key, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn public_view(&mut self, argument: Option<&str>) {
        if let Some(public_view) = argument {
            self.public_view_key = Some(public_view.to_string());
        }
    }

    /// Sets `subaddress` to the specified subaddress indices, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn subaddress(&mut self, arguments: Option<Values>) {
        if let Some(indices) = arguments {
            let index: Vec<u32> = indices
                .into_iter()
                .map(|i| i.to_string().parse::<u32>().unwrap())
                .collect();
            self.format = MoneroFormat::Subaddress(index[0], index[1]);
        }
    }
}

pub struct MoneroCLI;

impl CLI for MoneroCLI {
    type Options = MoneroOptions;

    const NAME: NameType = "monero";
    const ABOUT: AboutType = "Generates a Monero wallet (include -h for more options)";
    const FLAGS: &'static [FlagType] = &[flag::JSON];
    const OPTIONS: &'static [OptionType] = &[
        option::COUNT,
        option::INTEGRATED_MONERO,
        option::LANGUAGE_MONERO,
        option::NETWORK_MONERO,
        option::SUBADDRESS_MONERO,
    ];
    const SUBCOMMANDS: &'static [SubCommandType] = &[subcommand::IMPORT_MONERO];

    /// Handle all CLI arguments and flags for Monero
    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Result<Self::Options, CLIError> {
        let mut options = MoneroOptions::default();
        options.parse(
            arguments,
            &[
                "count",
                "format",
                "integrated",
                "json",
                "language",
                "network",
                "subaddress",
            ],
        );

        match arguments.subcommand() {
            ("import", Some(arguments)) => {
                options.subcommand = Some("import".into());
                options.parse(
                    arguments,
                    &["format", "integrated", "json", "language", "network", "subaddress"],
                );
                options.parse(
                    arguments,
                    &[
                        "address",
                        "mnemonic",
                        "private spend",
                        "private view",
                        "public spend",
                        "public view",
                    ],
                );
            }
            _ => {}
        };

        Ok(options)
    }

    /// Generate the Monero wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) -> Result<(), CLIError> {
        fn output<N: MoneroNetwork, W: MoneroWordlist>(options: MoneroOptions) -> Result<(), CLIError> {
            let wallets =
                match options.subcommand.as_ref().map(String::as_str) {
                    Some("import") => {
                        if let Some(mnemonic) = options.mnemonic {
                            vec![
                                MoneroWallet::from_mnemonic::<N, ChineseSimplified>(&mnemonic, &options.format)
                                    .or(MoneroWallet::from_mnemonic::<N, Dutch>(&mnemonic, &options.format))
                                    .or(MoneroWallet::from_mnemonic::<N, English>(&mnemonic, &options.format))
                                    .or(MoneroWallet::from_mnemonic::<N, EnglishOld>(&mnemonic, &options.format))
                                    .or(MoneroWallet::from_mnemonic::<N, Esperanto>(&mnemonic, &options.format))
                                    .or(MoneroWallet::from_mnemonic::<N, French>(&mnemonic, &options.format))
                                    .or(MoneroWallet::from_mnemonic::<N, German>(&mnemonic, &options.format))
                                    .or(MoneroWallet::from_mnemonic::<N, Italian>(&mnemonic, &options.format))
                                    .or(MoneroWallet::from_mnemonic::<N, Japanese>(&mnemonic, &options.format))
                                    .or(MoneroWallet::from_mnemonic::<N, Lojban>(&mnemonic, &options.format))
                                    .or(MoneroWallet::from_mnemonic::<N, Portuguese>(&mnemonic, &options.format))
                                    .or(MoneroWallet::from_mnemonic::<N, Russian>(&mnemonic, &options.format))
                                    .or(MoneroWallet::from_mnemonic::<N, Spanish>(&mnemonic, &options.format))?,
                            ]
                        } else if let Some(private_spend_key) = options.private_spend_key {
                            vec![MoneroWallet::from_private_spend_key::<N, W>(
                                &private_spend_key,
                                &options.format,
                            )?]
                        } else if let Some(private_view_key) = options.private_view_key {
                            vec![MoneroWallet::from_private_view_key::<N>(
                                &private_view_key,
                                &options.format,
                            )?]
                        } else if let Some(public_spend_key) = options.public_spend_key {
                            if let Some(public_view_key) = options.public_view_key {
                                vec![MoneroWallet::from_public_key::<N>(
                                    &public_spend_key,
                                    &public_view_key,
                                    &options.format,
                                )?]
                            } else {
                                vec![]
                            }
                        } else if let Some(address) = options.address {
                            vec![MoneroWallet::from_address::<MoneroMainnet>(&address)
                                .or(MoneroWallet::from_address::<MoneroTestnet>(&address))?]
                        } else {
                            vec![]
                        }
                    }
                    _ => (0..options.count)
                        .flat_map(|_| {
                            match MoneroWallet::new::<N, W, _>(&mut StdRng::from_entropy(), &options.format) {
                                Ok(wallet) => vec![wallet],
                                _ => vec![],
                            }
                        })
                        .collect(),
                };

            match options.json {
                true => println!("{}\n", serde_json::to_string_pretty(&wallets)?),
                false => wallets.iter().for_each(|wallet| println!("{}\n", wallet)),
            };

            Ok(())
        }

        match options.language.as_str() {
            "chinese_simplified" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, ChineseSimplified>(options),
                "stagenet" => output::<MoneroStagenet, ChineseSimplified>(options),
                _ => output::<MoneroMainnet, ChineseSimplified>(options),
            },
            "dutch" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, Dutch>(options),
                "stagenet" => output::<MoneroStagenet, Dutch>(options),
                _ => output::<MoneroMainnet, Dutch>(options),
            },
            "english" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, English>(options),
                "stagenet" => output::<MoneroStagenet, English>(options),
                _ => output::<MoneroMainnet, English>(options),
            },
            "english_old" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, EnglishOld>(options),
                "stagenet" => output::<MoneroStagenet, EnglishOld>(options),
                _ => output::<MoneroMainnet, EnglishOld>(options),
            },
            "esperanto" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, Esperanto>(options),
                "stagenet" => output::<MoneroStagenet, Esperanto>(options),
                _ => output::<MoneroMainnet, Esperanto>(options),
            },
            "french" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, French>(options),
                "stagenet" => output::<MoneroStagenet, French>(options),
                _ => output::<MoneroMainnet, French>(options),
            },
            "german" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, German>(options),
                "stagenet" => output::<MoneroStagenet, German>(options),
                _ => output::<MoneroMainnet, German>(options),
            },
            "italian" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, Italian>(options),
                "stagenet" => output::<MoneroStagenet, Italian>(options),
                _ => output::<MoneroMainnet, Italian>(options),
            },
            "japanese" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, Japanese>(options),
                "stagenet" => output::<MoneroStagenet, Japanese>(options),
                _ => output::<MoneroMainnet, Japanese>(options),
            },
            "lojban" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, Lojban>(options),
                "stagenet" => output::<MoneroStagenet, Lojban>(options),
                _ => output::<MoneroMainnet, Lojban>(options),
            },
            "portuguese" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, Portuguese>(options),
                "stagenet" => output::<MoneroStagenet, Portuguese>(options),
                _ => output::<MoneroMainnet, Portuguese>(options),
            },
            "russian" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, Russian>(options),
                "stagenet" => output::<MoneroStagenet, Russian>(options),
                _ => output::<MoneroMainnet, Russian>(options),
            },
            "spanish" => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, Spanish>(options),
                "stagenet" => output::<MoneroStagenet, Spanish>(options),
                _ => output::<MoneroMainnet, Spanish>(options),
            },
            _ => match options.network.as_str() {
                "testnet" => output::<MoneroTestnet, English>(options),
                "stagenet" => output::<MoneroStagenet, English>(options),
                _ => output::<MoneroMainnet, English>(options),
            },
        }
    }
}
