use crate::cli::{flag, option, subcommand, types::*, CLIError, CLI};
use crate::model::{ExtendedPrivateKey, ExtendedPublicKey, PrivateKey, PublicKey};
use crate::zcash::{
    format::ZcashFormat, Mainnet as ZcashMainnet, Testnet as ZcashTestnet, ZcashAddress, ZcashDerivationPath,
    ZcashExtendedPrivateKey, ZcashExtendedPublicKey, ZcashNetwork, ZcashPrivateKey, ZcashPublicKey,
};

use clap::ArgMatches;
use colored::*;
use rand::{rngs::StdRng, Rng};
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display, str::FromStr};

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
    pub path: Option<String>,
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

impl ZcashWallet {
    pub fn new<N: ZcashNetwork, R: Rng>(rng: &mut R, format: &ZcashFormat) -> Result<Self, CLIError> {
        let private_key = match format {
            ZcashFormat::P2PKH => ZcashPrivateKey::<N>::new_p2pkh(rng)?,
            ZcashFormat::Sprout => ZcashPrivateKey::<N>::new_sprout(rng)?,
            ZcashFormat::Sapling(_) => ZcashPrivateKey::<N>::new_sapling(rng)?,
            _ => ZcashPrivateKey::<N>::new_p2pkh(rng)?,
        };
        let public_key = private_key.to_public_key();
        let address = public_key.to_address(format)?;
        Ok(Self {
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            format: Some(address.format().to_string()),
            diversifier: address.to_diversifier(),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn new_hd<N: ZcashNetwork, R: Rng>(rng: &mut R, path: &str, format: &ZcashFormat) -> Result<Self, CLIError> {
        let seed: [u8; 32] = rng.gen();
        let master_extended_private_key = ZcashExtendedPrivateKey::<N>::new_master(&seed, format)?;
        let derivation_path = ZcashDerivationPath::from_str(path)?;
        let extended_private_key = master_extended_private_key.derive(&derivation_path)?;
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(format)?;
        Ok(Self {
            path: Some(path.to_string()),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            format: Some(address.format().to_string()),
            diversifier: address.to_diversifier(),
            network: Some(N::NAME.to_string()),
        })
    }

    pub fn from_extended_private_key<N: ZcashNetwork>(
        extended_private_key: &str,
        path: &Option<String>,
        format: &ZcashFormat,
    ) -> Result<Self, CLIError> {
        let mut extended_private_key = ZcashExtendedPrivateKey::<N>::from_str(extended_private_key)?;
        if let Some(derivation_path) = path {
            let derivation_path = ZcashDerivationPath::from_str(&derivation_path)?;
            extended_private_key = extended_private_key.derive(&derivation_path)?;
        }
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(format)?;
        Ok(Self {
            path: path.clone(),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            format: Some(address.format().to_string()),
            diversifier: address.to_diversifier(),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_extended_public_key<N: ZcashNetwork>(
        extended_public_key: &str,
        path: &Option<String>,
        format: &ZcashFormat,
    ) -> Result<Self, CLIError> {
        let mut extended_public_key = ZcashExtendedPublicKey::<N>::from_str(extended_public_key)?;
        if let Some(derivation_path) = path {
            let derivation_path = ZcashDerivationPath::from_str(&derivation_path)?;
            extended_public_key = extended_public_key.derive(&derivation_path)?;
        }
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(format)?;
        Ok(Self {
            path: path.clone(),
            extended_public_key: Some(extended_public_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            format: Some(address.format().to_string()),
            diversifier: address.to_diversifier(),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_private_key<N: ZcashNetwork>(private_key: &str, format: &ZcashFormat) -> Result<Self, CLIError> {
        let private_key = ZcashPrivateKey::<N>::from_str(private_key)?;
        let public_key = private_key.to_public_key();
        let address = public_key.to_address(format)?;
        Ok(Self {
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            format: Some(address.format().to_string()),
            diversifier: address.to_diversifier(),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_public_key<N: ZcashNetwork>(public_key: &str, format: &ZcashFormat) -> Result<Self, CLIError> {
        let public_key = ZcashPublicKey::<N>::from_str(public_key)?;
        let address = public_key.to_address(format)?;
        Ok(Self {
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            format: Some(address.format().to_string()),
            diversifier: address.to_diversifier(),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_address<N: ZcashNetwork>(address: &str) -> Result<Self, CLIError> {
        let address = ZcashAddress::<N>::from_str(address)?;
        Ok(Self {
            address: address.to_string(),
            format: Some(address.format().to_string()),
            diversifier: address.to_diversifier(),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }
}

#[cfg_attr(tarpaulin, skip)]
impl Display for ZcashWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = [
            match &self.path {
                Some(path) => format!("      {}                 {}\n", "Path".cyan().bold(), path),
                _ => "".to_owned(),
            },
            match &self.extended_private_key {
                Some(extended_private_key) => format!(
                    "      {} {}\n",
                    "Extended Private Key".cyan().bold(),
                    extended_private_key
                ),
                _ => "".to_owned(),
            },
            match &self.extended_public_key {
                Some(extended_public_key) => format!(
                    "      {}  {}\n",
                    "Extended Public Key".cyan().bold(),
                    extended_public_key
                ),
                _ => "".to_owned(),
            },
            match &self.private_key {
                Some(private_key) => format!("      {}          {}\n", "Private Key".cyan().bold(), private_key),
                _ => "".to_owned(),
            },
            match &self.public_key {
                Some(public_key) => format!("      {}           {}\n", "Public Key".cyan().bold(), public_key),
                _ => "".to_owned(),
            },
            format!("      {}              {}\n", "Address".cyan().bold(), self.address),
            match &self.format {
                Some(format) => format!("      {}               {}\n", "Format".cyan().bold(), format),
                _ => "".to_owned(),
            },
            match &self.diversifier {
                Some(diversifier) => format!("      {}          {}\n", "Diversifier".cyan().bold(), diversifier),
                _ => "".to_owned(),
            },
            match &self.network {
                Some(network) => format!("      {}              {}\n", "Network".cyan().bold(), network),
                _ => "".to_owned(),
            },
        ]
        .concat();

        // Removes final new line character
        let output = output[..output.len() - 1].to_owned();
        write!(f, "\n{}", output)
    }
}

/// Represents options for a Zcash wallet
#[derive(Clone, Debug, Serialize)]
pub struct ZcashOptions {
    // Standard command
    count: usize,
    diversifier: Option<String>,
    format: ZcashFormat,
    json: bool,
    network: String,
    subcommand: Option<String>,
    // HD and Import HD subcommands
    account: u32,
    chain: u32,
    derivation: String,
    extended_private_key: Option<String>,
    extended_public_key: Option<String>,
    index: u32,
    language: String,
    mnemonic: Option<String>,
    password: Option<String>,
    path: Option<String>,
    word_count: u8,
    // Import subcommand
    address: Option<String>,
    private: Option<String>,
    public: Option<String>,
}

impl Default for ZcashOptions {
    fn default() -> Self {
        Self {
            // Standard command
            count: 1,
            diversifier: None,
            format: ZcashFormat::P2PKH,
            json: false,
            network: "mainnet".into(),
            subcommand: None,
            // HD and Import HD subcommands
            account: 0,
            chain: 0,
            derivation: "bip32".into(),
            extended_private_key: None,
            extended_public_key: None,
            index: 0,
            language: "english".into(),
            mnemonic: None,
            password: None,
            path: None,
            word_count: 12,
            // Import subcommand
            address: None,
            private: None,
            public: None,
        }
    }
}

impl ZcashOptions {
    fn parse(&mut self, arguments: &ArgMatches, options: &[&str]) {
        options.iter().for_each(|option| match *option {
            "account" => self.account(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "address" => self.address(arguments.value_of(option)),
            "count" => self.count(clap::value_t!(arguments.value_of(*option), usize).ok()),
            "derivation" => self.derivation(arguments.value_of(option)),
            "diversifier" => self.diversifier(arguments.value_of(option)),
            "extended private" => self.extended_private(arguments.value_of(option)),
            "extended public" => self.extended_public(arguments.value_of(option)),
            "format" => self.format(arguments.value_of(option)),
            "index" => self.index(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "json" => self.json(arguments.is_present(option)),
            "network" => self.network(arguments.value_of(option)),
            "private" => self.private(arguments.value_of(option)),
            "public" => self.public(arguments.value_of(option)),
            _ => (),
        });
    }

    /// Sets `account` to the specified account index, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn account(&mut self, argument: Option<u32>) {
        if let Some(account) = argument {
            self.account = account;
        }
    }

    /// Imports a wallet for the specified address, overriding its previous state.
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

    /// Sets `derivation` to the specified derivation, overriding its previous state.
    /// If `derivation` is `\"custom\"`, then `path` is set to the specified path.
    /// If the specified argument is `None`, then no change occurs.
    fn derivation(&mut self, argument: Option<&str>) {
        match argument {
            Some("zip32") => self.derivation = "zip32".into(),
            Some(custom) => {
                self.derivation = "custom".into();
                self.path = Some(custom.to_string());
            }
            _ => (),
        };
    }

    /// Sets `diversifier` to the specified diversifier and `format` to the updated Sapling format,
    /// overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn diversifier(&mut self, argument: Option<&str>) {
        if let Some(data) = argument {
            self.diversifier = Some(data.into());
            // Set `format` to ZcashFormat::Sapling(diversifier)
            let mut diversifier = [0u8; 11];
            diversifier.copy_from_slice(&hex::decode(data).unwrap());
            self.format = ZcashFormat::Sapling(Some(diversifier))
        }
    }

    /// Sets `extended_private_key` to the specified extended private key, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn extended_private(&mut self, argument: Option<&str>) {
        if let Some(extended_private_key) = argument {
            self.extended_private_key = Some(extended_private_key.to_string());
        }
    }

    /// Sets `extended_public_key` to the specified extended public key, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn extended_public(&mut self, argument: Option<&str>) {
        if let Some(extended_public_key) = argument {
            self.extended_public_key = Some(extended_public_key.to_string());
        }
    }

    /// Sets `format` to the specified format, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn format(&mut self, argument: Option<&str>) {
        match argument {
            Some("sapling") => match &self.diversifier {
                Some(data) => {
                    let mut diversifier = [0u8; 11];
                    diversifier.copy_from_slice(&hex::decode(data).unwrap());
                    self.format = ZcashFormat::Sapling(Some(diversifier))
                }
                None => self.format = ZcashFormat::Sapling(None),
            },
            Some("sprout") => self.format = ZcashFormat::Sprout,
            Some("transparent") => self.format = ZcashFormat::P2PKH,
            _ => (),
        };
    }

    /// Sets `index` to the specified index, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn index(&mut self, argument: Option<u32>) {
        if let Some(index) = argument {
            self.index = index;
        }
    }

    /// Sets `json` to the specified boolean value, overriding its previous state.
    fn json(&mut self, argument: bool) {
        self.json = argument;
    }

    /// Sets `network` to the specified network, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn network(&mut self, argument: Option<&str>) {
        match argument {
            Some("mainnet") => self.network = "mainnet".into(),
            Some("testnet") => self.network = "testnet".into(),
            _ => (),
        };
    }

    /// Imports a wallet for the specified private key, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn private(&mut self, argument: Option<&str>) {
        if let Some(private_key) = argument {
            self.private = Some(private_key.to_string());
        }
    }

    /// Imports a wallet for the specified public key, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn public(&mut self, argument: Option<&str>) {
        if let Some(public_key) = argument {
            self.public = Some(public_key.to_string())
        }
    }

    /// Returns the derivation path with the specified account, index, and path.
    /// If `default` is enabled, then return the default path if no derivation was provided.
    fn to_derivation_path(&self, default: bool) -> Option<String> {
        match self.derivation.as_str() {
            "zip32" => Some(format!("m/44'/133'/{}'/{}", self.account, self.index)),
            "custom" => self.path.clone(),
            _ => match default {
                true => Some(format!("m/44'/133'/{}'/{}", self.account, self.index)),
                false => None,
            },
        }
    }
}

pub struct ZcashCLI;

impl CLI for ZcashCLI {
    type Options = ZcashOptions;

    const NAME: NameType = "zcash";
    const ABOUT: AboutType = "Generates a Zcash wallet (include -h for more options)";
    const FLAGS: &'static [FlagType] = &[flag::JSON];
    const OPTIONS: &'static [OptionType] = &[
        option::COUNT,
        option::DIVERSIFIER_ZCASH,
        option::FORMAT_ZCASH,
        option::NETWORK_ZCASH,
    ];
    const SUBCOMMANDS: &'static [SubCommandType] = &[
        subcommand::HD_ZCASH,
        subcommand::IMPORT_ZCASH,
        subcommand::IMPORT_HD_ZCASH,
    ];

    /// Handle all CLI arguments and flags for Zcash
    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Result<Self::Options, CLIError> {
        let mut options = ZcashOptions::default();
        options.parse(arguments, &["count", "diversifier", "format", "json", "network"]);

        match arguments.subcommand() {
            ("hd", Some(arguments)) => {
                options.subcommand = Some("hd".into());
                options.parse(arguments, &["count", "diversifier", "format", "json", "network"]);
                options.parse(arguments, &["derivation"]);
            }
            ("import", Some(arguments)) => {
                options.subcommand = Some("import".into());
                options.parse(arguments, &["diversifier", "format", "json", "network"]);
                options.parse(arguments, &["address", "private", "public"]);
            }
            ("import-hd", Some(arguments)) => {
                options.subcommand = Some("import-hd".into());
                options.parse(arguments, &["diversifier", "format", "json", "network"]);
                options.parse(
                    arguments,
                    &["account", "derivation", "extended private", "extended public", "index"],
                );
            }
            _ => {}
        };

        Ok(options)
    }

    /// Generate the Zcash wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) -> Result<(), CLIError> {
        fn output<N: ZcashNetwork>(options: ZcashOptions) -> Result<(), CLIError> {
            let wallets =
                match options.subcommand.as_ref().map(String::as_str) {
                    Some("hd") => {
                        let path = options.to_derivation_path(true).unwrap();
                        (0..options.count)
                            .flat_map(|_| {
                                match ZcashWallet::new_hd::<N, _>(&mut StdRng::from_entropy(), &path, &options.format) {
                                    Ok(wallet) => vec![wallet],
                                    _ => vec![],
                                }
                            })
                            .collect()
                    }
                    Some("import") => {
                        if let Some(private_key) = options.private {
                            vec![
                                ZcashWallet::from_private_key::<ZcashMainnet>(&private_key, &options.format).or(
                                    ZcashWallet::from_private_key::<ZcashTestnet>(&private_key, &options.format),
                                )?,
                            ]
                        } else if let Some(public_key) = options.public {
                            vec![
                                ZcashWallet::from_public_key::<ZcashMainnet>(&public_key, &options.format).or(
                                    ZcashWallet::from_public_key::<ZcashTestnet>(&public_key, &options.format),
                                )?,
                            ]
                        } else if let Some(address) = options.address {
                            vec![ZcashWallet::from_address::<ZcashMainnet>(&address)
                                .or(ZcashWallet::from_address::<ZcashTestnet>(&address))?]
                        } else {
                            vec![]
                        }
                    }
                    Some("import-hd") => {
                        if let Some(extended_private_key) = options.extended_private_key.clone() {
                            let key = &extended_private_key;
                            let path = &options.to_derivation_path(false);
                            let format = &options.format;

                            vec![
                                ZcashWallet::from_extended_private_key::<ZcashMainnet>(key, path, format).or(
                                    ZcashWallet::from_extended_private_key::<ZcashTestnet>(key, path, format),
                                )?,
                            ]
                        } else if let Some(extended_public_key) = options.extended_public_key.clone() {
                            let key = &extended_public_key;
                            let path = &options.to_derivation_path(false);
                            let format = &options.format;

                            vec![ZcashWallet::from_extended_public_key::<ZcashMainnet>(key, path, format)
                                .or(ZcashWallet::from_extended_public_key::<ZcashTestnet>(key, path, format))?]
                        } else {
                            vec![]
                        }
                    }
                    _ => (0..options.count)
                        .flat_map(
                            |_| match ZcashWallet::new::<N, _>(&mut StdRng::from_entropy(), &options.format) {
                                Ok(wallet) => vec![wallet],
                                _ => vec![],
                            },
                        )
                        .collect(),
                };

            match options.json {
                true => println!("{}\n", serde_json::to_string_pretty(&wallets)?),
                false => wallets.iter().for_each(|wallet| println!("{}\n", wallet)),
            };

            Ok(())
        }

        match options.network.as_str() {
            "testnet" => output::<ZcashTestnet>(options),
            _ => output::<ZcashMainnet>(options),
        }
    }
}
