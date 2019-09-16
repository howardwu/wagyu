use crate::bitcoin::{
    format::BitcoinFormat, wordlist::*, BitcoinAddress, BitcoinDerivationPath, BitcoinExtendedPrivateKey,
    BitcoinExtendedPublicKey, BitcoinMnemonic, BitcoinNetwork, BitcoinPrivateKey, BitcoinPublicKey, BitcoinWordlist,
    Mainnet as BitcoinMainnet, Testnet as BitcoinTestnet,
};
use crate::cli::{flag, option, subcommand, types::*, CLIError, CLI};
use crate::model::{ExtendedPrivateKey, ExtendedPublicKey, Mnemonic, MnemonicCount, MnemonicExtended, PrivateKey, PublicKey};

use clap::ArgMatches;
use colored::*;
use rand::{rngs::StdRng, Rng};
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display, str::FromStr};

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

impl BitcoinWallet {
    pub fn new<N: BitcoinNetwork, R: Rng>(rng: &mut R, format: &BitcoinFormat) -> Result<Self, CLIError> {
        let private_key = BitcoinPrivateKey::<N>::new(rng)?;
        let public_key = private_key.to_public_key();
        let address = public_key.to_address(format)?;
        Ok(Self {
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            network: Some(N::NAME.to_string()),
            format: Some(address.format().to_string()),
            compressed: private_key.is_compressed().into(),
            ..Default::default()
        })
    }

    pub fn new_hd<N: BitcoinNetwork, W: BitcoinWordlist, R: Rng>(
        rng: &mut R,
        word_count: u8,
        password: Option<&str>,
        path: &str,
        format: &BitcoinFormat,
    ) -> Result<Self, CLIError> {
        let mnemonic = BitcoinMnemonic::<N, W>::new_with_count(rng, word_count)?;
        let master_extended_private_key = mnemonic.to_extended_private_key(password)?;
        let derivation_path = BitcoinDerivationPath::from_str(path)?;
        let extended_private_key = master_extended_private_key.derive(&derivation_path)?;
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(format)?;
        let compressed = private_key.is_compressed();
        Ok(Self {
            path: Some(path.to_string()),
            password: password.map(String::from),
            mnemonic: Some(mnemonic.to_string()),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            format: Some(address.format().to_string()),
            network: Some(N::NAME.to_string()),
            compressed: Some(compressed),
        })
    }

    pub fn from_mnemonic<N: BitcoinNetwork, W: BitcoinWordlist>(
        mnemonic: &str,
        password: &Option<&str>,
        path: &str,
        format: &BitcoinFormat,
    ) -> Result<Self, CLIError> {
        let mnemonic = BitcoinMnemonic::<N, W>::from_phrase(&mnemonic)?;
        let master_extended_private_key = mnemonic.to_extended_private_key(password.clone())?;
        let derivation_path = BitcoinDerivationPath::from_str(path)?;
        let extended_private_key = master_extended_private_key.derive(&derivation_path)?;
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(format)?;
        let compressed = private_key.is_compressed();
        Ok(Self {
            path: Some(path.to_string()),
            password: password.map(String::from),
            mnemonic: Some(mnemonic.to_string()),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            format: Some(address.format().to_string()),
            network: Some(N::NAME.to_string()),
            compressed: Some(compressed),
        })
    }

    pub fn from_extended_private_key<N: BitcoinNetwork>(
        extended_private_key: &str,
        path: &Option<String>,
        format: &BitcoinFormat,
    ) -> Result<Self, CLIError> {
        let mut extended_private_key = BitcoinExtendedPrivateKey::<N>::from_str(extended_private_key)?;
        if let Some(derivation_path) = path {
            let derivation_path = BitcoinDerivationPath::from_str(&derivation_path)?;
            extended_private_key = extended_private_key.derive(&derivation_path)?;
        }
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(format)?;
        let compressed = private_key.is_compressed();
        Ok(Self {
            path: path.clone(),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            format: Some(address.format().to_string()),
            network: Some(N::NAME.to_string()),
            compressed: Some(compressed),
            ..Default::default()
        })
    }

    pub fn from_extended_public_key<N: BitcoinNetwork>(
        extended_public_key: &str,
        path: &Option<String>,
        format: &BitcoinFormat,
    ) -> Result<Self, CLIError> {
        let mut extended_public_key = BitcoinExtendedPublicKey::<N>::from_str(extended_public_key)?;
        if let Some(derivation_path) = path {
            let derivation_path = BitcoinDerivationPath::from_str(&derivation_path)?;
            extended_public_key = extended_public_key.derive(&derivation_path)?;
        }
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(format)?;
        let compressed = public_key.is_compressed();
        Ok(Self {
            path: path.clone(),
            extended_public_key: Some(extended_public_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            format: Some(address.format().to_string()),
            network: Some(N::NAME.to_string()),
            compressed: Some(compressed),
            ..Default::default()
        })
    }

    pub fn from_private_key<N: BitcoinNetwork>(private_key: &str, format: &BitcoinFormat) -> Result<Self, CLIError> {
        let private_key = BitcoinPrivateKey::<N>::from_str(private_key)?;
        let public_key = private_key.to_public_key();
        let address = public_key.to_address(format)?;
        Ok(Self {
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            network: Some(N::NAME.to_string()),
            format: Some(address.format().to_string()),
            compressed: private_key.is_compressed().into(),
            ..Default::default()
        })
    }

    pub fn from_public_key<N: BitcoinNetwork>(public_key: &str, format: &BitcoinFormat) -> Result<Self, CLIError> {
        let public_key = BitcoinPublicKey::<N>::from_str(public_key)?;
        let address = public_key.to_address(format)?;
        Ok(Self {
            public_key: Some(public_key.to_string()),
            address: address.to_string(),
            network: Some(N::NAME.to_string()),
            format: Some(address.format().to_string()),
            compressed: public_key.is_compressed().into(),
            ..Default::default()
        })
    }

    pub fn from_address<N: BitcoinNetwork>(address: &str) -> Result<Self, CLIError> {
        let address = BitcoinAddress::<N>::from_str(address)?;
        Ok(Self {
            address: address.to_string(),
            network: Some(N::NAME.to_string()),
            format: Some(address.format().to_string()),
            ..Default::default()
        })
    }
}

#[cfg_attr(tarpaulin, skip)]
impl Display for BitcoinWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = [
            match &self.path {
                Some(path) => format!("      {}                 {}\n", "Path".cyan().bold(), path),
                _ => "".to_owned(),
            },
            match &self.password {
                Some(password) => format!("      {}             {}\n", "Password".cyan().bold(), password),
                _ => "".to_owned(),
            },
            match &self.mnemonic {
                Some(mnemonic) => format!("      {}             {}\n", "Mnemonic".cyan().bold(), mnemonic),
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
            match &self.network {
                Some(network) => format!("      {}              {}\n", "Network".cyan().bold(), network),
                _ => "".to_owned(),
            },
            match &self.compressed {
                Some(compressed) => format!("      {}           {}\n", "Compressed".cyan().bold(), compressed),
                _ => "".to_owned(),
            },
        ]
        .concat();

        // Removes final new line character
        let output = output[..output.len() - 1].to_owned();
        write!(f, "\n{}", output)
    }
}

/// Represents options for a Bitcoin wallet
#[derive(Clone, Debug, Serialize)]
pub struct BitcoinOptions {
    // Standard command
    count: usize,
    format: BitcoinFormat,
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

impl Default for BitcoinOptions {
    fn default() -> Self {
        Self {
            // Standard command
            count: 1,
            format: BitcoinFormat::P2PKH,
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

impl BitcoinOptions {
    fn parse(&mut self, arguments: &ArgMatches, options: &[&str]) {
        options.iter().for_each(|option| match *option {
            "account" => self.account(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "address" => self.address(arguments.value_of(option)),
            "chain" => self.chain(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "count" => self.count(clap::value_t!(arguments.value_of(*option), usize).ok()),
            "derivation" => self.derivation(arguments.value_of(option)),
            "extended private" => self.extended_private(arguments.value_of(option)),
            "extended public" => self.extended_public(arguments.value_of(option)),
            "format" => self.format(arguments.value_of(option)),
            "json" => self.json(arguments.is_present(option)),
            "index" => self.index(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "language" => self.language(arguments.value_of(option)),
            "mnemonic" => self.mnemonic(arguments.value_of(option)),
            "network" => self.network(arguments.value_of(option)),
            "password" => self.password(arguments.value_of(option)),
            "private" => self.private(arguments.value_of(option)),
            "public" => self.public(arguments.value_of(option)),
            "word count" => self.word_count(clap::value_t!(arguments.value_of(*option), u8).ok()),
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

    /// Sets `chain` to the specified chain index, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn chain(&mut self, argument: Option<u32>) {
        if let Some(chain) = argument {
            self.chain = chain;
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
            Some("bip32") => self.derivation = "bip32".into(),
            Some("bip44") => self.derivation = "bip44".into(),
            Some("bip49") => self.derivation = "bip49".into(),
            Some(custom) => {
                self.derivation = "custom".into();
                self.path = Some(custom.to_string());
            }
            _ => (),
        };
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
            Some("legacy") => self.format = BitcoinFormat::P2PKH,
            Some("segwit") => self.format = BitcoinFormat::P2SH_P2WPKH,
            Some("bech32") => self.format = BitcoinFormat::Bech32,
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

    /// Sets `language` to the specified language, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn language(&mut self, argument: Option<&str>) {
        match argument {
            Some("chinese_simplified") => self.language = "chinese_simplified".into(),
            Some("chinese_traditional") => self.language = "chinese_traditional".into(),
            Some("english") => self.language = "english".into(),
            Some("french") => self.language = "french".into(),
            Some("italian") => self.language = "italian".into(),
            Some("japanese") => self.language = "japanese".into(),
            Some("korean") => self.language = "korean".into(),
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
            Some("testnet") => self.network = "testnet".into(),
            _ => (),
        };
    }

    /// Sets `password` to the specified password, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn password(&mut self, argument: Option<&str>) {
        if let Some(password) = argument {
            self.password = Some(password.to_string());
        }
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

    /// Sets `word_count` to the specified word count, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn word_count(&mut self, argument: Option<u8>) {
        if let Some(word_count) = argument {
            self.word_count = word_count;
        }
    }

    /// Returns the derivation path with the specified account, chain, derivation, index, and path.
    /// If `default` is enabled, then return the default path if no derivation was provided.
    fn to_derivation_path(&self, default: bool) -> Option<String> {
        match self.derivation.as_str() {
            "bip32" => Some(format!("m/0'/0'/{}'", self.index)),
            "bip44" => Some(format!("m/44'/0'/{}'/{}/{}'", self.account, self.chain, self.index)),
            "bip49" => Some(format!("m/44'/0'/{}'/{}/{}'", self.account, self.chain, self.index)),
            "custom" => self.path.clone(),
            _ => match default {
                true => Some(format!("m/0'/0'/{}'", self.index)),
                false => None,
            },
        }
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
        let mut options = BitcoinOptions::default();
        options.parse(arguments, &["count", "format", "json", "network"]);

        match arguments.subcommand() {
            ("hd", Some(arguments)) => {
                options.subcommand = Some("hd".into());
                options.parse(arguments, &["count", "format", "json", "network"]);
                options.parse(arguments, &["derivation", "language", "password", "word count"]);
            }
            ("import", Some(arguments)) => {
                options.subcommand = Some("import".into());
                options.parse(arguments, &["format", "json", "network"]);
                options.parse(arguments, &["address", "private", "public"]);
            }
            ("import-hd", Some(arguments)) => {
                options.subcommand = Some("import-hd".into());
                options.parse(arguments, &["format", "json", "network"]);
                options.parse(
                    arguments,
                    &[
                        "account",
                        "chain",
                        "derivation",
                        "extended private",
                        "extended public",
                        "index",
                        "mnemonic",
                        "password",
                    ],
                );
            }
            _ => {}
        };

        Ok(options)
    }

    /// Generate the Bitcoin wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) -> Result<(), CLIError> {
        fn output<N: BitcoinNetwork, W: BitcoinWordlist>(options: BitcoinOptions) -> Result<(), CLIError> {
            let wallets = match options.subcommand.as_ref().map(String::as_str) {
                Some("hd") => {
                    let path = options.to_derivation_path(true).unwrap();
                    (0..options.count)
                        .flat_map(|_| {
                            match BitcoinWallet::new_hd::<N, W, _>(
                                &mut StdRng::from_entropy(),
                                options.word_count,
                                options.password.as_ref().map(String::as_str),
                                &path,
                                &options.format,
                            ) {
                                Ok(wallet) => vec![wallet],
                                _ => vec![],
                            }
                        })
                        .collect()
                }
                Some("import") => {
                    if let Some(private_key) = options.private {
                        vec![
                            BitcoinWallet::from_private_key::<BitcoinMainnet>(&private_key, &options.format).or(
                                BitcoinWallet::from_private_key::<BitcoinTestnet>(&private_key, &options.format),
                            )?,
                        ]
                    } else if let Some(public_key) = options.public {
                        vec![BitcoinWallet::from_public_key::<N>(&public_key, &options.format)?]
                    } else if let Some(address) = options.address {
                        vec![BitcoinWallet::from_address::<BitcoinMainnet>(&address)
                            .or(BitcoinWallet::from_address::<BitcoinTestnet>(&address))?]
                    } else {
                        vec![]
                    }
                }
                Some("import-hd") => {
                    if let Some(mnemonic) = options.mnemonic.clone() {
                        let password = &options.password.as_ref().map(String::as_str);
                        let path = &options.to_derivation_path(true).unwrap();
                        let format = &options.format;

                        vec![
                            BitcoinWallet::from_mnemonic::<N, ChineseSimplified>(&mnemonic, password, path, format)
                                .or(BitcoinWallet::from_mnemonic::<N, ChineseTraditional>(
                                    &mnemonic, password, path, format,
                                ))
                                .or(BitcoinWallet::from_mnemonic::<N, English>(
                                    &mnemonic, password, path, format,
                                ))
                                .or(BitcoinWallet::from_mnemonic::<N, French>(
                                    &mnemonic, password, path, format,
                                ))
                                .or(BitcoinWallet::from_mnemonic::<N, Italian>(
                                    &mnemonic, password, path, format,
                                ))
                                .or(BitcoinWallet::from_mnemonic::<N, Japanese>(
                                    &mnemonic, password, path, format,
                                ))
                                .or(BitcoinWallet::from_mnemonic::<N, Korean>(
                                    &mnemonic, password, path, format,
                                ))
                                .or(BitcoinWallet::from_mnemonic::<N, Spanish>(
                                    &mnemonic, password, path, format,
                                ))?,
                        ]
                    } else if let Some(extended_private_key) = options.extended_private_key.clone() {
                        let key = &extended_private_key;
                        let path = &options.to_derivation_path(false);
                        let format = &options.format;

                        vec![
                            BitcoinWallet::from_extended_private_key::<BitcoinMainnet>(key, path, format).or(
                                BitcoinWallet::from_extended_private_key::<BitcoinTestnet>(key, path, format),
                            )?,
                        ]
                    } else if let Some(extended_public_key) = options.extended_public_key.clone() {
                        let key = &extended_public_key;
                        let path = &options.to_derivation_path(false);
                        let format = &options.format;

                        vec![
                            BitcoinWallet::from_extended_public_key::<BitcoinMainnet>(key, path, format).or(
                                BitcoinWallet::from_extended_public_key::<BitcoinTestnet>(key, path, format),
                            )?,
                        ]
                    } else {
                        vec![]
                    }
                }
                _ => (0..options.count)
                    .flat_map(
                        |_| match BitcoinWallet::new::<N, _>(&mut StdRng::from_entropy(), &options.format) {
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

        match options.language.as_str() {
            "chinese_simplified" => match options.network.as_str() {
                "testnet" => output::<BitcoinTestnet, ChineseSimplified>(options),
                _ => output::<BitcoinMainnet, ChineseSimplified>(options),
            },
            "chinese_traditional" => match options.network.as_str() {
                "testnet" => output::<BitcoinTestnet, ChineseTraditional>(options),
                _ => output::<BitcoinMainnet, ChineseTraditional>(options),
            },
            "english" => match options.network.as_str() {
                "testnet" => output::<BitcoinTestnet, English>(options),
                _ => output::<BitcoinMainnet, English>(options),
            },
            "french" => match options.network.as_str() {
                "testnet" => output::<BitcoinTestnet, French>(options),
                _ => output::<BitcoinMainnet, French>(options),
            },
            "italian" => match options.network.as_str() {
                "testnet" => output::<BitcoinTestnet, Italian>(options),
                _ => output::<BitcoinMainnet, Italian>(options),
            },
            "japanese" => match options.network.as_str() {
                "testnet" => output::<BitcoinTestnet, Japanese>(options),
                _ => output::<BitcoinMainnet, Japanese>(options),
            },
            "korean" => match options.network.as_str() {
                "testnet" => output::<BitcoinTestnet, Korean>(options),
                _ => output::<BitcoinMainnet, Korean>(options),
            },
            "spanish" => match options.network.as_str() {
                "testnet" => output::<BitcoinTestnet, Spanish>(options),
                _ => output::<BitcoinMainnet, Spanish>(options),
            },
            _ => match options.network.as_str() {
                "testnet" => output::<BitcoinTestnet, English>(options),
                _ => output::<BitcoinMainnet, English>(options),
            },
        }
    }
}
