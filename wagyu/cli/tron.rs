use crate::cli::{flag, option, subcommand, types::*, CLIError, CLI};
use crate::tron::{
    wordlist::*, TronAddress, TronAmount, TronDerivationPath, TronExtendedPrivateKey,
    TronExtendedPublicKey, TronFormat, TronMnemonic, TronNetwork, TronPrivateKey,
    TronPublicKey, TronTransaction, TronTransactionParameters, Mainnet as TronMainnet, Testnet as TronTestnet,
};
use crate::model::{
    ExtendedPrivateKey, ExtendedPublicKey, Mnemonic, MnemonicCount, MnemonicExtended, Network, PrivateKey, PublicKey,
    Transaction,
};

use clap::{ArgMatches, Values};
use colored::*;
use rand::{rngs::StdRng, Rng};
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use std::{fmt, fmt::Display, str::FromStr};

/// Represents a generic wallet to output
#[derive(Serialize, Debug, Default)]
struct TronWallet {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_hex: Option<String>,
}

impl TronWallet {
    pub fn new<N: TronNetwork, R: Rng>(rng: &mut R) -> Result<Self, CLIError> {
        let private_key = TronPrivateKey::<N>::new(rng)?;
        let public_key = private_key.to_public_key();
        let address = public_key.to_address(&TronFormat::Standard)?;
        Ok(Self {
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn new_hd<N: TronNetwork, W: TronWordlist, R: Rng>(
        rng: &mut R,
        word_count: u8,
        password: Option<&str>,
        path: &str,
    ) -> Result<Self, CLIError> {
        let mnemonic = TronMnemonic::<N, W>::new_with_count(rng, word_count)?;
        let master_extended_private_key = mnemonic.to_extended_private_key(password)?;
        let derivation_path = TronDerivationPath::from_str(path)?;
        let extended_private_key = master_extended_private_key.derive(&derivation_path)?;
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(&TronFormat::Standard)?;
        Ok(Self {
            path: Some(path.to_string()),
            password: password.map(String::from),
            mnemonic: Some(mnemonic.to_string()),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            network: Some(N::NAME.to_string()),
            address: Some(address.to_string()),
            ..Default::default()
        })
    }

    pub fn from_mnemonic<N: TronNetwork, W: TronWordlist>(
        mnemonic: &str,
        password: Option<&str>,
        path: &str,
    ) -> Result<Self, CLIError> {
        let mnemonic = TronMnemonic::<N, W>::from_phrase(&mnemonic)?;
        let master_extended_private_key = mnemonic.to_extended_private_key(password)?;
        let derivation_path = TronDerivationPath::from_str(path)?;
        let extended_private_key = master_extended_private_key.derive(&derivation_path)?;
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(&TronFormat::Standard)?;
        Ok(Self {
            path: Some(path.to_string()),
            password: password.map(String::from),
            mnemonic: Some(mnemonic.to_string()),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            network: Some(N::NAME.to_string()),
            address: Some(address.to_string()),
            ..Default::default()
        })
    }

    pub fn from_extended_private_key<N: TronNetwork>(
        extended_private_key: &str,
        path: &Option<String>,
    ) -> Result<Self, CLIError> {
        let mut extended_private_key = TronExtendedPrivateKey::<N>::from_str(extended_private_key)?;
        if let Some(derivation_path) = path {
            let derivation_path = TronDerivationPath::from_str(&derivation_path)?;
            extended_private_key = extended_private_key.derive(&derivation_path)?;
        }
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(&TronFormat::Standard)?;
        Ok(Self {
            path: path.clone(),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_extended_public_key<N: TronNetwork>(
        extended_public_key: &str,
        path: &Option<String>,
    ) -> Result<Self, CLIError> {
        let mut extended_public_key = TronExtendedPublicKey::<N>::from_str(extended_public_key)?;
        if let Some(derivation_path) = path {
            let derivation_path = TronDerivationPath::from_str(&derivation_path)?;
            extended_public_key = extended_public_key.derive(&derivation_path)?;
        }
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(&TronFormat::Standard)?;
        Ok(Self {
            path: path.clone(),
            extended_public_key: Some(extended_public_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_private_key<N: TronNetwork>(private_key: &str) -> Result<Self, CLIError> {
        let private_key = TronPrivateKey::<N>::from_str(private_key)?;
        let public_key = private_key.to_public_key();
        let address = public_key.to_address(&TronFormat::Standard)?;
        Ok(Self {
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_public_key<N: TronNetwork>(public_key: &str) -> Result<Self, CLIError> {
        let public_key = TronPublicKey::<N>::from_str(public_key)?;
        let address = public_key.to_address(&TronFormat::Standard)?;
        Ok(Self {
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_address<N: TronNetwork>(address: &str) -> Result<Self, CLIError> {
        let address = TronAddress::<N>::from_str(address)?;
        Ok(Self {
            address: Some(address.to_string()),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn to_raw_transaction<N: TronNetwork>(parameters: TronInput) -> Result<Self, CLIError> {
        let transaction_parameters = TronTransactionParameters {
            receiver: TronAddress::from_str(&parameters.to)?,
            amount: TronAmount::from_wei(&parameters.value)?,
            gas: TronAmount::u256_from_str(&parameters.gas)?,
            gas_price: TronAmount::from_wei(&parameters.gas_price)?,
            nonce: TronAmount::u256_from_str(&parameters.nonce.to_string())?,
            data: parameters.data.unwrap_or("".to_string()).as_bytes().to_vec(),
        };

        let raw_transaction = TronTransaction::<N>::new(&transaction_parameters)?;
        let raw_transaction_hex = hex::encode(raw_transaction.to_transaction_bytes()?);

        Ok(Self {
            transaction_hex: Some(format!("0x{}", raw_transaction_hex)),
            ..Default::default()
        })
    }

    pub fn to_signed_transaction<N: TronNetwork>(
        transaction_hex: String,
        private_key: String,
    ) -> Result<Self, CLIError> {
        let transaction_bytes = match &transaction_hex[0..2] {
            "0x" => hex::decode(&transaction_hex[2..])?,
            _ => hex::decode(&transaction_hex)?,
        };

        let private_key = TronPrivateKey::from_str(&private_key)?;

        let mut transaction = TronTransaction::<N>::from_transaction_bytes(&transaction_bytes)?;
        transaction = transaction.sign(&private_key)?;

        Ok(Self {
            transaction_id: Some(transaction.to_transaction_id()?.to_string()),
            transaction_hex: Some(format!("0x{}", hex::encode(&transaction.to_transaction_bytes()?))),
            ..Default::default()
        })
    }
}

#[cfg_attr(tarpaulin, skip)]
impl Display for TronWallet {
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
            match &self.address {
                Some(address) => format!("      {}              {}\n", "Address".cyan().bold(), address),
                _ => "".to_owned(),
            },
            match &self.transaction_id {
                Some(transaction_id) => format!("      {}       {}\n", "Transaction Id".cyan().bold(), transaction_id),
                _ => "".to_owned(),
            },
            match &self.network {
                Some(network) => format!("      {}              {}\n", "Network".cyan().bold(), network),
                _ => "".to_owned(),
            },
            match &self.transaction_hex {
                Some(transaction_hex) => {
                    format!("      {}      {}\n", "Transaction Hex".cyan().bold(), transaction_hex)
                }
                _ => "".to_owned(),
            },
        ]
        .concat();

        // Removes final new line character
        let output = output[..output.len() - 1].to_owned();
        write!(f, "\n{}", output)
    }
}

/// Represents parameters for an Tron transaction input
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TronInput {
    pub to: String,
    pub value: String,
    pub gas: String,
    #[serde(rename(deserialize = "gasPrice"))]
    pub gas_price: String,
    pub nonce: u64,
    pub data: Option<String>,
}

/// Represents options for an Tron wallet
#[derive(Clone, Debug, Serialize)]
pub struct TronOptions {
    // Standard command
    count: usize,
    json: bool,
    network: Option<String>,
    subcommand: Option<String>,
    // HD and Import HD subcommands
    derivation: String,
    extended_private_key: Option<String>,
    extended_public_key: Option<String>,
    index: u32,
    indices: u32,
    language: String,
    mnemonic: Option<String>,
    password: Option<String>,
    path: Option<String>,
    word_count: u8,
    // Import subcommand
    address: Option<String>,
    private: Option<String>,
    public: Option<String>,
    // Transaction subcommand
    transaction_hex: Option<String>,
    transaction_parameters: Option<String>,
    transaction_private_key: Option<String>,
}

impl Default for TronOptions {
    fn default() -> Self {
        Self {
            // Standard command
            count: 1,
            json: false,
            network: Some("mainnet".to_string()),
            subcommand: None,
            // HD and Import HD subcommands
            derivation: "tron".into(),
            extended_private_key: None,
            extended_public_key: None,
            index: 0,
            indices: 1,
            language: "english".into(),
            mnemonic: None,
            password: None,
            path: None,
            word_count: 12,
            // Import subcommand
            address: None,
            private: None,
            public: None,
            // Transaction subcommand
            transaction_hex: None,
            transaction_parameters: None,
            transaction_private_key: None,
        }
    }
}

impl TronOptions {
    fn parse(&mut self, arguments: &ArgMatches, options: &[&str]) {
        options.iter().for_each(|option| match *option {
            "address" => self.address(arguments.value_of(option)),
            "count" => self.count(clap::value_t!(arguments.value_of(*option), usize).ok()),
            "createrawtransaction" => self.create_raw_transaction(arguments.value_of(option)),
            "derivation" => self.derivation(arguments.value_of(option)),
            "extended private" => self.extended_private(arguments.value_of(option)),
            "extended public" => self.extended_public(arguments.value_of(option)),
            "json" => self.json(arguments.is_present(option)),
            "index" => self.index(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "indices" => self.indices(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "language" => self.language(arguments.value_of(option)),
            "mnemonic" => self.mnemonic(arguments.value_of(option)),
            "network" => self.network(arguments.value_of(option)),
            "password" => self.password(arguments.value_of(option)),
            "private" => self.private(arguments.value_of(option)),
            "public" => self.public(arguments.value_of(option)),
            "signrawtransaction" => self.sign_raw_transaction(arguments.values_of(option)),
            "word count" => self.word_count(clap::value_t!(arguments.value_of(*option), u8).ok()),
            _ => (),
        });
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

    /// Sets `transaction_parameters`to the specified transaction parameters, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn create_raw_transaction(&mut self, argument: Option<&str>) {
        if let Some(transaction_parameters) = argument {
            self.transaction_parameters = Some(transaction_parameters.to_string());
        }
    }

    /// Sets `derivation` to the specified derivation, overriding its previous state.
    /// If `derivation` is `\"custom\"`, then `path` is set to the specified path.
    /// If the specified argument is `None`, then no change occurs.
    fn derivation(&mut self, argument: Option<&str>) {
        match argument {
            Some("tron") => self.derivation = "tron".into(),
            Some("keepkey") => self.derivation = "keepkey".into(),
            Some("ledger-legacy") => self.derivation = "ledger-legacy".into(),
            Some("ledger-live") => self.derivation = "ledger-legacy".into(),
            Some("trezor") => self.derivation = "trezor".into(),
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

    /// Sets `index` to the specified index, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn index(&mut self, argument: Option<u32>) {
        if let Some(index) = argument {
            self.index = index;
        }
    }

    /// Sets `indices` to the specified number of indices, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn indices(&mut self, argument: Option<u32>) {
        if let Some(indices) = argument {
            self.indices = indices;
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
        if let Some(network) = argument {
            self.network = Some(network.to_string());
        }
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

    /// Sets `transaction_hex` and `transaction_private_key` to the specified transaction values, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn sign_raw_transaction(&mut self, argument: Option<Values>) {
        if let Some(transaction_parameters) = argument {
            let params: Vec<&str> = transaction_parameters.collect();
            self.transaction_hex = Some(params[0].to_string());
            self.transaction_private_key = Some(params[1].to_string());
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
            "tron" => Some(format!("m/44'/195'/0'/{}", self.index)),
            "keepkey" => Some(format!("m/44'/195'/{}'/0", self.index)),
            "ledger-legacy" => Some(format!("m/44'/195'/0'/{}", self.index)),
            "ledger-live" => Some(format!("m/44'/195'/{}'/0/0", self.index)),
            "trezor" => Some(format!("m/44'/195'/0'/{}", self.index)),
            "custom" => self.path.clone(),
            _ => match default {
                true => Some(format!("m/44'/195'/0'/0/{}", self.index)),
                false => None,
            },
        }
    }

    /// Returns the derivation paths with the specified account, chain, derivation, indices, and path.
    /// If `default` is enabled, then return the default path if no derivation was provided.
    fn to_derivation_paths(&self, default: bool) -> Vec<Option<String>> {
        let start = self.index;
        let end = start + self.indices;
        let mut options = self.clone();
        (start..end).map(|index| {
            // Sets the index to the specified index
            options.index(Some(index));
            // Generates the derivation path for the specified information
            options.to_derivation_path(default)
        }).collect()
    }
}

pub struct TronCLI;

impl CLI for TronCLI {
    type Options = TronOptions;

    const ABOUT: AboutType = "Generates a Tron wallet (include -h for more options)";
    const FLAGS: &'static [FlagType] = &[flag::JSON];
    const NAME: NameType = "tron";
    const OPTIONS: &'static [OptionType] = &[option::COUNT, option::NETWORK_TRON];
    const SUBCOMMANDS: &'static [SubCommandType] = &[
        subcommand::HD_ETHEREUM,
        subcommand::IMPORT_ETHEREUM,
        subcommand::IMPORT_HD_ETHEREUM,
        subcommand::TRANSACTION_ETHEREUM,
    ];

    /// Handle all CLI arguments and flags for Tron
    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Result<Self::Options, CLIError> {
        let mut options = TronOptions::default();
        options.parse(arguments, &["count", "json", "network"]);

        match arguments.subcommand() {
            ("hd", Some(arguments)) => {
                options.subcommand = Some("hd".into());
                options.parse(arguments, &["count", "json", "network"]);
                options.parse(arguments, &["derivation", "index", "indices", "language", "password", "word count"]);
            }
            ("import", Some(arguments)) => {
                options.subcommand = Some("import".into());
                options.parse(arguments, &["json", "network"]);
                options.parse(arguments, &["address", "private", "public"]);
            }
            ("import-hd", Some(arguments)) => {
                options.subcommand = Some("import-hd".into());
                options.parse(arguments, &["json", "network"]);
                options.parse(
                    arguments,
                    &[
                        "account",
                        "chain",
                        "derivation",
                        "extended private",
                        "extended public",
                        "index",
                        "indices",
                        "mnemonic",
                        "password",
                    ],
                );
            }
            ("transaction", Some(arguments)) => {
                options.subcommand = Some("transaction".into());
                options.parse(arguments, &["createrawtransaction", "network", "signrawtransaction"]);
            }
            _ => {}
        };

        Ok(options)
    }

    /// Generate the Tron wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) -> Result<(), CLIError> {
        fn output<N: TronNetwork, W: TronWordlist>(options: TronOptions) -> Result<(), CLIError> {
            let wallets = match options.subcommand.as_ref().map(String::as_str) {
                Some("hd") => {
                    let password = options.password.as_ref().map(String::as_str);
                    (0..options.count)
                        .flat_map(|_| {
                            // Sample a new HD wallet
                            let wallet = TronWallet::new_hd::<N, W, _>(
                                &mut StdRng::from_entropy(),
                                options.word_count,
                                password,
                                &options.to_derivation_path(true).unwrap(),
                            )
                                .unwrap();
                            let mnemonic = &wallet.mnemonic.unwrap();

                            // Generate the HD wallet, from `index` to a number of specified `indices`
                            options.to_derivation_paths(true).iter().flat_map(|path| {
                                match TronWallet::from_mnemonic::<N, W>(mnemonic, password, path.as_ref().unwrap()) {
                                    Ok(wallet) => vec![wallet],
                                    _ => vec![],
                                }
                            })
                            .collect::<Vec<TronWallet>>()
                        })
                        .collect()
                }
                Some("import") => {
                    if let Some(private_key) = options.private {
                        vec![
                                TronWallet::from_private_key::<TronMainnet>(&private_key).or(
                                    TronWallet::from_private_key::<TronTestnet>(&private_key),
                                )?,
                            ]
                        // vec![TronWallet::from_private_key(&private_key)?]
                    } else if let Some(public_key) = options.public {
                        // vec![TronWallet::from_public_key(&public_key)?]
                        vec![TronWallet::from_public_key::<N>(&public_key)?]
                    } else if let Some(address) = options.address {
                        // vec![TronWallet::from_address(&address)?]
                        vec![TronWallet::from_address::<TronMainnet>(&address)
                                .or(TronWallet::from_address::<TronTestnet>(&address))?]
                    } else {
                        vec![]
                    }
                }
                Some("import-hd") => {
                    if let Some(mnemonic) = options.mnemonic.clone() {
                        fn process_mnemonic<EN: TronNetwork, EW: TronWordlist>(
                            mnemonic: &String,
                            options: &TronOptions,
                        ) -> Result<Vec<TronWallet>, CLIError> {
                            // Generate the mnemonic wallets, from `index` to a number of specified `indices`
                            let mut wallets = vec![];
                            let password = options.password.as_ref().map(String::as_str);
                            for path in options.to_derivation_paths(true) {
                                wallets.push(TronWallet::from_mnemonic::<EN, EW>(mnemonic, password, path.as_ref().unwrap())?);
                            }
                            Ok(wallets)
                        }

                        process_mnemonic::<N, ChineseSimplified>(&mnemonic, &options)
                            .or(process_mnemonic::<N, ChineseTraditional>(&mnemonic, &options))
                            .or(process_mnemonic::<N, English>(&mnemonic, &options))
                            .or(process_mnemonic::<N, French>(&mnemonic, &options))
                            .or(process_mnemonic::<N, Italian>(&mnemonic, &options))
                            .or(process_mnemonic::<N, Japanese>(&mnemonic, &options))
                            .or(process_mnemonic::<N, Korean>(&mnemonic, &options))
                            .or(process_mnemonic::<N, Spanish>(&mnemonic, &options))?
                    } else if let Some(extended_private_key) = options.extended_private_key.clone() {
                        // Generate the extended private keys, from `index` to a number of specified `indices`
                        options.to_derivation_paths(true).iter().flat_map(|path| {
                            match TronWallet::from_extended_private_key::<N>(&extended_private_key, path) {
                                Ok(wallet) => vec![wallet],
                                _ => vec![],
                            }
                        })
                        .collect::<Vec<TronWallet>>()
                    } else if let Some(extended_public_key) = options.extended_public_key.clone() {
                        // Generate the extended public keys, from `index` to a number of specified `indices`
                        options.to_derivation_paths(true).iter().flat_map(|path| {
                            match TronWallet::from_extended_public_key::<N>(&extended_public_key, path) {
                                Ok(wallet) => vec![wallet],
                                _ => vec![],
                            }
                        })
                        .collect::<Vec<TronWallet>>()
                    } else {
                        vec![]
                    }
                }
                Some("transaction") => {
                    if let Some(transaction_parameters) = options.transaction_parameters.clone() {
                        let parameters: TronInput = from_str(&transaction_parameters)?;

                        // Note: Raw Tron transactions are network agnostic
                        vec![TronWallet::to_raw_transaction::<TronMainnet>(parameters)?]
                    } else if let (Some(transaction_hex), Some(transaction_private_key)) =
                        (options.transaction_hex.clone(), options.transaction_private_key.clone())
                    {
                        match options.network.as_ref().map(String::as_str) {
                            Some(TronMainnet::NAME) => vec![TronWallet::to_signed_transaction::<
                                TronMainnet,
                            >(
                                transaction_hex, transaction_private_key
                            )?],
                            Some(TronTestnet::NAME) => vec![TronWallet::to_signed_transaction::<
                                TronMainnet,
                            >(
                                transaction_hex, transaction_private_key
                            )?],
                            _ => vec![TronWallet::to_signed_transaction::<TronMainnet>(
                                transaction_hex,
                                transaction_private_key,
                            )?],
                        }
                    } else {
                        vec![]
                    }
                }
                _ => (0..options.count)
                    .flat_map(|_| match TronWallet::new::<N, _>(&mut StdRng::from_entropy()) {
                        Ok(wallet) => vec![wallet],
                        _ => vec![],
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


            "chinese_simplified" => match options.network.as_ref().map(String::as_str) {
                Some(TronTestnet::NAME) => output::<TronTestnet, ChineseSimplified>(options),
                _ => output::<TronMainnet, ChineseTraditional>(options),
            }
            "chinese_traditional" => match options.network.as_ref().map(String::as_str) {
                Some(TronTestnet::NAME) => output::<TronTestnet, ChineseTraditional>(options),
                _ => output::<TronMainnet, ChineseTraditional>(options),
            }
            "english" => match options.network.as_ref().map(String::as_str) {
                Some(TronTestnet::NAME) => output::<TronTestnet, English>(options),
                _ => output::<TronMainnet, English>(options),
            }
            "french" => match options.network.as_ref().map(String::as_str) {
                Some(TronTestnet::NAME) => output::<TronTestnet, French>(options),
                _ => output::<TronMainnet, French>(options),
            }
            "italian" => match options.network.as_ref().map(String::as_str) {
                Some(TronTestnet::NAME) => output::<TronTestnet, Italian>(options),
                _ => output::<TronMainnet, Italian>(options),
            }
            "japanese" => match options.network.as_ref().map(String::as_str) {
                Some(TronTestnet::NAME) => output::<TronTestnet, Japanese>(options),
                _ => output::<TronMainnet, Japanese>(options),
            }
            "korean" => match options.network.as_ref().map(String::as_str) {
                Some(TronTestnet::NAME) => output::<TronTestnet, Korean>(options),
                _ => output::<TronMainnet, Korean>(options),
            }
            "spanish" => match options.network.as_ref().map(String::as_str) {
                Some(TronTestnet::NAME) => output::<TronTestnet, Spanish>(options),
                _ => output::<TronMainnet, Spanish>(options),
            }
            _ => match options.network.as_ref().map(String::as_str) {
                Some(TronTestnet::NAME) => output::<TronTestnet, English>(options),
                _ => output::<TronMainnet, English>(options),
            }
            // "chinese_simplified" => output::<TronMainnet, ChineseSimplified>(options),
            // "chinese_traditional" => output::<TronMainnet, ChineseTraditional>(options),
            // "english" => output::<TronMainnet, English>(options),
            // "french" => output::<TronMainnet, French>(options),
            // "italian" => output::<TronMainnet, Italian>(options),
            // "japanese" => output::<TronMainnet, Japanese>(options),
            // "korean" => output::<TronMainnet, Korean>(options),
            // "spanish" => output::<TronMainnet, Spanish>(options),
            // _ => output::<TronMainnet, English>(options),
        }
    }
}
