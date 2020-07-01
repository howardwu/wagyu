use crate::cli::{flag, option, subcommand, types::*, CLIError, CLI};
use crate::ethereum::{
    wordlist::*, EthereumAddress, EthereumAmount, EthereumDerivationPath, EthereumExtendedPrivateKey,
    EthereumExtendedPublicKey, EthereumFormat, EthereumMnemonic, EthereumNetwork, EthereumPrivateKey,
    EthereumPublicKey, EthereumTransaction, EthereumTransactionParameters, Goerli, Kovan, Mainnet as EthereumMainnet,
    Rinkeby, Ropsten,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_hex: Option<String>,
}

impl EthereumWallet {
    pub fn new<R: Rng>(rng: &mut R) -> Result<Self, CLIError> {
        let private_key = EthereumPrivateKey::new(rng)?;
        let public_key = private_key.to_public_key();
        let address = public_key.to_address(&EthereumFormat::Standard)?;
        Ok(Self {
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            ..Default::default()
        })
    }

    #[allow(dead_code)]
    pub fn new_hd<N: EthereumNetwork, W: EthereumWordlist, R: Rng>(
        rng: &mut R,
        word_count: u8,
        password: Option<&str>,
        path: &str,
    ) -> Result<Self, CLIError> {
        let mnemonic = EthereumMnemonic::<N, W>::new_with_count(rng, word_count)?;
        let master_extended_private_key = mnemonic.to_extended_private_key(password)?;
        let derivation_path = EthereumDerivationPath::from_str(path)?;
        let extended_private_key = master_extended_private_key.derive(&derivation_path)?;
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(&EthereumFormat::Standard)?;
        Ok(Self {
            path: Some(path.to_string()),
            password: password.map(String::from),
            mnemonic: Some(mnemonic.to_string()),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            ..Default::default()
        })
    }

    pub fn from_mnemonic<N: EthereumNetwork, W: EthereumWordlist>(
        mnemonic: &str,
        password: Option<&str>,
        path: &str,
    ) -> Result<Self, CLIError> {
        let mnemonic = EthereumMnemonic::<N, W>::from_phrase(&mnemonic)?;
        let master_extended_private_key = mnemonic.to_extended_private_key(password)?;
        let derivation_path = EthereumDerivationPath::from_str(path)?;
        let extended_private_key = master_extended_private_key.derive(&derivation_path)?;
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(&EthereumFormat::Standard)?;
        Ok(Self {
            path: Some(path.to_string()),
            password: password.map(String::from),
            mnemonic: Some(mnemonic.to_string()),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            ..Default::default()
        })
    }

    pub fn from_extended_private_key<N: EthereumNetwork>(
        extended_private_key: &str,
        path: &Option<String>,
    ) -> Result<Self, CLIError> {
        let mut extended_private_key = EthereumExtendedPrivateKey::<N>::from_str(extended_private_key)?;
        if let Some(derivation_path) = path {
            let derivation_path = EthereumDerivationPath::from_str(&derivation_path)?;
            extended_private_key = extended_private_key.derive(&derivation_path)?;
        }
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(&EthereumFormat::Standard)?;
        Ok(Self {
            path: path.clone(),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            ..Default::default()
        })
    }

    pub fn from_extended_public_key<N: EthereumNetwork>(
        extended_public_key: &str,
        path: &Option<String>,
    ) -> Result<Self, CLIError> {
        let mut extended_public_key = EthereumExtendedPublicKey::<N>::from_str(extended_public_key)?;
        if let Some(derivation_path) = path {
            let derivation_path = EthereumDerivationPath::from_str(&derivation_path)?;
            extended_public_key = extended_public_key.derive(&derivation_path)?;
        }
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(&EthereumFormat::Standard)?;
        Ok(Self {
            path: path.clone(),
            extended_public_key: Some(extended_public_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            ..Default::default()
        })
    }

    pub fn from_private_key(private_key: &str) -> Result<Self, CLIError> {
        let private_key = EthereumPrivateKey::from_str(private_key)?;
        let public_key = private_key.to_public_key();
        let address = public_key.to_address(&EthereumFormat::Standard)?;
        Ok(Self {
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            ..Default::default()
        })
    }

    pub fn from_public_key(public_key: &str) -> Result<Self, CLIError> {
        let public_key = EthereumPublicKey::from_str(public_key)?;
        let address = public_key.to_address(&EthereumFormat::Standard)?;
        Ok(Self {
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            ..Default::default()
        })
    }

    pub fn from_address(address: &str) -> Result<Self, CLIError> {
        let address = EthereumAddress::from_str(address)?;
        Ok(Self {
            address: Some(address.to_string()),
            ..Default::default()
        })
    }

    pub fn to_raw_transaction<N: EthereumNetwork>(parameters: EthereumInput) -> Result<Self, CLIError> {
        let transaction_parameters = EthereumTransactionParameters {
            receiver: EthereumAddress::from_str(&parameters.to)?,
            amount: EthereumAmount::from_wei(&parameters.value)?,
            gas: EthereumAmount::u256_from_str(&parameters.gas)?,
            gas_price: EthereumAmount::from_wei(&parameters.gas_price)?,
            nonce: EthereumAmount::u256_from_str(&parameters.nonce.to_string())?,
            data: parameters.data.unwrap_or("".to_string()).as_bytes().to_vec(),
        };

        let raw_transaction = EthereumTransaction::<N>::new(&transaction_parameters)?;
        let raw_transaction_hex = hex::encode(raw_transaction.to_transaction_bytes()?);

        Ok(Self {
            transaction_hex: Some(format!("0x{}", raw_transaction_hex)),
            ..Default::default()
        })
    }

    pub fn to_signed_transaction<N: EthereumNetwork>(
        transaction_hex: String,
        private_key: String,
    ) -> Result<Self, CLIError> {
        let transaction_bytes = match &transaction_hex[0..2] {
            "0x" => hex::decode(&transaction_hex[2..])?,
            _ => hex::decode(&transaction_hex)?,
        };

        let private_key = EthereumPrivateKey::from_str(&private_key)?;

        let mut transaction = EthereumTransaction::<N>::from_transaction_bytes(&transaction_bytes)?;
        transaction = transaction.sign(&private_key)?;

        Ok(Self {
            transaction_id: Some(transaction.to_transaction_id()?.to_string()),
            transaction_hex: Some(format!("0x{}", hex::encode(&transaction.to_transaction_bytes()?))),
            ..Default::default()
        })
    }
}

#[cfg_attr(tarpaulin, skip)]
impl Display for EthereumWallet {
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

/// Represents parameters for an Ethereum transaction input
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EthereumInput {
    pub to: String,
    pub value: String,
    pub gas: String,
    #[serde(rename(deserialize = "gasPrice"))]
    pub gas_price: String,
    pub nonce: u64,
    pub data: Option<String>,
}

/// Represents options for an Ethereum wallet
#[derive(Clone, Debug, Serialize)]
pub struct EthereumOptions {
    // Standard command
    count: usize,
    json: bool,
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
    network: Option<String>,
}

impl Default for EthereumOptions {
    fn default() -> Self {
        Self {
            // Standard command
            count: 1,
            json: false,
            subcommand: None,
            // HD and Import HD subcommands
            derivation: "ethereum".into(),
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
            network: None,
        }
    }
}

impl EthereumOptions {
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
            Some("ethereum") => self.derivation = "ethereum".into(),
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

    /// Sets `indices` to the specified indices, overriding its previous state.
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
            "ethereum" => Some(format!("m/44'/60'/0'/0/{}", self.index)),
            "keepkey" => Some(format!("m/44'/60'/{}'/0", self.index)),
            "ledger-legacy" => Some(format!("m/44'/60'/0'/{}", self.index)),
            "ledger-live" => Some(format!("m/44'/60'/{}'/0/0", self.index)),
            "trezor" => Some(format!("m/44'/60'/0'/0/{}", self.index)),
            "custom" => self.path.clone(),
            _ => match default {
                true => Some(format!("m/44'/60'/0'/0/{}", self.index)),
                false => None,
            },
        }
    }
}

pub struct EthereumCLI;

impl CLI for EthereumCLI {
    type Options = EthereumOptions;

    const NAME: NameType = "ethereum";
    const ABOUT: AboutType = "Generates a Ethereum wallet (include -h for more options)";
    const FLAGS: &'static [FlagType] = &[flag::JSON];
    const OPTIONS: &'static [OptionType] = &[option::COUNT];
    const SUBCOMMANDS: &'static [SubCommandType] = &[
        subcommand::HD_ETHEREUM,
        subcommand::IMPORT_ETHEREUM,
        subcommand::IMPORT_HD_ETHEREUM,
        subcommand::TRANSACTION_ETHEREUM,
    ];

    /// Handle all CLI arguments and flags for Ethereum
    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Result<Self::Options, CLIError> {
        let mut options = EthereumOptions::default();
        options.parse(arguments, &["count", "json"]);

        match arguments.subcommand() {
            ("hd", Some(arguments)) => {
                options.subcommand = Some("hd".into());
                options.parse(arguments, &["count", "json"]);
                options.parse(
                    arguments,
                    &["derivation", "index", "indices", "language", "password", "word count"],
                );
            }
            ("import", Some(arguments)) => {
                options.subcommand = Some("import".into());
                options.parse(arguments, &["json"]);
                options.parse(arguments, &["address", "private", "public"]);
            }
            ("import-hd", Some(arguments)) => {
                options.subcommand = Some("import-hd".into());
                options.parse(arguments, &["json"]);
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

    /// Generate the Ethereum wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) -> Result<(), CLIError> {
        fn output<N: EthereumNetwork, W: EthereumWordlist>(options: EthereumOptions) -> Result<(), CLIError> {
            let wallets = match options.subcommand.as_ref().map(String::as_str) {
                Some("hd") => (0..options.count)
                    .flat_map(|_| {
                        let mut rng = StdRng::from_entropy();
                        let mnemonic = EthereumMnemonic::<N, W>::new_with_count(&mut rng, options.word_count).unwrap();
                        let password = options.password.as_ref().map(String::as_str);
                        let mut opt = options.clone();
                        let hd_wallet_from_mnemonic = move |i| {
                            opt.index(Some(i));
                            let path = opt.to_derivation_path(true).unwrap();

                            match EthereumWallet::from_mnemonic::<N, W>(&format!("{}", mnemonic), password, &path) {
                                Ok(wallet) => vec![wallet],
                                _ => vec![],
                            }
                        };
                        if options.index > 0 {
                            (options.index..options.index + 1).flat_map(hd_wallet_from_mnemonic)
                        } else {
                            (0..options.indices).flat_map(hd_wallet_from_mnemonic)
                        }
                    })
                    .collect(),
                Some("import") => {
                    if let Some(private_key) = options.private {
                        vec![EthereumWallet::from_private_key(&private_key)?]
                    } else if let Some(public_key) = options.public {
                        vec![EthereumWallet::from_public_key(&public_key)?]
                    } else if let Some(address) = options.address {
                        vec![EthereumWallet::from_address(&address)?]
                    } else {
                        vec![]
                    }
                }
                Some("import-hd") => {
                    let begin;
                    let end;
                    if options.index > 0 {
                        begin = options.index;
                        end = options.index + 1;
                    } else if options.indices > 1 {
                        begin = 0;
                        end = options.indices;
                    } else {
                        begin = 0;
                        end = 1;
                    }
                    let mut ops = options.clone();
                    if let Some(mnemonic) = options.mnemonic.clone() {
                        fn process_mnemonic<EN: EthereumNetwork, EW: EthereumWordlist>(
                            mnemonic: &String,
                            options: &EthereumOptions,
                        ) -> Result<EthereumWallet, CLIError> {
                            EthereumWallet::from_mnemonic::<EN, EW>(
                                &mnemonic,
                                options.password.as_ref().map(String::as_str),
                                &options.to_derivation_path(true).unwrap(),
                            )
                        }
                        (begin..end)
                            .map(|i| {
                                ops.index(Some(i));
                                process_mnemonic::<N, ChineseSimplified>(&mnemonic, &ops)
                                    .or(process_mnemonic::<N, ChineseTraditional>(&mnemonic, &ops))
                                    .or(process_mnemonic::<N, English>(&mnemonic, &ops))
                                    .or(process_mnemonic::<N, French>(&mnemonic, &ops))
                                    .or(process_mnemonic::<N, Italian>(&mnemonic, &ops))
                                    .or(process_mnemonic::<N, Japanese>(&mnemonic, &ops))
                                    .or(process_mnemonic::<N, Korean>(&mnemonic, &ops))
                                    .or(process_mnemonic::<N, Spanish>(&mnemonic, &ops))
                                    .unwrap()
                            })
                            .collect()
                    } else if let Some(extended_private_key) = options.extended_private_key.clone() {
                        (begin..end)
                            .map(|i| {
                                ops.index(Some(i));
                                EthereumWallet::from_extended_private_key::<N>(
                                    &extended_private_key,
                                    &ops.to_derivation_path(false),
                                )
                                .unwrap()
                            })
                            .collect()
                    } else if let Some(extended_public_key) = options.extended_public_key.clone() {
                        (begin..end)
                            .map(|i| {
                                ops.index(Some(i));
                                EthereumWallet::from_extended_public_key::<N>(
                                    &extended_public_key,
                                    &ops.to_derivation_path(false),
                                )
                                .unwrap()
                            })
                            .collect()
                    } else {
                        vec![]
                    }
                }
                Some("transaction") => {
                    if let Some(transaction_parameters) = options.transaction_parameters.clone() {
                        let parameters: EthereumInput = from_str(&transaction_parameters)?;

                        // Note: Raw Ethereum transactions are network agnostic
                        vec![EthereumWallet::to_raw_transaction::<EthereumMainnet>(parameters)?]
                    } else if let (Some(transaction_hex), Some(transaction_private_key)) =
                        (options.transaction_hex.clone(), options.transaction_private_key.clone())
                    {
                        match options.network.as_ref().map(String::as_str) {
                            Some(EthereumMainnet::NAME) => vec![EthereumWallet::to_signed_transaction::<
                                EthereumMainnet,
                            >(
                                transaction_hex, transaction_private_key
                            )?],
                            Some(Goerli::NAME) => vec![EthereumWallet::to_signed_transaction::<Goerli>(
                                transaction_hex,
                                transaction_private_key,
                            )?],
                            Some(Kovan::NAME) => vec![EthereumWallet::to_signed_transaction::<Kovan>(
                                transaction_hex,
                                transaction_private_key,
                            )?],
                            Some(Rinkeby::NAME) => vec![EthereumWallet::to_signed_transaction::<Rinkeby>(
                                transaction_hex,
                                transaction_private_key,
                            )?],
                            Some(Ropsten::NAME) => vec![EthereumWallet::to_signed_transaction::<Ropsten>(
                                transaction_hex,
                                transaction_private_key,
                            )?],
                            _ => vec![EthereumWallet::to_signed_transaction::<EthereumMainnet>(
                                transaction_hex,
                                transaction_private_key,
                            )?],
                        }
                    } else {
                        vec![]
                    }
                }
                _ => (0..options.count)
                    .flat_map(|_| match EthereumWallet::new::<_>(&mut StdRng::from_entropy()) {
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
            "chinese_simplified" => output::<EthereumMainnet, ChineseSimplified>(options),
            "chinese_traditional" => output::<EthereumMainnet, ChineseTraditional>(options),
            "english" => output::<EthereumMainnet, English>(options),
            "french" => output::<EthereumMainnet, French>(options),
            "italian" => output::<EthereumMainnet, Italian>(options),
            "japanese" => output::<EthereumMainnet, Japanese>(options),
            "korean" => output::<EthereumMainnet, Korean>(options),
            "spanish" => output::<EthereumMainnet, Spanish>(options),
            _ => output::<EthereumMainnet, English>(options),
        }
    }
}
