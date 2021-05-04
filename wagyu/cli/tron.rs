use crate::tron::{
    format::TronFormat, wordlist::*, TronAddress, TronAmount, TronDerivationPath,
    TronExtendedPrivateKey, TronExtendedPublicKey, TronMnemonic, TronNetwork, TronPrivateKey,
    TronPublicKey, TronTransaction, TronTransactionInput, TronTransactionOutput,
    TronTransactionParameters, TronWordlist, Mainnet as TronMainnet, Outpoint, SignatureHash,
    Testnet as TronTestnet,
};
use crate::cli::{flag, option, subcommand, types::*, CLIError, CLI};
use crate::model::{
    crypto::hash160, ExtendedPrivateKey, ExtendedPublicKey, Mnemonic, MnemonicCount, MnemonicExtended, PrivateKey,
    PublicKey, Transaction,
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
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

impl TronWallet {
    pub fn new<N: TronNetwork, R: Rng>(rng: &mut R, format: &TronFormat) -> Result<Self, CLIError> {
        let private_key = TronPrivateKey::<N>::new(rng)?;
        let public_key = private_key.to_public_key();
        let address = public_key.to_address(format)?;
        Ok(Self {
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            network: Some(N::NAME.to_string()),
            format: Some(address.format().to_string()),
            compressed: private_key.is_compressed().into(),
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
        let address = public_key.to_address(&extended_private_key.format())?;
        let compressed = private_key.is_compressed();
        Ok(Self {
            path: Some(path.to_string()),
            password: password.map(String::from),
            mnemonic: Some(mnemonic.to_string()),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            format: Some(address.format().to_string()),
            network: Some(N::NAME.to_string()),
            compressed: Some(compressed),
            ..Default::default()
        })
    }

    pub fn from_mnemonic<N: TronNetwork, W: TronWordlist>(
        mnemonic: &str,
        password: &Option<&str>,
        path: &str,
    ) -> Result<Self, CLIError> {
        let mnemonic = TronMnemonic::<N, W>::from_phrase(&mnemonic)?;
        let master_extended_private_key = mnemonic.to_extended_private_key(password.clone())?;
        let derivation_path = TronDerivationPath::from_str(path)?;
        let extended_private_key = master_extended_private_key.derive(&derivation_path)?;
        let extended_public_key = extended_private_key.to_extended_public_key();
        let private_key = extended_private_key.to_private_key();
        let public_key = extended_public_key.to_public_key();
        let address = public_key.to_address(&extended_private_key.format())?;
        let compressed = private_key.is_compressed();
        Ok(Self {
            path: Some(path.to_string()),
            password: password.map(String::from),
            mnemonic: Some(mnemonic.to_string()),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            format: Some(address.format().to_string()),
            network: Some(N::NAME.to_string()),
            compressed: Some(compressed),
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
        let address = public_key.to_address(&extended_private_key.format())?;
        let compressed = private_key.is_compressed();
        Ok(Self {
            path: path.clone(),
            extended_private_key: Some(extended_private_key.to_string()),
            extended_public_key: Some(extended_public_key.to_string()),
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            format: Some(address.format().to_string()),
            network: Some(N::NAME.to_string()),
            compressed: Some(compressed),
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
        let address = public_key.to_address(&extended_public_key.format())?;
        let compressed = public_key.is_compressed();
        Ok(Self {
            path: path.clone(),
            extended_public_key: Some(extended_public_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            format: Some(address.format().to_string()),
            network: Some(N::NAME.to_string()),
            compressed: Some(compressed),
            ..Default::default()
        })
    }

    pub fn from_private_key<N: TronNetwork>(private_key: &str, format: &TronFormat) -> Result<Self, CLIError> {
        let private_key = TronPrivateKey::<N>::from_str(private_key)?;
        let public_key = private_key.to_public_key();
        let address = public_key.to_address(format)?;
        Ok(Self {
            private_key: Some(private_key.to_string()),
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            network: Some(N::NAME.to_string()),
            format: Some(address.format().to_string()),
            compressed: private_key.is_compressed().into(),
            ..Default::default()
        })
    }

    pub fn from_public_key<N: TronNetwork>(public_key: &str, format: &TronFormat) -> Result<Self, CLIError> {
        let public_key = TronPublicKey::<N>::from_str(public_key)?;
        let address = public_key.to_address(format)?;
        Ok(Self {
            public_key: Some(public_key.to_string()),
            address: Some(address.to_string()),
            network: Some(N::NAME.to_string()),
            format: Some(address.format().to_string()),
            compressed: public_key.is_compressed().into(),
            ..Default::default()
        })
    }

    pub fn from_address<N: TronNetwork>(address: &str) -> Result<Self, CLIError> {
        let address = TronAddress::<N>::from_str(address)?;
        Ok(Self {
            address: Some(address.to_string()),
            network: Some(N::NAME.to_string()),
            format: Some(address.format().to_string()),
            ..Default::default()
        })
    }

    pub fn to_raw_transaction<N: TronNetwork>(
        inputs: &Vec<TronInput>,
        outputs: &Vec<&str>,
        version: u32,
        lock_time: u32,
    ) -> Result<Self, CLIError> {
        let mut transaction_inputs = vec![];
        for input in inputs {
            let transaction_input = TronTransactionInput::<N>::new(
                hex::decode(&input.txid)?,
                input.vout,
                None,
                None,
                None,
                None,
                None,
                SignatureHash::SIGHASH_ALL,
            )?;
            transaction_inputs.push(transaction_input);
        }

        let mut transaction_outputs = vec![];
        for output in outputs {
            let values: Vec<&str> = output.split(":").collect();
            let address = TronAddress::<N>::from_str(values[0])?;
            transaction_outputs.push(TronTransactionOutput::new(
                &address,
                TronAmount::from_satoshi(i64::from_str(values[1])?)?,
            )?);
        }

        let transaction_parameters = TronTransactionParameters::<N> {
            version,
            inputs: transaction_inputs,
            outputs: transaction_outputs,
            lock_time,
            segwit_flag: false,
        };

        let transaction = TronTransaction::<N>::new(&transaction_parameters)?;
        let raw_transaction_hex = hex::encode(&transaction.to_transaction_bytes()?);

        Ok(Self {
            transaction_hex: Some(raw_transaction_hex),
            ..Default::default()
        })
    }

    pub fn to_signed_transaction<N: TronNetwork>(
        transaction_hex: &str,
        inputs: &Vec<TronInput>,
    ) -> Result<Self, CLIError> {
        let mut transaction = TronTransaction::<N>::from_transaction_bytes(&hex::decode(transaction_hex)?)?;

        for input in inputs {
            match (input.amount.clone(), input.address.clone(), input.private_key.clone()) {
                (Some(amount), Some(address), Some(private_key)) => {
                    let private_key = TronPrivateKey::<N>::from_str(&private_key)?;
                    let address = TronAddress::<N>::from_str(&address)?;

                    let redeem_script = match (input.redeem_script.clone(), address.format()) {
                        (Some(script), _) => Some(hex::decode(script)?),
                        (None, TronFormat::P2SH_P2WPKH) => {
                            let mut redeem_script = vec![0x00, 0x14];
                            redeem_script.extend(&hash160(
                                &private_key.to_public_key().to_secp256k1_public_key().serialize(),
                            ));
                            Some(redeem_script)
                        }
                        (None, _) => None,
                    };

                    let script_pub_key = match &input.script_pub_key {
                        Some(script) => Some(hex::decode(script)?),
                        None => None,
                    };

                    let mut reverse_transaction_id = hex::decode(&input.txid)?;
                    reverse_transaction_id.reverse();

                    let outpoint = Outpoint::<N>::new(
                        reverse_transaction_id,
                        input.vout,
                        Some(address),
                        Some(TronAmount::from_satoshi(amount as i64)?),
                        redeem_script,
                        script_pub_key,
                    )?;

                    transaction = transaction.update_outpoint(outpoint);
                    transaction = transaction.sign(&private_key)?;
                }
                _ => {}
            }
        }

        Ok(Self {
            transaction_id: Some(transaction.to_transaction_id()?.to_string()),
            transaction_hex: Some(hex::encode(&transaction.to_transaction_bytes()?)),
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
            match &self.transaction_id {
                Some(transaction_id) => format!("      {}       {}\n", "Transaction Id".cyan().bold(), transaction_id),
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

/// Represents parameters for a Tron transaction input
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TronInput {
    pub txid: String,
    pub vout: u32,
    pub amount: Option<u64>,
    pub address: Option<String>,
    #[serde(rename(deserialize = "privatekey"))]
    pub private_key: Option<String>,
    #[serde(rename(deserialize = "scriptPubKey"))]
    pub script_pub_key: Option<String>,
    #[serde(rename(deserialize = "redeemScript"))]
    pub redeem_script: Option<String>,
}

/// Represents options for a Tron wallet
#[derive(Clone, Debug, Serialize)]
pub struct TronOptions {
    // Standard command
    count: usize,
    format: TronFormat,
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
    // Transaction subcommand
    transaction_inputs: Option<String>,
    transaction_hex: Option<String>,
    transaction_outputs: Option<String>,
    lock_time: Option<u32>,
    version: Option<u32>,
}

impl Default for TronOptions {
    fn default() -> Self {
        Self {
            // Standard command
            count: 1,
            format: TronFormat::Tron,
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
            // Transaction subcommand
            transaction_inputs: None,
            transaction_hex: None,
            transaction_outputs: None,
            lock_time: None,
            version: None,
        }
    }
}

impl TronOptions {
    fn parse(&mut self, arguments: &ArgMatches, options: &[&str]) {
        options.iter().for_each(|option| match *option {
            "account" => self.account(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "address" => self.address(arguments.value_of(option)),
            "chain" => self.chain(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "count" => self.count(clap::value_t!(arguments.value_of(*option), usize).ok()),
            "createrawtransaction" => self.create_raw_transaction(arguments.values_of(option)),
            "derivation" => self.derivation(arguments.value_of(option)),
            "extended private" => self.extended_private(arguments.value_of(option)),
            "extended public" => self.extended_public(arguments.value_of(option)),
            "format" => self.format(arguments.value_of(option)),
            "json" => self.json(arguments.is_present(option)),
            "index" => self.index(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "language" => self.language(arguments.value_of(option)),
            "lock time" => self.lock_time(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "mnemonic" => self.mnemonic(arguments.value_of(option)),
            "network" => self.network(arguments.value_of(option)),
            "password" => self.password(arguments.value_of(option)),
            "private" => self.private(arguments.value_of(option)),
            "public" => self.public(arguments.value_of(option)),
            "signrawtransaction" => self.sign_raw_transaction(arguments.values_of(option)),
            "word count" => self.word_count(clap::value_t!(arguments.value_of(*option), u8).ok()),
            "version" => self.version(clap::value_t!(arguments.value_of(*option), u32).ok()),
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

    /// Sets `transaction_inputs` and `transaction_outputs` to the specified transaction values, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn create_raw_transaction(&mut self, argument: Option<Values>) {
        if let Some(transaction_parameters) = argument {
            let params: Vec<&str> = transaction_parameters.collect();
            self.transaction_inputs = Some(params[0].to_string());
            self.transaction_outputs = Some(params[1].to_string())
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
            Some("tron") => self.format = TronFormat::Tron,
            Some("legacy") => self.format = TronFormat::P2PKH,
            Some("segwit") => self.format = TronFormat::P2SH_P2WPKH,
            Some("bech32") => self.format = TronFormat::Bech32,
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

    /// Sets `lock_time` to the specified transaction lock time, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn lock_time(&mut self, argument: Option<u32>) {
        if let Some(lock_time) = argument {
            self.lock_time = Some(lock_time);
        }
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

    /// Sets `transaction_hex` and `transaction_inputs` to the specified transaction values, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn sign_raw_transaction(&mut self, argument: Option<Values>) {
        if let Some(transaction_parameters) = argument {
            let params: Vec<&str> = transaction_parameters.collect();
            self.transaction_hex = Some(params[0].to_string());
            self.transaction_inputs = Some(params[1].to_string());
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
            "bip32" => Some(format!("m/44'/195'/{}'", self.index)),
            "bip44" => Some(format!("m/44'/195'/{}'/{}/{}", self.account, self.chain, self.index)),
            "bip49" => Some(format!("m/49'/0'/{}'/{}/{}", self.account, self.chain, self.index)),
            "custom" => self.path.clone(),
            _ => match default {
                true => Some(format!("m/0'/0'/{}'", self.index)),
                false => None,
            },
        }
    }

    /// Sets `version` to the specified transaction version, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn version(&mut self, argument: Option<u32>) {
        if let Some(version) = argument {
            self.version = Some(version);
        }
    }
}

pub struct TronCLI;

impl CLI for TronCLI {
    type Options = TronOptions;

    const NAME: NameType = "tron";
    const ABOUT: AboutType = "Generates a Tron wallet (include -h for more options)";
    const FLAGS: &'static [FlagType] = &[flag::JSON];
    const OPTIONS: &'static [OptionType] = &[option::COUNT, option::FORMAT_BITCOIN, option::NETWORK_BITCOIN];
    const SUBCOMMANDS: &'static [SubCommandType] = &[
        subcommand::HD_BITCOIN,
        subcommand::IMPORT_BITCOIN,
        subcommand::IMPORT_HD_BITCOIN,
        subcommand::TRANSACTION_BITCOIN,
    ];

    /// Handle all CLI arguments and flags for Tron
    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Result<Self::Options, CLIError> {
        let mut options = TronOptions::default();
        options.parse(arguments, &["count", "format", "json", "network"]);

        match arguments.subcommand() {
            ("hd", Some(arguments)) => {
                options.subcommand = Some("hd".into());
                options.parse(arguments, &["count", "json", "network"]);
                options.parse(arguments, &["derivation", "language", "password", "word count"]);
            }
            ("import", Some(arguments)) => {
                options.subcommand = Some("import".into());
                options.parse(arguments, &["format", "json", "network"]);
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
                        "mnemonic",
                        "password",
                    ],
                );
            }
            ("transaction", Some(arguments)) => {
                options.subcommand = Some("transaction".into());
                options.parse(
                    arguments,
                    &["createrawtransaction", "lock time", "signrawtransaction", "version"],
                );
            }
            _ => {}
        };

        Ok(options)
    }

    /// Generate the Tron wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) -> Result<(), CLIError> {
        fn output<N: TronNetwork, W: TronWordlist>(options: TronOptions) -> Result<(), CLIError> {
            let wallets =
                match options.subcommand.as_ref().map(String::as_str) {
                    Some("hd") => match options.to_derivation_path(true) {
                        Some(path) => (0..options.count)
                            .flat_map(|_| {
                                match TronWallet::new_hd::<N, W, _>(
                                    &mut StdRng::from_entropy(),
                                    options.word_count,
                                    options.password.as_ref().map(String::as_str),
                                    &path,
                                ) {
                                    Ok(wallet) => vec![wallet],
                                    _ => vec![],
                                }
                            })
                            .collect(),
                        None => vec![],
                    },
                    Some("import") => {
                        if let Some(private_key) = options.private {
                            vec![
                                TronWallet::from_private_key::<TronMainnet>(&private_key, &options.format).or(
                                    TronWallet::from_private_key::<TronTestnet>(&private_key, &options.format),
                                )?,
                            ]
                        } else if let Some(public_key) = options.public {
                            vec![TronWallet::from_public_key::<N>(&public_key, &options.format)?]
                        } else if let Some(address) = options.address {
                            vec![TronWallet::from_address::<TronMainnet>(&address)
                                .or(TronWallet::from_address::<TronTestnet>(&address))?]
                        } else {
                            vec![]
                        }
                    }
                    Some("import-hd") => {
                        if let Some(mnemonic) = options.mnemonic.clone() {
                            let password = &options.password.as_ref().map(String::as_str);

                            match options.to_derivation_path(true) {
                                Some(path) => vec![TronWallet::from_mnemonic::<N, ChineseSimplified>(
                                    &mnemonic, password, &path,
                                )
                                .or(TronWallet::from_mnemonic::<N, ChineseTraditional>(
                                    &mnemonic, password, &path,
                                ))
                                .or(TronWallet::from_mnemonic::<N, English>(&mnemonic, password, &path))
                                .or(TronWallet::from_mnemonic::<N, French>(&mnemonic, password, &path))
                                .or(TronWallet::from_mnemonic::<N, Italian>(&mnemonic, password, &path))
                                .or(TronWallet::from_mnemonic::<N, Japanese>(&mnemonic, password, &path))
                                .or(TronWallet::from_mnemonic::<N, Korean>(&mnemonic, password, &path))
                                .or(TronWallet::from_mnemonic::<N, Spanish>(&mnemonic, password, &path))?],
                                None => vec![],
                            }
                        } else if let Some(extended_private_key) = options.extended_private_key.clone() {
                            let key = &extended_private_key;
                            let path = &options.to_derivation_path(false);

                            vec![TronWallet::from_extended_private_key::<TronMainnet>(key, path)
                                .or(TronWallet::from_extended_private_key::<TronTestnet>(key, path))?]
                        } else if let Some(extended_public_key) = options.extended_public_key.clone() {
                            let key = &extended_public_key;
                            let path = &options.to_derivation_path(false);

                            vec![TronWallet::from_extended_public_key::<TronMainnet>(key, path)
                                .or(TronWallet::from_extended_public_key::<TronTestnet>(key, path))?]
                        } else {
                            vec![]
                        }
                    }
                    Some("transaction") => {
                        if let (Some(transaction_inputs), Some(transaction_outputs)) =
                            (options.transaction_inputs.clone(), options.transaction_outputs.clone())
                        {
                            let inputs: &Vec<TronInput> = &from_str(&transaction_inputs)?;
                            let outputs = transaction_outputs.replace(&['{', '}', '"', ' '][..], "");
                            let outputs: &Vec<&str> = &outputs.split(",").collect();
                            let version = options.version.unwrap_or(1);
                            let lock_time = options.lock_time.unwrap_or(0);

                            vec![TronWallet::to_raw_transaction::<TronMainnet>(
                                inputs, outputs, version, lock_time,
                            )
                            .or(TronWallet::to_raw_transaction::<TronTestnet>(
                                inputs, outputs, version, lock_time,
                            ))?]
                        } else if let (Some(transaction_hex), Some(transaction_inputs)) =
                            (options.transaction_hex.clone(), options.transaction_inputs.clone())
                        {
                            let inputs: &Vec<TronInput> = &from_str(&transaction_inputs)?;

                            vec![
                                TronWallet::to_signed_transaction::<TronMainnet>(&transaction_hex, inputs).or(
                                    TronWallet::to_signed_transaction::<TronTestnet>(&transaction_hex, inputs),
                                )?,
                            ]
                        } else {
                            vec![]
                        }
                    }
                    _ => (0..options.count)
                        .flat_map(
                            |_| match TronWallet::new::<N, _>(&mut StdRng::from_entropy(), &options.format) {
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
                "testnet" => output::<TronTestnet, ChineseSimplified>(options),
                _ => output::<TronMainnet, ChineseSimplified>(options),
            },
            "chinese_traditional" => match options.network.as_str() {
                "testnet" => output::<TronTestnet, ChineseTraditional>(options),
                _ => output::<TronMainnet, ChineseTraditional>(options),
            },
            "english" => match options.network.as_str() {
                "testnet" => output::<TronTestnet, English>(options),
                _ => output::<TronMainnet, English>(options),
            },
            "french" => match options.network.as_str() {
                "testnet" => output::<TronTestnet, French>(options),
                _ => output::<TronMainnet, French>(options),
            },
            "italian" => match options.network.as_str() {
                "testnet" => output::<TronTestnet, Italian>(options),
                _ => output::<TronMainnet, Italian>(options),
            },
            "japanese" => match options.network.as_str() {
                "testnet" => output::<TronTestnet, Japanese>(options),
                _ => output::<TronMainnet, Japanese>(options),
            },
            "korean" => match options.network.as_str() {
                "testnet" => output::<TronTestnet, Korean>(options),
                _ => output::<TronMainnet, Korean>(options),
            },
            "spanish" => match options.network.as_str() {
                "testnet" => output::<TronTestnet, Spanish>(options),
                _ => output::<TronMainnet, Spanish>(options),
            },
            _ => match options.network.as_str() {
                "testnet" => output::<TronTestnet, English>(options),
                _ => output::<TronMainnet, English>(options),
            },
        }
    }
}
