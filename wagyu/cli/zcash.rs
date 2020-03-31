use crate::cli::{flag, option, subcommand, types::*, CLIError, CLI};
use crate::model::{ExtendedPrivateKey, ExtendedPublicKey, PrivateKey, PublicKey, Transaction};
use crate::zcash::{
    format::ZcashFormat, initialize_proving_context, initialize_verifying_context, load_sapling_parameters,
    Mainnet as ZcashMainnet, Outpoint, SignatureHash, Testnet as ZcashTestnet, ZcashAddress, ZcashAmount,
    ZcashDerivationPath, ZcashExtendedPrivateKey, ZcashExtendedPublicKey, ZcashNetwork, ZcashPrivateKey,
    ZcashPublicKey, ZcashTransaction, ZcashTransactionParameters,
};

use clap::{ArgMatches, Values};
use colored::*;
use rand::{rngs::StdRng, Rng};
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diversifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outgoing_view_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_hex: Option<String>,
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
            address: Some(address.to_string()),
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
            address: Some(address.to_string()),
            format: Some(address.format().to_string()),
            diversifier: address.to_diversifier(),
            network: Some(N::NAME.to_string()),
            ..Default::default()
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
            address: Some(address.to_string()),
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
            address: Some(address.to_string()),
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
            address: Some(address.to_string()),
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
            address: Some(address.to_string()),
            format: Some(address.format().to_string()),
            diversifier: address.to_diversifier(),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn from_address<N: ZcashNetwork>(address: &str) -> Result<Self, CLIError> {
        let address = ZcashAddress::<N>::from_str(address)?;
        Ok(Self {
            address: Some(address.to_string()),
            format: Some(address.format().to_string()),
            diversifier: address.to_diversifier(),
            network: Some(N::NAME.to_string()),
            ..Default::default()
        })
    }

    pub fn to_raw_transaction<N: ZcashNetwork>(
        inputs: &Vec<ZcashInput>,
        outputs: &Vec<&str>,
        version: String,
        lock_time: u32,
        expiry_height: u32,
    ) -> Result<Self, CLIError> {
        let parameters = ZcashTransactionParameters::<N>::new(&version, lock_time, expiry_height)?;
        let mut transaction = ZcashTransaction::<N>::new(&parameters)?;

        for input in inputs {
            transaction.parameters = transaction.parameters.add_transparent_input(
                hex::decode(&input.txid)?,
                input.vout,
                None,
                None,
                None,
                None,
                None,
                SignatureHash::SIGHASH_ALL,
            )?;
        }

        let mut sapling_outputs = false;

        for output in outputs {
            let values: Vec<&str> = output.split(":").collect();
            let address = ZcashAddress::<N>::from_str(values[0])?;
            let amount = ZcashAmount::from_zatoshi(i64::from_str(values[1])?)?;

            match &address.format() {
                ZcashFormat::Sapling(_) => {
                    transaction.parameters = transaction.parameters.add_sapling_output(None, &address, amount)?;
                    sapling_outputs = true;
                }
                _ => {
                    transaction.parameters = transaction.parameters.add_transparent_output(&address, amount)?;
                }
            }
        }

        let mut outgoing_view_key = None;
        if sapling_outputs {
            outgoing_view_key = match &transaction.parameters.shielded_outputs[0].output_parameters {
                Some(params) => Some(hex::encode(params.ovk.0)),
                None => None,
            };

            let (spend_params, spend_vk, output_params, output_vk) = load_sapling_parameters();
            let mut proving_ctx = initialize_proving_context();
            let mut verifying_ctx = initialize_verifying_context();
            transaction.build_sapling_transaction(
                &mut proving_ctx,
                &mut verifying_ctx,
                &spend_params,
                &spend_vk,
                &output_params,
                &output_vk,
            )?;
        }

        let raw_transaction_hex = hex::encode(transaction.to_transaction_bytes()?);

        Ok(Self {
            outgoing_view_key,
            transaction_hex: Some(raw_transaction_hex),
            ..Default::default()
        })
    }

    pub fn to_signed_transaction<N: ZcashNetwork>(
        transaction_hex: &str,
        inputs: &Vec<ZcashInput>,
    ) -> Result<Self, CLIError> {
        let mut transaction = ZcashTransaction::<N>::from_transaction_bytes(&hex::decode(transaction_hex)?)?;

        for input in inputs {
            match (input.amount.clone(), input.address.clone(), input.private_key.clone()) {
                (Some(amount), Some(address), Some(private_key)) => {
                    let private_key = ZcashPrivateKey::<N>::from_str(&private_key)?;
                    let address = ZcashAddress::<N>::from_str(&address)?;

                    let mut reverse_transaction_id = hex::decode(&input.txid)?;
                    reverse_transaction_id.reverse();

                    let script_pub_key = match &input.script_pub_key {
                        Some(script) => Some(hex::decode(script)?),
                        None => None,
                    };

                    let redeem_script = match &input.redeem_script {
                        Some(script) => Some(hex::decode(script)?),
                        None => None,
                    };

                    let outpoint = Outpoint::<N>::new(
                        reverse_transaction_id,
                        input.vout,
                        Some(address),
                        Some(ZcashAmount::from_zatoshi(amount as i64)?),
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
            match &self.address {
                Some(address) => format!("      {}              {}\n", "Address".cyan().bold(), address),
                _ => "".to_owned(),
            },
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
            match &self.outgoing_view_key {
                Some(outgoing_view_key) => {
                    format!("      {}    {}\n", "Outgoing View Key".cyan().bold(), outgoing_view_key)
                }
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

/// Represents parameters for a Zcash transparent transaction input
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ZcashInput {
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
    // Transaction subcommand
    transaction_inputs: Option<String>,
    transaction_hex: Option<String>,
    transaction_outputs: Option<String>,
    expiry_height: Option<u32>,
    lock_time: Option<u32>,
    version: Option<String>,
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
            // Transaction subcommand
            transaction_inputs: None,
            transaction_hex: None,
            transaction_outputs: None,
            expiry_height: None,
            lock_time: None,
            version: None,
        }
    }
}

impl ZcashOptions {
    fn parse(&mut self, arguments: &ArgMatches, options: &[&str]) {
        options.iter().for_each(|option| match *option {
            "account" => self.account(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "address" => self.address(arguments.value_of(option)),
            "count" => self.count(clap::value_t!(arguments.value_of(*option), usize).ok()),
            "createrawtransaction" => self.create_raw_transaction(arguments.values_of(option)),
            "derivation" => self.derivation(arguments.value_of(option)),
            "diversifier" => self.diversifier(arguments.value_of(option)),
            "expiry height" => self.expiry_height(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "extended private" => self.extended_private(arguments.value_of(option)),
            "extended public" => self.extended_public(arguments.value_of(option)),
            "format" => self.format(arguments.value_of(option)),
            "index" => self.index(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "json" => self.json(arguments.is_present(option)),
            "lock time" => self.lock_time(clap::value_t!(arguments.value_of(*option), u32).ok()),
            "network" => self.network(arguments.value_of(option)),
            "private" => self.private(arguments.value_of(option)),
            "public" => self.public(arguments.value_of(option)),
            "signrawtransaction" => self.sign_raw_transaction(arguments.values_of(option)),
            "version" => self.version(arguments.value_of(option)),
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

    /// Sets `expiry_height` to the specified transaction lock time, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn expiry_height(&mut self, argument: Option<u32>) {
        if let Some(expiry_height) = argument {
            self.expiry_height = Some(expiry_height);
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

    /// Sets `lock_time` to the specified transaction lock time, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn lock_time(&mut self, argument: Option<u32>) {
        if let Some(lock_time) = argument {
            self.lock_time = Some(lock_time);
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

    /// Returns the derivation path with the specified account, index, and path.
    /// If `default` is enabled, then return the default path if no derivation was provided.
    fn to_derivation_path(&self, default: bool) -> Option<String> {
        match self.derivation.as_str() {
            "zip32" => match self.network.as_str() {
                "mainnet" => Some(format!("m/32'/133'/{}'/{}", self.account, self.index)),
                "testnet" => Some(format!("m/32'/1'/{}'/{}", self.account, self.index)),
                _ => None,
            },
            "custom" => self.path.clone(),
            _ => match default {
                true => match self.network.as_str() {
                    "mainnet" => Some(format!("m/32'/133'/{}'/{}", self.account, self.index)),
                    "testnet" => Some(format!("m/32'/1'/{}'/{}", self.account, self.index)),
                    _ => None,
                },
                false => None,
            },
        }
    }

    /// Sets `version` to the specified transaction version, overriding its previous state.
    /// If the specified argument is `None`, then no change occurs.
    fn version(&mut self, argument: Option<&str>) {
        if let Some(version) = argument {
            self.version = Some(version.to_string());
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
        subcommand::TRANSACTION_ZCASH,
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
            ("transaction", Some(arguments)) => {
                options.subcommand = Some("transaction".into());
                options.parse(
                    arguments,
                    &[
                        "createrawtransaction",
                        "expiry height",
                        "lock time",
                        "signrawtransaction",
                        "version",
                    ],
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
                    Some("hd") => match options.to_derivation_path(true) {
                        Some(path) => (0..options.count)
                            .flat_map(|_| {
                                match ZcashWallet::new_hd::<N, _>(&mut StdRng::from_entropy(), &path, &options.format) {
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
                    Some("transaction") => {
                        if let (Some(transaction_inputs), Some(transaction_outputs)) =
                            (options.transaction_inputs.clone(), options.transaction_outputs.clone())
                        {
                            let inputs: &Vec<ZcashInput> = &from_str(&transaction_inputs)?;
                            let outputs = transaction_outputs.replace(&['{', '}', '"', ' '][..], "");
                            let outputs: &Vec<&str> = &outputs.split(",").collect();
                            let version = options.version.unwrap_or("sapling".to_string());
                            let lock_time = options.lock_time.unwrap_or(0);
                            let expiry_height = options.expiry_height.unwrap_or(0);

                            vec![ZcashWallet::to_raw_transaction::<ZcashMainnet>(
                                inputs,
                                outputs,
                                version.clone(),
                                lock_time,
                                expiry_height,
                            )
                            .or(ZcashWallet::to_raw_transaction::<ZcashTestnet>(
                                inputs,
                                outputs,
                                version.clone(),
                                lock_time,
                                expiry_height,
                            ))?]
                        } else if let (Some(transaction_hex), Some(transaction_inputs)) =
                            (options.transaction_hex.clone(), options.transaction_inputs.clone())
                        {
                            let inputs: &Vec<ZcashInput> = &from_str(&transaction_inputs)?;

                            vec![
                                ZcashWallet::to_signed_transaction::<ZcashMainnet>(&transaction_hex, inputs).or(
                                    ZcashWallet::to_signed_transaction::<ZcashTestnet>(&transaction_hex, inputs),
                                )?,
                            ]
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
