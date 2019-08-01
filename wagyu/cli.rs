//! # Wagyu CLI
//!
//! A command-line tool to generate cryptocurrency wallets.

use bitcoin::address::Format as BitcoinFormat;
use bitcoin::{BitcoinAddress, BitcoinMnemonic, BitcoinPrivateKey, Mainnet as BitcoinMainnet, BitcoinNetwork, BitcoinDerivationPath, BitcoinExtendedPrivateKey,  English as BitcoinEnglish, Testnet as BitcoinTestnet};
use ethereum::{English as EthereumEnglish, EthereumAddress, EthereumMnemonic, EthereumDerivationPath, EthereumExtendedPrivateKey, EthereumPrivateKey};
use monero::address::Format as MoneroFormat;
use monero::{English as MoneroEnglish, Mainnet as MoneroMainnet, MoneroAddress, MoneroMnemonic, MoneroNetwork, MoneroPrivateKey, Testnet as MoneroTestnet};
use wagyu_model::{Address, Mnemonic, MnemonicExtended, ExtendedPrivateKey, PrivateKey};
use zcash::address::Format as ZcashFormat;
use zcash::{Mainnet as ZcashMainnet, Testnet as ZcashTestnet, SpendingKey, ZcashAddress, ZcashNetwork, ZcashExtendedPrivateKey, ZcashDerivationPath, ZcashPrivateKey};

use clap::{App, Arg, ArgMatches, SubCommand, AppSettings};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display};
use std::marker::PhantomData;
use std::str::FromStr;
use rand::Rng;

/// Represents custom options for a Bitcoin wallet
#[derive(Serialize, Clone, Debug)]
pub struct BitcoinOptions {
    pub private_key: Option<String>,
    pub mnemonic_values: Option<MnemonicValues>,
    pub extended_private_key_values: Option<ExtendedPrivateKeyValues>,
    pub count: usize,
    pub network: String,
    pub format: BitcoinFormat,
    pub json: bool,
}

/// Represents custom options for an Ethereum wallet
#[derive(Serialize, Clone, Debug)]
pub struct EthereumOptions {
    pub private_key: Option<String>,
    pub mnemonic_values: Option<MnemonicValues>,
    pub extended_private_key_values: Option<ExtendedPrivateKeyValues>,
    pub count: usize,
    pub json: bool,
}

/// Represents custom options for a Monero wallet
#[derive(Serialize, Clone, Debug)]
pub struct MoneroOptions {
    pub private_key: Option<String>,
    pub mnemonic_values: Option<MnemonicValues>,
    pub count: usize,
    pub network: String,
    pub format: MoneroFormat,
    pub json: bool,
}

/// Represents custom options for a Zcash wallet
#[derive(Serialize, Clone, Debug)]
pub struct ZcashOptions {
    pub private_key: Option<String>,
    pub extended_private_key_values: Option<ExtendedPrivateKeyValues>,
    pub count: usize,
    pub network: String,
    pub format: ZcashFormat,
    pub json: bool,
}

/// Represents values to derive extended private keys
#[derive(Serialize, Clone, Debug)]
pub struct ExtendedPrivateKeyValues {
    pub key: Option<String>,
    pub path: Option<String>,
}

/// Represents values to derive mnemonics
#[derive(Serialize, Clone, Debug)]
pub struct MnemonicValues {
    pub word_count: Option<u8>,
    pub mnemonic: String,
    pub password: String,
    pub path: Option<String>,
}

/// Represents a generic wallet to output
#[derive(Serialize, Debug, Default)]
pub struct GenericWallet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_private_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_keys: Option<String>,

    pub address: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub diversifier: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed: Option<bool>,
}

#[cfg_attr(tarpaulin, skip)]
impl Display for GenericWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mnemonic = match &self.mnemonic {
            Some(mnemonic) => {
                format!("      Mnemonic:             {}\n", mnemonic)
            },
            _ => "".to_owned() };

        let extended_private_key = match &self.extended_private_key {
            Some(extended_private_key) => {
                format!("      Extended private key: {}\n", extended_private_key)
            },
            _ => "".to_owned() };

        let private_key = match &self.private_key {
            Some(private_key) => {
                format!("      Private key:          {}\n", private_key)
            },
            _ => "".to_owned() };

        let private_keys = match &self.private_keys {
            Some(private_keys) => {
                format!("      Private spend/view:   {}\n", private_keys)
            },
            _ => "".to_owned() };

        let address = format!("      Address:              {}\n", self.address);

        let diversifier = match &self.diversifier {
            Some(diversifier) => {
                format!("      Diversifier:          {}\n", diversifier)
            },
            _ => "".to_owned() };

        let format = match &self.format {
            Some(format) => {
                format!("      Format:               {}\n", format)
            },
            _ => "".to_owned() };

        let network = match &self.network {
            Some(network) => {
                format!("      Network:              {}\n", network)
            },
            _ => "".to_owned() };

        let compressed = match &self.compressed {
            Some(compressed) => {
                format!("      Compressed:           {}\n", compressed)
            },
            _ => "".to_owned() };

        let output = [mnemonic, extended_private_key, private_key, private_keys, address, diversifier, format, network, compressed].concat();
        let output = output[..output.len()-1].to_owned();

        write!(f, "\n{}", output)
    }
}

/// Wagyu CLI Interface
#[cfg_attr(tarpaulin, skip)]
fn main() {
    // Generic wallet arguments
    let arg_count = Arg::from_usage("[count] -n --count=[count] 'Number of wallets to generate'");
    let arg_json = Arg::from_usage("[json] -j --json 'Print the generated wallet(s) in JSON format'");
    let arg_network = Arg::from_usage("[network] -N --network=[network] 'Network of wallet(s) to generate'")
        .possible_values(&["mainnet", "testnet"]);

    // Wallet import arguments
    let arg_path = Arg::from_usage("[path] --path=[path] 'Specify a derivation path'");
    let arg_import = Arg::from_usage("[import] --import")
        .conflicts_with("word_count");
    let arg_password = Arg::from_usage("[password] --password=[password] 'Specify a password used for extended private key derivation'");
    let arg_word_count = Arg::from_usage("[word count] --word_count=[word count] 'Generate a wallet with a new mnemonic with the specified word count'")
        .conflicts_with("import");

    // Bitcoin specific arguments
    let arg_bech32 = Arg::from_usage("[bech32] --bech32 'Generate a wallet with a Bech32 (SegWit enabled) address'")
        .conflicts_with("segwit");
    let arg_segwit = Arg::from_usage("[segwit] --segwit 'Generate a wallet with a Segwit address'")
        .conflicts_with("bech32");

    // Monero specific arguments
    let arg_integrated = Arg::from_usage("[integrated] --integrated=[PaymentID] 'Generate a wallet with an integrated address - Requires a paymentID'")
        .conflicts_with("subaddress");
    let arg_subaddress = Arg::from_usage("[subaddress] --subaddress=[Major Index][MinorIndex] 'Generate a wallet with a subaddress - Requires a major (account) and minor index'")
        .conflicts_with("integrated");

    // Zcash specific arguments
    let arg_shielded =  Arg::from_usage("[shielded] --shielded 'Generate a wallet with a shielded address'");

    // Subcommands
    let mnemonic_subcommand = SubCommand::with_name("mnemonic")
        .about("Generate a wallet using mnemonics (run with -h for additional options)")
        .arg(&arg_import.to_owned().number_of_values(1).value_name("mnemonic")
            .help("Generate a wallet by importing a mnemonic (in quotes)"))
        .arg(&arg_path)
        .arg(&arg_password)
        .after_help("");

    let monero_mnemonic_subcommand = SubCommand::with_name("mnemonic")
        .about("Generate a wallet using mnemonics (run with -h for additional options)")
        .arg(&arg_import.to_owned().number_of_values(1).value_name("mnemonic")
            .help("Generate a wallet by importing a mnemonic (in quotes)"))
        .after_help("");

    let private_key_subcommand = SubCommand::with_name("private_key")
        .about("Generate a wallet by importing a private key (run with -h for additional options)")
        .arg(&arg_import.to_owned().number_of_values(1).value_name("private key")
            .help("Generate a wallet by importing a private key (run with -h for additional options)"))
        .after_help("");

    let extended_private_key_subcommand = SubCommand::with_name("extended_private_key")
        .about("Generate a wallet from an extended key (run with -h for additional options)")
        .arg(&arg_import.to_owned().number_of_values(1).value_name("extended private key")
            .help("Generate a wallet by importing an extended private key"))
        .arg(&arg_path)
        .after_help("");

    // Construct Wagyu CLI
    let wagyu_matches = App::new("wagyu")
        .version("v0.6.0")
        .about("Generate a wallet for Bitcoin, Ethereum, Monero, and Zcash")
        .author("Argus <team@argus.dev>")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("bitcoin")
            .about("Generate a Bitcoin wallet (run with -h for additional options)")
            .arg(&arg_bech32)
            .arg(&arg_count)
            .arg(&arg_json)
            .arg(&arg_network)
            .arg(&arg_segwit)
            .subcommand(extended_private_key_subcommand.to_owned())
            .subcommand(mnemonic_subcommand
                .to_owned()
                .arg(&arg_word_count))
            .subcommand(private_key_subcommand.to_owned())
            .after_help("")
        )
        .subcommand(SubCommand::with_name("ethereum")
            .about("Generate an Ethereum wallet (run with -h for additional options)")
            .arg(&arg_count)
            .arg(&arg_json)
            .subcommand(extended_private_key_subcommand.to_owned())
            .subcommand(mnemonic_subcommand
                .to_owned()
                .arg(&arg_word_count))
            .subcommand(private_key_subcommand.to_owned())
            .after_help("")
        )
        .subcommand(SubCommand::with_name("monero")
            .about("Generate a Monero wallet (run with -h for additional options)")
            .arg(&arg_count)
            .arg(&arg_json)
            .arg(&arg_network)
            .arg(&arg_integrated)
            .arg(&arg_subaddress)
            .subcommand(monero_mnemonic_subcommand.to_owned())
            .subcommand(private_key_subcommand.to_owned())
            .after_help("")
        )
        .subcommand(SubCommand::with_name("zcash")
            .about("Generate a Zcash wallet (run with -h for additional options)")
            .arg(&arg_network)
            .arg(&arg_count)
            .arg(&arg_json)
            .arg(&arg_shielded)
            .subcommand(extended_private_key_subcommand.to_owned())
            .subcommand(private_key_subcommand.to_owned())
            .after_help("")
        )
        .after_help("")
        .get_matches();

    match wagyu_matches.subcommand() {
        ("bitcoin", Some(bitcoin_matches)) => { handle_bitcoin_cases(bitcoin_matches) },
        ("ethereum", Some(ethereum_matches)) => { handle_ethereum_cases(ethereum_matches) },
        ("monero", Some(monero_matches)) => { handle_monero_cases(monero_matches) },
        ("zcash", Some(zcash_matches)) => { handle_zcash_cases(zcash_matches) },
        _ => unreachable!(),
    };
}

/// Handle all CLI arguments and flags for Bitcoin
#[cfg_attr(tarpaulin, skip)]
fn handle_bitcoin_cases(bitcoin_matches: &ArgMatches) {
    let bitcoin_address_type = if bitcoin_matches.is_present("segwit") {
        BitcoinFormat::P2SH_P2WPKH
    } else if bitcoin_matches.is_present("bech32") {
        BitcoinFormat::Bech32
    } else { BitcoinFormat::P2PKH };

    let network = match bitcoin_matches.value_of("network") {
        Some("testnet") => "testnet",
        _ => "mainnet",
    };

    let mut bitcoin_options = BitcoinOptions {
        private_key: None,
        mnemonic_values: None,
        extended_private_key_values: None,
        count: clap::value_t!(bitcoin_matches.value_of("count"), usize).unwrap_or_else(|_e| 1),
        network: network.to_owned(),
        format: bitcoin_address_type,
        json: bitcoin_matches.is_present("json"),
    };

    match bitcoin_matches.subcommand() {
        ("private_key", Some(private_key_matches)) => {
            bitcoin_options.private_key = private_key_matches.value_of("import").map(|s| s.to_string());
        },
        ("mnemonic", Some(mnemonic_matches)) => {
            const DEFAULT_WORD_COUNT: u8 = 12;
            let password: String = mnemonic_matches.value_of("password").unwrap_or("").to_owned();
            let path = mnemonic_matches.value_of("path").map(|s| s.to_string());
            bitcoin_options.mnemonic_values = match (mnemonic_matches.value_of("import"), mnemonic_matches.value_of("word count")) {
                (Some(phrase), _) => Some(MnemonicValues { word_count: None, mnemonic: phrase.to_owned(), password, path }),
                (None, Some(word_count)) => Some(MnemonicValues { word_count: Some(word_count.parse().unwrap()), mnemonic: "".to_owned(), password, path }),
                (None, None) => Some(MnemonicValues { word_count: Some(DEFAULT_WORD_COUNT), mnemonic: "".to_owned(), password, path }),
            };
        },
        ("extended_private_key", Some(xpriv_matches)) => {
            let path = xpriv_matches.value_of("path").map(|s| s.to_string());
            let key = xpriv_matches.value_of("import").map(|s| s.to_string());
            bitcoin_options.extended_private_key_values = Some( ExtendedPrivateKeyValues { key, path });
        },
        _ => {},
    };

    match network {
        "testnet" => print_bitcoin_wallet::<BitcoinTestnet>(bitcoin_options),
        _ => print_bitcoin_wallet::<BitcoinMainnet>(bitcoin_options),
    };
}

/// Handle all CLI arguments and flags for Ethereum
#[cfg_attr(tarpaulin, skip)]
fn handle_ethereum_cases(ethereum_matches: &ArgMatches) {
    let mut ethereum_options = EthereumOptions {
        private_key: None,
        mnemonic_values: None,
        extended_private_key_values: None,
        count: clap::value_t!(ethereum_matches.value_of("count"), usize).unwrap_or_else(|_e| 1),
        json: ethereum_matches.is_present("json"),
    };

    match ethereum_matches.subcommand() {
        ("private_key", Some(private_key_matches)) => {
            ethereum_options.private_key = private_key_matches.value_of("import").map(|s| s.to_string());
        },
        ("mnemonic", Some(mnemonic_matches)) => {
            const DEFAULT_WORD_COUNT: u8 = 12;
            let password: String = mnemonic_matches.value_of("password").unwrap_or("").to_owned();
            let path = mnemonic_matches.value_of("path").map(|s| s.to_string());
            ethereum_options.mnemonic_values = match (mnemonic_matches.value_of("import"), mnemonic_matches.value_of("word count")) {
                (Some(phrase), _) => Some(MnemonicValues { word_count: None, mnemonic: phrase.to_owned(), password, path }),
                (None, Some(word_count)) => Some(MnemonicValues { word_count: Some(word_count.parse().unwrap()), mnemonic: "".to_owned(), password, path }),
                (None, None) => Some(MnemonicValues { word_count: Some(DEFAULT_WORD_COUNT), mnemonic: "".to_owned(), password, path }),
            };
        },
        ("extended_private_key", Some(xpriv_matches)) => {
            let path = xpriv_matches.value_of("path").map(|s| s.to_string());
            let key = xpriv_matches.value_of("import").map(|s| s.to_string());
            ethereum_options.extended_private_key_values = Some( ExtendedPrivateKeyValues { key, path });
        },
        _ => {},
    };

    print_ethereum_wallet(ethereum_options);
}

/// Handle all CLI arguments and flags for Monero
#[cfg_attr(tarpaulin, skip)]
fn handle_monero_cases(monero_matches: &ArgMatches) {
    let monero_address_type = match (monero_matches.values_of("subaddress"), monero_matches.value_of("integrated")) {
        (Some(indexes), None) => {
            let indexes: Vec<u32> = indexes.into_iter().map(|index| index.to_owned().parse().unwrap()).collect();
            MoneroFormat::Subaddress(indexes[0], indexes[1])
        },
        (None, Some(payment_id_string)) => {
            let mut payment_id = [0u8; 8];
            payment_id.copy_from_slice(&hex::decode(payment_id_string).unwrap());
            MoneroFormat::Integrated(payment_id)
        },
        (None, None) => MoneroFormat::Standard,
        _ => unreachable!(),
    };

    let network = match monero_matches.value_of("network") {
        Some("testnet") => "testnet",
        _ => "mainnet",
    };

    let mut monero_options = MoneroOptions {
        private_key: None,
        mnemonic_values: None,
        count: clap::value_t!(monero_matches.value_of("count"), usize).unwrap_or_else(|_e| 1),
        network: network.to_owned(),
        format: monero_address_type,
        json: monero_matches.is_present("json"),
    };

    match monero_matches.subcommand() {
        ("private_key", Some(private_key_matches)) => {
            monero_options.private_key = private_key_matches.value_of("import").map(|s| s.to_string());
        },
        ("mnemonic", Some(mnemonic_matches)) => {
            const DEFAULT_WORD_COUNT: u8 = 25;
            let password: String = mnemonic_matches.value_of("password").unwrap_or("").to_owned();
            let path = mnemonic_matches.value_of("path").map(|s| s.to_string());
            monero_options.mnemonic_values = match mnemonic_matches.value_of("import") {
                Some(phrase) => Some(MnemonicValues { word_count: None, mnemonic: phrase.to_owned(), password, path }),
                None => Some(MnemonicValues { word_count: Some(DEFAULT_WORD_COUNT), mnemonic: "".to_owned(), password, path }),
            };
        },
        _ => {},
    };

    match network {
        "testnet" => print_monero_wallet::<MoneroTestnet>(monero_options),
        _ => print_monero_wallet::<MoneroMainnet>(monero_options),
    };
}

/// Handle all CLI arguments and flags for Zcash
#[cfg_attr(tarpaulin, skip)]
fn handle_zcash_cases(zcash_matches: &ArgMatches) {
    let zcash_address_type = if zcash_matches.is_present("shielded") {
        ZcashFormat::Sapling(None)
    } else {
        ZcashFormat::P2PKH
    };

    let network = match zcash_matches.value_of("network") {
        Some("testnet") => "testnet",
        _ => "mainnet",
    };

    let mut zcash_options = ZcashOptions {
        private_key: None,
        extended_private_key_values: None,
        count: clap::value_t!(zcash_matches.value_of("count"), usize).unwrap_or_else(|_e| 1),
        network: network.to_owned(),
        format: zcash_address_type,
        json: zcash_matches.is_present("json"),
    };

    match zcash_matches.subcommand() {
        ("private_key", Some(private_key_matches)) => {
            zcash_options.private_key = private_key_matches.value_of("import").map(|s| s.to_string());
        },
        ("extended_private_key", Some(xpriv_matches)) => {
            let path = xpriv_matches.value_of("path").map(|s| s.to_string());
            let key = xpriv_matches.value_of("import").map(|s| s.to_string());
            zcash_options.extended_private_key_values = Some( ExtendedPrivateKeyValues { key, path });
        },
        _ => {},
    };

    match network {
        "testnet" => print_zcash_wallet::<ZcashTestnet>(zcash_options),
        _ => print_zcash_wallet::<ZcashMainnet>(zcash_options),
    };
}

/// Generate the Bitcoin wallet and print the relevant fields
#[cfg_attr(tarpaulin, skip)]
fn print_bitcoin_wallet<N: BitcoinNetwork>(bitcoin_options: BitcoinOptions) {
    for _ in 0..bitcoin_options.count {
        let wallet = match (bitcoin_options.mnemonic_values.to_owned(), bitcoin_options.extended_private_key_values.to_owned()) {
            (None, None) => {
                let private_key = match bitcoin_options.private_key.to_owned() {
                    None => BitcoinPrivateKey::<N>::new(&mut StdRng::from_entropy()).unwrap(),
                    Some(key) => BitcoinPrivateKey::<N>::from_str(&key).unwrap(),
                };

                let address = BitcoinAddress::from_private_key(&private_key, &bitcoin_options.format).unwrap();

                GenericWallet {
                    private_key: Some(private_key.to_string()),
                    address: address.to_string(),
                    network: Some(bitcoin_options.network.to_owned()),
                    format: Some(address.format().to_string()),
                    compressed: Some(private_key.is_compressed()),
                    ..Default::default()
                }
            },
            (Some(mnemonic_values), None) => {
                type W = BitcoinEnglish;
                let mnemonic = match mnemonic_values.word_count {
                    Some(word_count) => BitcoinMnemonic::<N, W>::new(word_count, &mut StdRng::from_entropy()).unwrap(),
                    None => BitcoinMnemonic::<N, W>::from_phrase(&mnemonic_values.mnemonic).unwrap(),
                };

                let master_xpriv_key = mnemonic.to_extended_private_key(Some(&mnemonic_values.password)).unwrap();
                let extended_private_key = match mnemonic_values.path {
                    Some(path) => { master_xpriv_key.derive(&BitcoinDerivationPath::from_str(&path).unwrap()).unwrap() },
                    None => master_xpriv_key,
                };

                let private_key = extended_private_key.to_private_key();
                let address = BitcoinAddress::from_private_key(&private_key, &bitcoin_options.format).unwrap();

                GenericWallet {
                    mnemonic: Some(mnemonic.to_string()),
                    extended_private_key: Some(extended_private_key.to_string()),
                    private_key: Some(private_key.to_string()),
                    address: address.to_string(),
                    network: Some(bitcoin_options.network.to_owned()),
                    format: Some(address.format().to_string()),
                    compressed: Some(private_key.is_compressed()),
                    ..Default::default()
                }
            },
            (None, Some(wallet_extended)) => {
                let extended_private_key = match (wallet_extended.key, wallet_extended.path)  {
                    (None, None) => {
                        let seed: [u8; 32] = StdRng::from_entropy().gen();
                        BitcoinExtendedPrivateKey::<N>::new_master(&seed, &bitcoin_options.format).unwrap()
                    },
                    (Some(key), None) => {
                        BitcoinExtendedPrivateKey::<N>::from_str(&key).unwrap()
                    },
                    (None, Some(path)) => {
                        let seed: [u8; 32] = StdRng::from_entropy().gen();
                        BitcoinExtendedPrivateKey::<N>::new(
                            &seed,
                            &bitcoin_options.format,
                            &BitcoinDerivationPath::from_str(&path).unwrap())
                            .unwrap()
                    },
                    (Some(key), Some(path)) => {
                        BitcoinExtendedPrivateKey::<N>::from_str(&key).unwrap()
                            .derive(&BitcoinDerivationPath::from_str(&path).unwrap()).unwrap()
                    },
                };

                let private_key = extended_private_key.to_private_key();
                let address = BitcoinAddress::from_private_key(&private_key, &bitcoin_options.format).unwrap();

                GenericWallet {
                    extended_private_key: Some(extended_private_key.to_string()),
                    private_key: Some(private_key.to_string()),
                    address: address.to_string(),
                    network: Some(bitcoin_options.network.to_owned()),
                    format: Some(address.format().to_string()),
                    compressed: Some(private_key.is_compressed()),
                    ..Default::default()
                }
            },
            _ => unreachable!()
        };

        if bitcoin_options.json {
            println!("{}\n", serde_json::to_string_pretty(&wallet).unwrap());
        } else {
            println!("{}\n", wallet);
        }
    }
}

/// Generate the Ethereum wallet and print the relevant fields
#[cfg_attr(tarpaulin, skip)]
fn print_ethereum_wallet(ethereum_options: EthereumOptions) {
    for _ in 0..ethereum_options.count {
        let wallet = match (ethereum_options.mnemonic_values.to_owned(), ethereum_options.extended_private_key_values.to_owned()) {
            (None, None) => {
                let private_key = match ethereum_options.private_key.to_owned() {
                    None => EthereumPrivateKey::new(&mut StdRng::from_entropy()).unwrap(),
                    Some(key) => EthereumPrivateKey::from_str(&key).unwrap(),
                };

                let address = EthereumAddress::from_private_key(&private_key, &PhantomData).unwrap();

                GenericWallet {
                    private_key: Some(private_key.to_string()),
                    address: address.to_string(),
                    ..Default::default()
                }
            },
            (Some(mnemonic_values), None) => {
                type W = EthereumEnglish;
                let mnemonic = match mnemonic_values.word_count {
                    Some(word_count) => EthereumMnemonic::<W>::new(word_count, &mut StdRng::from_entropy()).unwrap(),
                    None => EthereumMnemonic::<W>::from_phrase(&mnemonic_values.mnemonic).unwrap(),
                };

                let master_xpriv_key = mnemonic.to_extended_private_key(Some(&mnemonic_values.password)).unwrap();
                let extended_private_key = match mnemonic_values.path {
                    Some(path) => master_xpriv_key.derive(&EthereumDerivationPath::from_str(&path).unwrap()).unwrap(),
                    None => master_xpriv_key,
                };

                let private_key = extended_private_key.to_private_key();
                let address = EthereumAddress::from_private_key(&private_key, &PhantomData).unwrap();

                GenericWallet {
                    mnemonic: Some(mnemonic.to_string()),
                    extended_private_key: Some(extended_private_key.to_string()),
                    private_key: Some(private_key.to_string()),
                    address: address.to_string(),
                    ..Default::default()
                }
            },
            (None, Some(wallet_extended)) => {
                let extended_private_key = match (wallet_extended.key, wallet_extended.path)  {
                    (None, None) => {
                        let seed: [u8; 32] = StdRng::from_entropy().gen();
                        EthereumExtendedPrivateKey::new_master(&seed, &PhantomData).unwrap()
                    },
                    (Some(key), None) => {
                        EthereumExtendedPrivateKey::from_str(&key).unwrap()
                    },
                    (None, Some(path)) => {
                        let seed: [u8; 32] = StdRng::from_entropy().gen();
                        EthereumExtendedPrivateKey::new(
                            &seed,
                            &PhantomData,
                            &EthereumDerivationPath::from_str(&path).unwrap())
                            .unwrap()
                    },
                    (Some(key), Some(path)) => {
                        EthereumExtendedPrivateKey::from_str(&key).unwrap()
                            .derive(&EthereumDerivationPath::from_str(&path).unwrap()).unwrap()
                    },
                };

                let private_key = extended_private_key.to_private_key();
                let address = EthereumAddress::from_private_key(&private_key, &PhantomData).unwrap();

                GenericWallet {
                    extended_private_key: Some(extended_private_key.to_string()),
                    private_key: Some(private_key.to_string()),
                    address: address.to_string(),
                    ..Default::default()
                }
            },
            _ => unreachable!(),
        };

        if ethereum_options.json {
            println!("{}\n", serde_json::to_string_pretty(&wallet).unwrap());
        } else {
            println!("{}\n", wallet);
        }
    }
}

/// Generate the Monero wallet and print the relevant fields
#[cfg_attr(tarpaulin, skip)]
fn print_monero_wallet<N: MoneroNetwork>(monero_options: MoneroOptions) {
    for _ in 0..monero_options.count {
        let wallet = match monero_options.mnemonic_values.to_owned() {
            None => {
                let private_key = match monero_options.private_key.to_owned() {
                    None => MoneroPrivateKey::<N>::new(&mut StdRng::from_entropy()).unwrap(),
                    Some(key) => MoneroPrivateKey::<N>::from_str(&key).unwrap(),
                };

                let address = MoneroAddress::from_private_key(&private_key, &monero_options.format).unwrap();

                GenericWallet {
                    private_keys: Some(private_key.to_string()),
                    address: address.to_string(),
                    network: Some(monero_options.network.to_owned()),
                    format: Some(monero_options.format.to_string()),
                    ..Default::default()
                }
            },
            Some(mnemonic_values) => {
                type W = MoneroEnglish;
                let mnemonic = match mnemonic_values.word_count {
                    Some(_) => MoneroMnemonic::<N, W>::new(&mut StdRng::from_entropy()).unwrap(),
                    None => MoneroMnemonic::<N, W>::from_phrase(&mnemonic_values.mnemonic).unwrap(),
                };

                let private_key = mnemonic.to_private_key(None).unwrap();
                let address = MoneroAddress::from_private_key(&private_key, &monero_options.format).unwrap();

                GenericWallet {
                    mnemonic:  Some(mnemonic.to_string()),
                    private_keys: Some(private_key.to_string()),
                    address: address.to_string(),
                    network: Some(monero_options.network.to_owned()),
                    format: Some(monero_options.format.to_string()),
                    ..Default::default()
                }
            }
        };

        if monero_options.json {
            println!("{}\n", serde_json::to_string_pretty(&wallet).unwrap())
        } else {
            println!("{}\n", wallet);
        };
    }
}

/// Generate the Zcash wallet and print the relevant fields
#[cfg_attr(tarpaulin, skip)]
fn print_zcash_wallet<N: ZcashNetwork>(zcash_options: ZcashOptions) {
    for _ in 0..zcash_options.count {
        let wallet = match zcash_options.extended_private_key_values.to_owned() {
            None => {
                let private_key = match zcash_options.private_key.to_owned() {
                    None => {
                        let rng = &mut StdRng::from_entropy();
                        match zcash_options.format {
                            ZcashFormat::P2PKH => ZcashPrivateKey::<N>::new_p2pkh(rng).unwrap(),
                            _ => ZcashPrivateKey::<N>::new_sapling(rng).unwrap(),
                        }
                    },
                    Some(key) => ZcashPrivateKey::<N>::from_str(&key).unwrap(),
                };

                let address = ZcashAddress::<N>::from_private_key(&private_key, &zcash_options.format).unwrap();
                let address_format = address.format().to_string();
                let address_format: Vec<String> = address_format.split(" ").map(|s| s.to_owned()).collect();
                let diversifier: Option<String> = match ZcashAddress::<N>::get_diversifier(&address.to_string()) {
                    Ok(diversifier) => Some(hex::encode(diversifier)),
                    _ => None,
                };

                match private_key.to_spending_key() {
                    SpendingKey::P2PKH(p2pkh_spending_key)=> {
                        GenericWallet {
                            private_key: Some(private_key.to_string()),
                            address: address.to_string(),
                            diversifier,
                            format: Some(address_format[0].to_owned()),
                            network: Some(zcash_options.network.to_owned()),
                            compressed: Some(p2pkh_spending_key.is_compressed()),
                            ..Default::default()
                        }
                    }
                    _ => {
                        GenericWallet {
                            private_key: Some(private_key.to_string()),
                            address: address.to_string(),
                            diversifier,
                            format: Some(address_format[0].to_owned()),
                            network: Some(zcash_options.network.to_owned()),
                            ..Default::default()
                        }
                    }
                }
            },
            Some(wallet_extended) => {
                let extended_private_key = match (wallet_extended.key, wallet_extended.path)  {
                    (None, None) => {
                        let seed: [u8; 32] = StdRng::from_entropy().gen();
                        ZcashExtendedPrivateKey::<N>::new_master(&seed, &zcash_options.format).unwrap()
                    },
                    (Some(key), None) => ZcashExtendedPrivateKey::<N>::from_str(&key).unwrap(),
                    (None, Some(path)) => {
                        let seed: [u8; 32] = StdRng::from_entropy().gen();
                        ZcashExtendedPrivateKey::<N>::new(
                            &seed,
                            &zcash_options.format,
                            &ZcashDerivationPath::from_str(&path).unwrap())
                            .unwrap()
                    },
                    (Some(key), Some(path)) => {
                        ZcashExtendedPrivateKey::<N>::from_str(&key).unwrap()
                            .derive(&ZcashDerivationPath::from_str(&path).unwrap()).unwrap()
                    },
                };

                let private_key = extended_private_key.to_private_key();
                let address = ZcashAddress::<N>::from_private_key(&private_key, &zcash_options.format).unwrap();
                let address_format: Vec<String> = address.format().to_string().split(" ").map(|s| s.to_owned()).collect();
                let diversifier: Option<String> = match ZcashAddress::<N>::get_diversifier(&address.to_string()) {
                    Ok(diversifier) => Some(hex::encode(diversifier)),
                    _ => None,
                };
                match private_key.to_spending_key() {
                    SpendingKey::P2PKH(p2pkh_spending_key)=> {
                        GenericWallet {
                            extended_private_key: Some(extended_private_key.to_string()),
                            private_key: Some(private_key.to_string()),
                            address: address.to_string(),
                            diversifier,
                            format: Some(address_format[0].to_owned()),
                            network: Some(zcash_options.network.to_owned()),
                            compressed: Some(p2pkh_spending_key.is_compressed()),
                            ..Default::default()
                        }
                    }
                    _ => {
                        GenericWallet {
                            private_key: Some(private_key.to_string()),
                            address: address.to_string(),
                            diversifier,
                            format: Some(address_format[0].to_owned()),
                            network: Some(zcash_options.network.to_owned()),
                            ..Default::default()
                        }
                    }
                }
            },
        };

        if zcash_options.json {
            println!("{}\n", serde_json::to_string_pretty(&wallet).unwrap())
        } else {
            println!("{}\n", wallet);
        };
    }
}
