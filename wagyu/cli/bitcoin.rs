use crate::bitcoin::{
    address::Format as BitcoinFormat, BitcoinAddress, BitcoinDerivationPath, BitcoinMnemonic, BitcoinNetwork,
    BitcoinPrivateKey, English as BitcoinEnglish, Mainnet as BitcoinMainnet, Testnet as BitcoinTestnet,
};
use crate::cli::{flag, option, subcommand, types::*, CLI};
use crate::model::{Address, ExtendedPrivateKey, MnemonicExtended, PrivateKey};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::{fmt, fmt::Display, str::FromStr};

/// Represents custom options for a Bitcoin wallet
#[derive(Serialize, Clone, Debug)]
pub struct BitcoinOptions {
    pub private_key: Option<String>,
    pub hd_values: Option<HdValues>,
    pub count: usize,
    pub network: String,
    pub format: BitcoinFormat,
    pub json: bool,
}

/// Represents values to derive HD wallets
#[derive(Serialize, Clone, Debug)]
pub struct HdValues {
    pub mnemonic: Option<String>,
    pub password: Option<String>,
    pub path: Option<String>,
    pub word_count: Option<u8>,
}

/// Represents a generic wallet to output
#[derive(Serialize, Debug, Default)]
struct GenericWallet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

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
        let output = [
            match &self.path {
                Some(path) => format!("      Path:                 {}\n", path),
                _ => "".to_owned(),
            },
            match &self.mnemonic {
                Some(mnemonic) => format!("      Mnemonic:             {}\n", mnemonic),
                _ => "".to_owned(),
            },
            match &self.extended_private_key {
                Some(extended_private_key) => format!("      Extended private key: {}\n", extended_private_key),
                _ => "".to_owned(),
            },
            match &self.private_key {
                Some(private_key) => format!("      Private key:          {}\n", private_key),
                _ => "".to_owned(),
            },
            match &self.private_keys {
                Some(private_keys) => format!("      Private spend/view:   {}\n", private_keys),
                _ => "".to_owned(),
            },
            format!("      Address:              {}\n", self.address),
            match &self.diversifier {
                Some(diversifier) => format!("      Diversifier:          {}\n", diversifier),
                _ => "".to_owned(),
            },
            match &self.format {
                Some(format) => format!("      Format:               {}\n", format),
                _ => "".to_owned(),
            },
            match &self.network {
                Some(network) => format!("      Network:              {}\n", network),
                _ => "".to_owned(),
            },
            match &self.compressed {
                Some(compressed) => format!("      Compressed:           {}\n", compressed),
                _ => "".to_owned(),
            },
        ]
        .concat();

        // Removes final new line character
        let output = output[..output.len() - 1].to_owned();
        write!(f, "\n{}", output)
    }
}

pub struct BitcoinCLI {

}

impl CLI for BitcoinCLI {
    type Options = BitcoinOptions;

    const NAME: NameType = "bitcoin";
    const ABOUT: AboutType = "Generates a Bitcoin wallet (include -h for more options)";
    const FLAGS: &'static [FlagType] = &[flag::JSON];
    const OPTIONS: &'static [OptionType] = &[option::COUNT, option::FORMAT, option::BITCOIN_NETWORK];
    const SUBCOMMANDS: &'static [SubCommandType] = &[subcommand::HD, subcommand::IMPORT, subcommand::IMPORT_HD];

    /// Handle all CLI arguments and flags for Bitcoin
    #[cfg_attr(tarpaulin, skip)]
    fn parse(arguments: &ArgMatches) -> Self::Options {
        let bitcoin_address_type = if arguments.is_present("segwit") {
            BitcoinFormat::P2SH_P2WPKH
        } else if arguments.is_present("bech32") {
            BitcoinFormat::Bech32
        } else {
            BitcoinFormat::P2PKH
        };

        let network = match arguments.value_of("network") {
            Some("testnet") => "testnet",
            _ => "mainnet",
        };

        let mut options = BitcoinOptions {
            private_key: arguments.value_of("import").map(|s| s.to_string()),
            hd_values: None,
            count: clap::value_t!(arguments.value_of("count"), usize).unwrap_or_else(|_e| 1),
            network: network.to_owned(),
            format: bitcoin_address_type,
            json: arguments.is_present("json"),
        };

        match arguments.subcommand() {
            ("hd", Some(hd_matches)) => {
                if options.private_key.is_some() {
                    panic!("The argument \'--import\' cannot be used with \'hd\'")
                }

                //            const DEFAULT_WORD_COUNT: u8 = 12;
                let mnemonic = hd_matches.value_of("import").map(|s| s.to_string());
                let password = hd_matches.value_of("password").map(|s| s.to_string());
                let path = hd_matches.value_of("derivation").map(|s| s.to_string());
                let word_count = hd_matches.value_of("word count").map(|s| s.parse().unwrap());

                options.hd_values = Some(HdValues {
                    word_count,
                    mnemonic,
                    password,
                    path,
                });
            }
            _ => {}
        };

        options
    }

    /// Generate the Bitcoin wallet and print the relevant fields
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) {
        match options.network.as_str() {
            "testnet" => output::<BitcoinTestnet>(options),
            _ => output::<BitcoinMainnet>(options),
        };

        fn output<N: BitcoinNetwork>(options: BitcoinOptions) {
            for _ in 0..options.count {
                let wallet = match options.hd_values.to_owned() {
                    None => {
                        let private_key = match options.private_key.to_owned() {
                            None => BitcoinPrivateKey::<N>::new(&mut StdRng::from_entropy()).unwrap(),
                            Some(key) => BitcoinPrivateKey::<N>::from_str(&key).unwrap(),
                        };

                        let address = BitcoinAddress::from_private_key(&private_key, &options.format).unwrap();

                        GenericWallet {
                            private_key: Some(private_key.to_string()),
                            address: address.to_string(),
                            network: Some(options.network.to_owned()),
                            format: Some(address.format().to_string()),
                            compressed: Some(private_key.is_compressed()),
                            ..Default::default()
                        }
                    }
                    Some(mut hd_values) => {
                        type W = BitcoinEnglish;

                        let mnemonic = match hd_values.word_count {
                            Some(word_count) => {
                                BitcoinMnemonic::<N, W>::new(word_count, &mut StdRng::from_entropy()).unwrap()
                            }
                            None => BitcoinMnemonic::<N, W>::from_phrase(&hd_values.mnemonic.unwrap()).unwrap(),
                        };

                        let master_xpriv_key = mnemonic
                            .to_extended_private_key(Some(&hd_values.password.unwrap()))
                            .unwrap();
                        let extended_private_key = match hd_values.path.clone() {
                            Some(path) => master_xpriv_key
                                .derive(&BitcoinDerivationPath::from_str(&path).unwrap())
                                .unwrap(),
                            None => {
                                let path = "m/0'/0'/0";
                                hd_values.path = Some(path.into());
                                master_xpriv_key
                                    .derive(&BitcoinDerivationPath::from_str(path).unwrap())
                                    .unwrap()
                            }
                        };

                        let private_key = extended_private_key.to_private_key();
                        let address = BitcoinAddress::from_private_key(&private_key, &options.format).unwrap();

                        GenericWallet {
                            path: hd_values.path,
                            mnemonic: Some(mnemonic.to_string()),
                            extended_private_key: Some(extended_private_key.to_string()),
                            private_key: Some(private_key.to_string()),
                            address: address.to_string(),
                            network: Some(options.network.to_owned()),
                            format: Some(address.format().to_string()),
                            compressed: Some(private_key.is_compressed()),
                            ..Default::default()
                        }
                    }
                };

                if options.json {
                    println!("{}\n", serde_json::to_string_pretty(&wallet).unwrap());
                } else {
                    println!("{}\n", wallet);
                }
            }
        }
    }
}
