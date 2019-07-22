use crate::address::{MoneroAddress, Format};
use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;
use crate::wordlist::MoneroWordlist;
use wagu_model::{Mnemonic, MnemonicError, PrivateKey};

use crc::{crc32, Hasher32};
use rand::Rng;
use rand::rngs::OsRng;
use std::fmt;
use std::marker::PhantomData;
use std::str;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Represents a Monero mnemonic
pub struct MoneroMnemonic<N: MoneroNetwork, W: MoneroWordlist> {
    /// Initial 256-bit seed
    pub seed: [u8; 32],
    /// The mnemonic phrase
    pub phrase: String,
    /// PhantomData
    _network: PhantomData<N>,
    /// PhantomData
    _wordlist: PhantomData<W>,
}

impl <N: MoneroNetwork, W: MoneroWordlist> Mnemonic for MoneroMnemonic<N, W> {
    type Address = MoneroAddress<N>;
    type Format = Format;
    type PrivateKey = MoneroPrivateKey<N>;
    type PublicKey = MoneroPublicKey<N>;

    /// Returns the private key of the corresponding mnemonic.
    fn to_private_key(&self, _: Option<&str>) -> Result<Self::PrivateKey, MnemonicError> {
        Ok(MoneroPrivateKey::from_seed(hex::encode(&self.seed).as_str())?)
    }

    /// Returns the public key of the corresponding mnemonic.
    fn to_public_key(&self, _: Option<&str>) -> Result<Self::PublicKey, MnemonicError> {
        Ok(self.to_private_key(None)?.to_public_key())
    }

    /// Returns the address of the corresponding mnemonic.
    fn to_address(
        &self,
        _: Option<&str>,
        format: &Self::Format
    ) -> Result<Self::Address, MnemonicError> {
        Ok(self.to_private_key(None)?.to_address(format)?)
    }
}

impl <N: MoneroNetwork, W: MoneroWordlist> MoneroMnemonic<N, W> {
    /// Returns a new mnemonic phrase given the word count.
    fn new() -> Result<Self, MnemonicError> {
        let mut seed = [0u8; 32];
        OsRng.try_fill(&mut seed)?;
        Ok(Self::from_seed(&seed)?)
    }

//    /// Returns the mnemonic for the given phrase.
//    pub fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
//        Ok(Self {
//            seed: Self::to_seed(phrase)?,
//            phrase: phrase.to_owned(),
//            _network: PhantomData,
//            _wordlist: PhantomData
//        })
//    }

//    /// Compares the given phrase against the phrase extracted from its entropy.
//    pub fn verify_phrase(phrase: &str) -> bool {
//        Self::to_seed(phrase).is_ok()
//    }

    /// Returns the mnemonic for the given seed.
    fn from_seed(seed: &[u8; 32]) -> Result<Self, MnemonicError> {
        // Reverse the endian in 4 byte intervals
        let length = 1626;
        let mut inputs = seed.chunks(4).map(|chunk| {
            let mut input: [u8; 4] = [0u8; 4];
            input.copy_from_slice(chunk);

            u32::from_le_bytes(input)
        }).collect::<Vec<u32>>();

        // Generate three words from every 4 byte interval
        let mut phrase = vec![];
        for index in inputs {
            let w1 = index % length;
            let w2 = ((index / length) + w1) % length;
            let w3 = (((index / length) / length) + w2) % length;

            phrase.push(W::get(w1 as usize)?);
            phrase.push(W::get(w2 as usize)?);
            phrase.push(W::get(w3 as usize)?);
        }

        // Compute the checksum word
        let trimmed_phrase = phrase.iter().map(|word| {
            word[0..W::PREFIX_LENGTH as usize].to_string()
        }).collect::<Vec<String>>();

        let mut digest = crc32::Digest::new(crc32::IEEE);
        digest.write(trimmed_phrase.concat().as_bytes());
        phrase.push(phrase[(digest.sum32() % phrase.len() as u32) as usize].clone());

        Ok(Self {
            seed: *seed,
            phrase: phrase.join(" "),
            _network: PhantomData,
            _wordlist: PhantomData
        })
    }
}

impl <N: MoneroNetwork, W: MoneroWordlist> FromStr for MoneroMnemonic<N, W> {
    type Err = MnemonicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_phrase(s)
    }
}

impl <N: MoneroNetwork, W: MoneroWordlist> fmt::Display for MoneroMnemonic<N, W> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.phrase)
    }
}

