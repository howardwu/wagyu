use crate::address::ZcashAddress;
use crate::amount::ZcashAmount;
use crate::extended_private_key::ZcashExtendedPrivateKey;
use crate::format::ZcashFormat;
use crate::librustzcash::zip32::prf_expand;
use crate::network::ZcashNetwork;
use crate::private_key::{SaplingOutgoingViewingKey, ZcashPrivateKey};
use crate::public_key::ZcashPublicKey;
use wagyu_model::{ExtendedPrivateKey, PrivateKey, Transaction, TransactionError, TransactionId};

use base58::FromBase58;
use blake2b_simd::{Hash, Params, State};
use rand::{rngs::StdRng, Rng};
use rand_core::SeedableRng;
use secp256k1;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fmt, io::{self, BufReader, Read}, str::FromStr};

// librustzcash crates
use bellman::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey, Proof};
use ff::{Field, PrimeField, PrimeFieldRepr};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use zcash_primitives::{
    jubjub::{edwards, fs::Fs},
    keys::{ExpandedSpendingKey, FullViewingKey, OutgoingViewingKey},
    merkle_tree::MerklePath,
    note_encryption::{try_sapling_note_decryption, Memo, SaplingNoteEncryption},
    primitives::{Diversifier, Note, PaymentAddress},
    redjubjub::{PrivateKey as jubjubPrivateKey, PublicKey as jubjubPublicKey, Signature as jubjubSignature},
    sapling::{spend_sig, Node},
    transaction::components::Amount,
    JUBJUB,
};
use zcash_proofs::sapling::{SaplingProvingContext, SaplingVerificationContext};

const GROTH_PROOF_SIZE: usize = 48 + 96 + 48; // π_A + π_B + π_C

/// Returns the variable length integer of the given value.
/// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
pub fn variable_length_integer(value: u64) -> Result<Vec<u8>, TransactionError> {
    match value {
        // bounded by u8::max_value()
        0..=252 => Ok(vec![value as u8]),
        // bounded by u16::max_value()
        253..=65535 => Ok([vec![0xfd], (value as u16).to_le_bytes().to_vec()].concat()),
        // bounded by u32::max_value()
        65536..=4294967295 => Ok([vec![0xfe], (value as u32).to_le_bytes().to_vec()].concat()),
        // bounded by u64::max_value()
        _ => Ok([vec![0xff], value.to_le_bytes().to_vec()].concat()),
    }
}

/// Decode the value of a variable length integer.
/// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
pub fn read_variable_length_integer<R: Read>(mut reader: R) -> Result<usize, TransactionError> {
    let mut flag = [0u8; 1];
    reader.read(&mut flag)?;

    match flag[0] {
        0..=252 => Ok(flag[0] as usize),
        0xfd => {
            let mut size = [0u8; 2];
            reader.read(&mut size)?;
            match u16::from_le_bytes(size) {
                s if s < 253 => return Err(TransactionError::InvalidVariableSizeInteger(s as usize)),
                s => Ok(s as usize),
            }
        }
        0xfe => {
            let mut size = [0u8; 4];
            reader.read(&mut size)?;
            match u32::from_le_bytes(size) {
                s if s < 65536 => return Err(TransactionError::InvalidVariableSizeInteger(s as usize)),
                s => Ok(s as usize),
            }
        }
        _ => {
            let mut size = [0u8; 8];
            reader.read(&mut size)?;
            match u64::from_le_bytes(size) {
                s if s < 4294967296 => return Err(TransactionError::InvalidVariableSizeInteger(s as usize)),
                s => Ok(s as usize),
            }
        }
    }
}

/// Abstraction over a reader which hashes the data being read.
pub struct HashReader<R: Read> {
    reader: R,
    hasher: State,
}

impl<R: Read> HashReader<R> {
    /// Construct a new `HashReader` given an existing `reader` by value.
    pub fn new(reader: R) -> Self {
        HashReader {
            reader,
            hasher: State::new(),
        }
    }

    /// Destroy this reader and return the hash of what was read.
    pub fn into_hash(self) -> String {
        let hash = self.hasher.finalize();

        let mut s = String::new();
        for c in hash.as_bytes().iter() {
            s += &format!("{:02x}", c);
        }

        s
    }
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.reader.read(buf)?;

        if bytes > 0 {
            self.hasher.update(&buf[0..bytes]);
        }

        Ok(bytes)
    }
}

/// Initialize the sapling parameters and verifying keys
pub fn load_sapling_parameters() -> (
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
) {
    // Loads Zcash Sapling parameters as buffers
    let (spend, output) = wagyu_zcash_parameters::load_sapling_parameters();

    let mut spend_fs = HashReader::new(BufReader::with_capacity(1024 * 1024, &spend[..]));
    let mut output_fs =
        HashReader::new(BufReader::with_capacity(1024 * 1024, &output[..]));

    // Deserialize params
    let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
        .expect("couldn't deserialize Sapling spend parameters file");
    let output_params = Parameters::<Bls12>::read(&mut output_fs, false)
        .expect("couldn't deserialize Sapling spend parameters file");

    // There is extra stuff (the transcript) at the end of the parameter file which is
    // used to verify the parameter validity, but we're not interested in that. We do
    // want to read it, though, so that the BLAKE2b computed afterward is consistent
    // with `b2sum` on the files.
    let mut sink = io::sink();
    io::copy(&mut spend_fs, &mut sink)
        .expect("couldn't finish reading Sapling spend parameter file");
    io::copy(&mut output_fs, &mut sink)
        .expect("couldn't finish reading Sapling output parameter file");

    if spend_fs.into_hash() != "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c" {
        panic!("Sapling spend parameter is not correct. please file a Github issue.");
    }

    if output_fs.into_hash() != "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028" {
        panic!("Sapling output parameter is not correct, please file a Github issue.");
    }

    // Prepare verifying keys
    let spend_vk = prepare_verifying_key(&spend_params.vk);
    let output_vk = prepare_verifying_key(&output_params.vk);

    (spend_params, spend_vk, output_params, output_vk)
}

/// Initialize the sapling proving context
pub fn initialize_proving_context() -> SaplingProvingContext {
    SaplingProvingContext::new()
}

/// Initialize the sapling verifying context
pub fn initialize_verifying_context() -> SaplingVerificationContext {
    SaplingVerificationContext::new()
}

pub struct ZcashVector;

impl ZcashVector {
    /// Read and output a vector with a variable length integer
    pub fn read<R: Read, E, F>(mut reader: R, func: F) -> Result<Vec<E>, TransactionError>
    where
        F: Fn(&mut R) -> Result<E, TransactionError>,
    {
        let count = read_variable_length_integer(&mut reader)?;
        (0..count).map(|_| func(&mut reader)).collect()
    }
}

/// Generate the script_pub_key of a corresponding address
pub fn create_script_pub_key<N: ZcashNetwork>(address: &ZcashAddress<N>) -> Result<Vec<u8>, TransactionError> {
    match address.format() {
        ZcashFormat::P2PKH => {
            let address_bytes = &address.to_string().from_base58()?;
            let pub_key_hash = address_bytes[2..(address_bytes.len() - 4)].to_vec();

            let mut script = vec![];
            script.push(Opcode::OP_DUP as u8);
            script.push(Opcode::OP_HASH160 as u8);
            script.extend(variable_length_integer(pub_key_hash.len() as u64)?);
            script.extend(pub_key_hash);
            script.push(Opcode::OP_EQUALVERIFY as u8);
            script.push(Opcode::OP_CHECKSIG as u8);
            Ok(script)
        }
        _ => unreachable!(),
    }
}

/// Return the transaction header given a version
fn fetch_header_and_version_group_id(version: &str) -> (u32, u32) {
    match version {
        "sapling" => (2147483652, 0x892F2085),
        // Zcash currently only supports sapling transactions
        _ => unimplemented!(),
    }
}

/// Returns a Blake256 hash of a given personalization, message, and optional Zcash version
fn blake2_256_hash(personalization: &str, message: Vec<u8>, version: Option<&str>) -> Hash {
    let personalization = match version {
        Some("sapling") => [personalization.as_bytes(), &(0x76b809bb as u32).to_le_bytes()].concat(),
        Some("overwinter") => [personalization.as_bytes(), &(0x5ba81b19 as u32).to_le_bytes()].concat(),
        Some(_) => [personalization.as_bytes(), &(0x76b809bb as u32).to_le_bytes()].concat(),
        None => personalization.as_bytes().to_vec(),
    };

    Params::new()
        .hash_length(32)
        .personal(&personalization)
        .to_state()
        .update(&message)
        .finalize()
}

/// Represents the signature hash opcode
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum SignatureHash {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 128,
}

impl fmt::Display for SignatureHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignatureHash::SIGHASH_ALL => write!(f, "SIGHASH_ALL"),
            SignatureHash::SIGHASH_NONE => write!(f, "SIGHASH_NONE"),
            SignatureHash::SIGHASH_SINGLE => write!(f, "SIGHASH_SINGLE"),
            SignatureHash::SIGHASH_ANYONECANPAY => write!(f, "SIGHASH_ANYONECANPAY"),
        }
    }
}

impl SignatureHash {
    fn from_byte(byte: &u8) -> Self {
        match byte {
            1 => SignatureHash::SIGHASH_ALL,
            2 => SignatureHash::SIGHASH_NONE,
            3 => SignatureHash::SIGHASH_SINGLE,
            128 => SignatureHash::SIGHASH_ANYONECANPAY,
            _ => SignatureHash::SIGHASH_ALL,
        }
    }
}

/// Represents the commonly used script opcodes
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    OP_DUP = 0x76,
    OP_HASH160 = 0xa9,
    OP_CHECKSIG = 0xac,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Opcode::OP_DUP => write!(f, "OP_DUP"),
            Opcode::OP_HASH160 => write!(f, "OP_HASH160"),
            Opcode::OP_CHECKSIG => write!(f, "OP_CHECKSIG"),
            Opcode::OP_EQUAL => write!(f, "OP_EQUAL"),
            Opcode::OP_EQUALVERIFY => write!(f, "OP_EQUALVERIFY"),
        }
    }
}

/// Represents a Zcash transparent transaction outpoint
#[derive(Debug, Clone)]
pub struct Outpoint<N: ZcashNetwork> {
    /// Previous transaction id (using Zcash RPC's reversed hash order) - 32 bytes
    pub reverse_transaction_id: Vec<u8>,
    /// Index of the transaction being used - 4 bytes
    pub index: u32,
    /// Amount associated with the UTXO - used for segwit transaction signatures
    pub amount: Option<ZcashAmount>,
    /// Script public key asssociated with claiming this particular input UTXO
    pub script_pub_key: Option<Vec<u8>>,
    /// Optional redeem script - for segwit transactions
    pub redeem_script: Option<Vec<u8>>,
    /// Address of the outpoint
    pub address: Option<ZcashAddress<N>>,
}

impl<N: ZcashNetwork> Outpoint<N> {
    /// Returns a new Zcash transaction outpoint
    pub fn new(
        reverse_transaction_id: Vec<u8>,
        index: u32,
        address: Option<ZcashAddress<N>>,
        amount: Option<ZcashAmount>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
    ) -> Result<Self, TransactionError> {
        let script_pub_key = match address.clone() {
            Some(address) => {
                let script_pub_key = script_pub_key.unwrap_or(create_script_pub_key::<N>(&address)?);
                if &address.format() == &ZcashFormat::P2PKH
                    && script_pub_key[0] != Opcode::OP_DUP as u8
                    && script_pub_key[1] != Opcode::OP_HASH160 as u8
                    && script_pub_key[script_pub_key.len() - 1] != Opcode::OP_CHECKSIG as u8
                {
                    return Err(TransactionError::InvalidScriptPubKey("P2PKH".into()));
                };

                Some(script_pub_key)
            }
            None => None,
        };

        Ok(Self {
            reverse_transaction_id,
            index,
            amount,
            redeem_script,
            script_pub_key,
            address,
        })
    }
}

/// Represents a Zcash transaction transparent input
#[derive(Debug, Clone)]
pub struct ZcashTransparentInput<N: ZcashNetwork> {
    /// Outpoint - transaction id and index - 36 bytes
    pub outpoint: Outpoint<N>,
    /// Tx-in script - Variable size
    pub script: Vec<u8>,
    /// Sequence number - 4 bytes (normally 0xFFFFFFFF, unless lock > 0)
    /// Also used in replace-by-fee - BIP 125.
    pub sequence: Vec<u8>,
    /// SIGHASH Code - 4 Bytes (used in signing raw transaction only)
    pub sighash_code: SignatureHash,
    /// If true, the input has been signed
    pub is_signed: bool,
}

impl<N: ZcashNetwork> ZcashTransparentInput<N> {
    const DEFAULT_SEQUENCE: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

    /// Returns a new Zcash transparent input without the script.
    pub fn new(
        transaction_id: Vec<u8>,
        index: u32,
        address: Option<ZcashAddress<N>>,
        amount: Option<ZcashAmount>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
        sequence: Option<Vec<u8>>,
        sighash_code: SignatureHash,
    ) -> Result<Self, TransactionError> {
        if transaction_id.len() != 32 {
            return Err(TransactionError::InvalidTransactionId(transaction_id.len()));
        }

        // Reverse hash order - https://bitcoin.org/en/developer-reference#hash-byte-order
        let mut reverse_transaction_id = transaction_id;
        reverse_transaction_id.reverse();

        let outpoint = Outpoint::<N>::new(
            reverse_transaction_id,
            index,
            address,
            amount,
            redeem_script,
            script_pub_key,
        )?;
        let sequence = sequence.unwrap_or(ZcashTransparentInput::<N>::DEFAULT_SEQUENCE.to_vec());

        Ok(Self {
            outpoint,
            script: Vec::new(),
            sequence,
            sighash_code,
            is_signed: false,
        })
    }

    /// Read and output a Zcash transaction transparent input
    pub fn read<R: Read>(mut reader: &mut R) -> Result<Self, TransactionError> {
        let mut transaction_hash = [0u8; 32];
        reader.read(&mut transaction_hash)?;

        let mut vin = [0u8; 4];
        reader.read(&mut vin)?;

        let outpoint = Outpoint {
            reverse_transaction_id: transaction_hash.to_vec(),
            index: u32::from_le_bytes(vin),
            amount: None,
            script_pub_key: None,
            redeem_script: None,
            address: None,
        };

        let script: Vec<u8> = ZcashVector::read(&mut reader, |s| {
            let mut byte = [0u8; 1];
            s.read(&mut byte)?;
            Ok(byte[0])
        })?;

        let mut sequence = [0u8; 4];
        reader.read(&mut sequence)?;

        let script_len = read_variable_length_integer(&script[..])?;
        let sighash_code = SignatureHash::from_byte(&match script_len {
            0 => 0x01,
            length => script[length],
        });

        Ok(Self {
            outpoint,
            script: script.to_vec(),
            sequence: sequence.to_vec(),
            sighash_code,
            is_signed: script.len() > 0,
        })
    }

    /// Returns the serialized transparent input.
    pub fn serialize(&self, raw: bool, hash_preimage: bool) -> Result<Vec<u8>, TransactionError> {
        let mut input = vec![];
        input.extend(&self.outpoint.reverse_transaction_id);
        input.extend(&self.outpoint.index.to_le_bytes());

        match (raw, self.script.len()) {
            (true, _) => input.extend(vec![0x00]),
            (false, 0) => {
                let script_pub_key = match &self.outpoint.script_pub_key {
                    Some(script) => script,
                    None => return Err(TransactionError::MissingOutpointScriptPublicKey),
                };
                input.extend(variable_length_integer(script_pub_key.len() as u64)?);
                input.extend(script_pub_key);
            }
            (false, _) => {
                input.extend(variable_length_integer(self.script.len() as u64)?);
                input.extend(&self.script);
            }
        };

        match (hash_preimage, &self.outpoint.amount) {
            (true, Some(amount)) => input.extend(&amount.0.to_le_bytes()),
            (true, None) => return Err(TransactionError::MissingOutpointAmount),
            (false, _) => {}
        };

        input.extend(&self.sequence);
        Ok(input)
    }
}

/// Represents a Zcash transaction transparent output
#[derive(Debug, Clone)]
pub struct ZcashTransparentOutput {
    /// The amount (in zatoshi)
    pub amount: ZcashAmount,
    /// The public key script
    pub script_pub_key: Vec<u8>,
}

impl ZcashTransparentOutput {
    /// Returns a new Zcash transparent output.
    pub fn new<N: ZcashNetwork>(address: &ZcashAddress<N>, amount: ZcashAmount) -> Result<Self, TransactionError> {
        Ok(Self {
            amount,
            script_pub_key: create_script_pub_key::<N>(address)?,
        })
    }

    /// Read and output a Zcash transaction output
    pub fn read<R: Read>(mut reader: &mut R) -> Result<Self, TransactionError> {
        let mut amount = [0u8; 8];
        reader.read(&mut amount)?;

        let script_pub_key: Vec<u8> = ZcashVector::read(&mut reader, |s| {
            let mut byte = [0u8; 1];
            s.read(&mut byte)?;
            Ok(byte[0])
        })?;

        Ok(Self {
            amount: ZcashAmount::from_zatoshi(u64::from_le_bytes(amount) as i64)?,
            script_pub_key,
        })
    }

    /// Returns the serialized transparent output.
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let mut output = vec![];
        output.extend(&self.amount.0.to_le_bytes());
        output.extend(variable_length_integer(self.script_pub_key.len() as u64)?);
        output.extend(&self.script_pub_key);
        Ok(output)
    }
}

/// Represents a Zcash Sapling spend description
#[derive(Debug, Clone)]
pub struct SaplingSpendDescription {
    /// The value commitment to the value of the input note, LEBS2OSP_256(repr_J(cv)).
    pub cv: [u8; 32],
    /// The root of the Sapling note commitment tree at a past block height, LEBS2OSP_256(rt).
    pub anchor: [u8; 32],
    /// The nullifier of the input note, LEBS2OSP_256(nf).
    pub nullifier: [u8; 32],
    /// The randomized public key for `spend_auth_sig`, LEBS2OSP_256(repr_J(rk)).
    pub rk: [u8; 32],
    /// The encoding of the zero knowledge proof used for the output circuit.
    pub zk_proof: Vec<u8>,
    /// The signature authorizing this spend.
    pub spend_auth_sig: Option<Vec<u8>>,
}

impl SaplingSpendDescription {
    /// Returns the serialized sapling spend description
    pub fn serialize(&self, sighash: bool) -> Result<Vec<u8>, TransactionError> {
        let mut input = vec![];
        input.extend(&self.cv);
        input.extend(&self.anchor);
        input.extend(&self.nullifier);
        input.extend(&self.rk);
        input.extend(&self.zk_proof);
        if let (Some(spend_auth_sig), false) = (&self.spend_auth_sig, sighash) {
            input.extend(spend_auth_sig);
        };
        Ok(input)
    }

    /// Read and output a Zcash sapling spend description
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, TransactionError> {
        let mut cv = [0u8; 32];
        let mut anchor = [0u8; 32];
        let mut nullifier = [0u8; 32];
        let mut rk = [0u8; 32];
        let mut zk_proof = [0u8; 192];
        let mut spend_auth_sig = [0u8; 64];

        reader.read(&mut cv)?;
        reader.read(&mut anchor)?;
        reader.read(&mut nullifier)?;
        reader.read(&mut rk)?;
        reader.read(&mut zk_proof)?;
        reader.read(&mut spend_auth_sig)?;

        Ok(Self {
            cv,
            anchor,
            nullifier,
            rk,
            zk_proof: zk_proof.to_vec(),
            spend_auth_sig: Some(spend_auth_sig.to_vec()),
        })
    }
}

/// Represents a Zcash transaction Shielded Spend parameters
#[derive(Debug, Clone)]
pub struct SaplingSpendParameters<N: ZcashNetwork> {
    /// The Sapling extended secret key
    pub extended_private_key: ZcashExtendedPrivateKey<N>,
    /// The Sapling address diversifier
    pub diversifier: [u8; 11],
    /// The Sapling spend note
    pub note: Note<Bls12>,
    /// The alpha randomness
    pub alpha: Fs,
    /// The anchor
    pub anchor: Fr,
    /// The commitment witness
    pub witness: MerklePath<Node>,
}

/// Represents a Zcash transaction Shielded Spend
#[derive(Debug, Clone)]
pub struct SaplingSpend<N: ZcashNetwork> {
    /// The Sapling spend parameters
    pub spend_parameters: Option<SaplingSpendParameters<N>>,
    /// The spend description
    pub spend_description: Option<SaplingSpendDescription>,
}

impl<N: ZcashNetwork> SaplingSpend<N> {
    /// Returns a new Zcash sapling spend
    pub fn new(
        extended_private_key: &ZcashExtendedPrivateKey<N>,
        cmu: &[u8; 32],
        epk: &[u8; 32],
        enc_ciphertext: &str,
        anchor: Fr,
        witness: MerklePath<Node>,
    ) -> Result<Self, TransactionError> {
        let full_viewing_key = extended_private_key
            .to_extended_public_key()
            .to_extended_full_viewing_key()
            .fvk
            .to_bytes();
        let ivk = FullViewingKey::<Bls12>::read(&full_viewing_key[..], &JUBJUB)?.vk.ivk();

        let mut f = FrRepr::default();
        f.read_le(&cmu[..])?;

        let alpha = Fs::random(&mut StdRng::from_entropy());
        let cmu = Fr::from_repr(f)?;
        let enc_ciphertext_vec = hex::decode(enc_ciphertext)?;

        let epk = match edwards::Point::<Bls12, _>::read(&epk[..], &JUBJUB)?.as_prime_order(&JUBJUB) {
            Some(epk) => epk,
            None => return Err(TransactionError::InvalidEphemeralKey(hex::encode(epk))),
        };

        let (note, payment_address, _memo) =
            match try_sapling_note_decryption(&ivk.into(), &epk, &cmu, &enc_ciphertext_vec) {
                None => return Err(TransactionError::FailedNoteDecryption(enc_ciphertext.into())),
                Some((note, payment_address, memo)) => (note, payment_address, memo),
            };

        let spend_parameters = Some(SaplingSpendParameters {
            extended_private_key: extended_private_key.clone(),
            diversifier: payment_address.diversifier().0,
            note,
            alpha,
            anchor,
            witness,
        });

        Ok(Self {
            spend_parameters,
            spend_description: None,
        })
    }

    /// Create Sapling spend description
    pub fn create_sapling_spend_description(
        &mut self,
        proving_ctx: &mut SaplingProvingContext,
        spend_params: &Parameters<Bls12>,
        spend_vk: &PreparedVerifyingKey<Bls12>,
    ) -> Result<(), TransactionError> {
        let spend_parameters = match &self.spend_parameters {
            Some(spend_parameters) => spend_parameters,
            None => return Err(TransactionError::MissingSpendParameters),
        };

        let spending_key = spend_parameters
            .extended_private_key
            .to_extended_spending_key()
            .expsk
            .to_bytes();
        let proof_generation_key = ExpandedSpendingKey::<Bls12>::read(&spending_key[..])?.proof_generation_key(&JUBJUB);

        let nf = &spend_parameters.note.nf(
            &proof_generation_key.to_viewing_key(&JUBJUB),
            spend_parameters.witness.position,
            &JUBJUB,
        );

        let (proof, value_commitment, public_key) = proving_ctx.spend_proof(
            proof_generation_key,
            Diversifier(spend_parameters.diversifier),
            spend_parameters.note.r,
            spend_parameters.alpha,
            spend_parameters.note.value,
            spend_parameters.anchor,
            spend_parameters.witness.clone(),
            spend_params,
            spend_vk,
            &JUBJUB,
        )?;

        let mut cv = [0u8; 32];
        let mut anchor = [0u8; 32];
        let mut nullifier = [0u8; 32];
        let mut rk = [0u8; 32];
        let mut zk_proof = [0u8; GROTH_PROOF_SIZE];

        value_commitment.write(&mut cv[..])?;
        spend_parameters.anchor.into_repr().write_le(&mut anchor[..])?;
        nullifier.copy_from_slice(nf);
        public_key.write(&mut rk[..])?;
        proof.write(&mut zk_proof[..])?;

        let spend_description = SaplingSpendDescription {
            cv,
            anchor,
            nullifier,
            rk,
            zk_proof: zk_proof.to_vec(),
            spend_auth_sig: None,
        };

        self.spend_description = Some(spend_description);

        Ok(())
    }

    /// Read and output a Zcash sapling spend
    pub fn read<R: Read>(mut reader: &mut R) -> Result<Self, TransactionError> {
        let spend_description = SaplingSpendDescription::read(&mut reader)?;
        Ok(Self {
            spend_parameters: None,
            spend_description: Some(spend_description),
        })
    }
}

/// Represents a Zcash Sapling output description
#[derive(Debug, Clone)]
pub struct SaplingOutputDescription {
    /// The value commitment to the value of the output note, LEBS2OSP_256(repr_J(cv)).
    pub cv: [u8; 32],
    /// The u-coordinate of the note commitment for the output note,
    /// LEBS2OSP_256(cm_u) where cm_u = Extract_J^(r) (cm).
    pub cmu: [u8; 32],
    /// The encoding of an ephemeral Jubjub public key, LEBS2OSP_256(repr_J(epk)).
    pub ephemeral_key: [u8; 32],
    /// The ciphertext component for the encrypted output note, C_enc.
    pub enc_ciphertext: Vec<u8>,
    /// The ciphertext component for the encrypted output note, C_out.
    pub out_ciphertext: Vec<u8>,
    /// The encoding of the zero knowledge proof for the output circuit.
    pub zk_proof: Vec<u8>,
}

impl SaplingOutputDescription {
    /// Returns the serialized sapling output description
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let mut output = vec![];
        output.extend(&self.cv);
        output.extend(&self.cmu);
        output.extend(&self.ephemeral_key);
        output.extend(&self.enc_ciphertext);
        output.extend(&self.out_ciphertext);
        output.extend(&self.zk_proof);
        Ok(output)
    }

    /// Read and output a Zcash sapling spend description
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, TransactionError> {
        let mut cv = [0u8; 32];
        let mut cmu = [0u8; 32];
        let mut ephemeral_key = [0u8; 32];
        let mut enc_ciphertext = [0u8; 580];
        let mut out_ciphertext = [0u8; 80];
        let mut zk_proof = [0u8; 192];

        reader.read(&mut cv)?;
        reader.read(&mut cmu)?;
        reader.read(&mut ephemeral_key)?;
        reader.read(&mut enc_ciphertext)?;
        reader.read(&mut out_ciphertext)?;
        reader.read(&mut zk_proof)?;

        Ok(Self {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext: enc_ciphertext.to_vec(),
            out_ciphertext: out_ciphertext.to_vec(),
            zk_proof: zk_proof.to_vec(),
        })
    }
}

/// Represents a Zcash transaction Shielded Output parameters
#[derive(Debug, Clone)]
pub struct SaplingOutputParameters<N: ZcashNetwork> {
    /// The Sapling address
    pub address: ZcashAddress<N>,
    /// The outgoing view key
    pub ovk: SaplingOutgoingViewingKey,
    /// The Sapling output address
    pub to: PaymentAddress<Bls12>,
    /// The Sapling output note
    pub note: Note<Bls12>,
    /// An optional memo
    pub memo: Memo,
}

/// Represents a Zcash Sapling output
#[derive(Debug, Clone)]
pub struct SaplingOutput<N: ZcashNetwork> {
    /// The Sapling output parameters
    pub output_parameters: Option<SaplingOutputParameters<N>>,
    /// The output description
    pub output_description: Option<SaplingOutputDescription>,
}

impl<N: ZcashNetwork> SaplingOutput<N> {
    /// Returns a new Zcash sapling output
    pub fn new(
        ovk: SaplingOutgoingViewingKey,
        address: &ZcashAddress<N>,
        value: ZcashAmount,
    ) -> Result<Self, TransactionError> {
        let diversifier = match address.to_diversifier() {
            Some(d) => {
                let mut diversifier = [0u8; 11];
                diversifier.copy_from_slice(&hex::decode(d)?);
                diversifier
            }
            None => return Err(TransactionError::MissingDiversifier),
        };

        let pk_d = edwards::Point::<Bls12, _>::read(&address.to_diversified_transmission_key()?[..], &JUBJUB)?
            .as_prime_order(&JUBJUB);

        match pk_d {
            None => return Err(TransactionError::InvalidOutputAddress(address.to_string())),
            Some(pk_d) => {
                let to = match PaymentAddress::from_parts(Diversifier(diversifier), pk_d.clone()) {
                    Some(to) => to,
                    None => return Err(TransactionError::InvalidOutputAddress(address.to_string())),
                };

                let g_d = match to.g_d(&JUBJUB) {
                    Some(g_d) => g_d,
                    None => return Err(TransactionError::InvalidOutputAddress(address.to_string())),
                };

                let note = Note {
                    g_d,
                    pk_d,
                    value: value.0 as u64,
                    r: Fs::random(&mut StdRng::from_entropy()),
                };

                let output_parameters = Some(SaplingOutputParameters {
                    address: address.clone(),
                    ovk,
                    to,
                    note,
                    memo: Memo::default(),
                });

                Ok(Self {
                    output_parameters,
                    output_description: None,
                })
            }
        }
    }

    /// Create Sapling Output Description
    pub fn create_sapling_output_description(
        &mut self,
        proving_ctx: &mut SaplingProvingContext,
        verifying_ctx: &mut SaplingVerificationContext,
        output_params: &Parameters<Bls12>,
        output_vk: &PreparedVerifyingKey<Bls12>,
    ) -> Result<(), TransactionError> {
        let output_parameters = match &self.output_parameters {
            Some(output_parameters) => output_parameters,
            None => return Err(TransactionError::MissingOutputParameters),
        };
        let ovk = OutgoingViewingKey(output_parameters.ovk.0);
        let note_encryption = SaplingNoteEncryption::new(
            ovk,
            output_parameters.note.clone(),
            output_parameters.to.clone(),
            output_parameters.memo.clone(),
            &mut StdRng::from_entropy(),
        );

        let (proof, value_commitment) = proving_ctx.output_proof(
            note_encryption.esk().clone(),
            output_parameters.to.clone(),
            output_parameters.note.r,
            output_parameters.note.value,
            &output_params,
            &JUBJUB,
        );

        // Generate the ciphertexts

        let cm = output_parameters.note.cm(&JUBJUB);
        let enc_ciphertext = note_encryption.encrypt_note_plaintext();
        let out_ciphertext = note_encryption.encrypt_outgoing_plaintext(&value_commitment, &cm);

        // Write the points as bytes

        let mut cmu = [0u8; 32];
        cmu.copy_from_slice(
            &cm.into_repr()
                .0
                .iter()
                .flat_map(|num| num.to_le_bytes().to_vec())
                .collect::<Vec<u8>>(),
        );

        let mut cv = [0u8; 32]; // Value commitment
        let mut ephemeral_key = [0u8; 32]; // EPK
        let mut zk_proof = [0u8; GROTH_PROOF_SIZE];

        value_commitment.write(&mut cv[..])?;
        note_encryption.epk().write(&mut ephemeral_key[..])?;
        proof.write(&mut zk_proof[..])?;

        // Verify the output description
        // Consider removing spend checks because zcash nodes also do this check when broadcasting transactions

        match verifying_ctx.check_output(
            value_commitment,
            cm,
            note_encryption.epk().clone().into(),
            proof,
            output_vk,
            &JUBJUB,
        ) {
            true => {}
            false => {
                return Err(TransactionError::InvalidOutputDescription(
                    output_parameters.address.to_string(),
                ))
            }
        };

        let output_description = SaplingOutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext: enc_ciphertext.to_vec(),
            out_ciphertext: out_ciphertext.to_vec(),
            zk_proof: zk_proof.to_vec(),
        };

        self.output_description = Some(output_description);

        Ok(())
    }

    /// Read and output a Zcash sapling output
    pub fn read<R: Read>(mut reader: &mut R) -> Result<Self, TransactionError> {
        let output_description = SaplingOutputDescription::read(&mut reader)?;
        Ok(Self {
            output_parameters: None,
            output_description: Some(output_description),
        })
    }
}

/// Represents the Zcash transaction parameters
#[derive(Debug, Clone)]
pub struct ZcashTransactionParameters<N: ZcashNetwork> {
    /// The header of the transaction (Overwintered flag and transaction version) (04000080 for Sapling)
    pub header: u32,
    /// The version group ID (0x892F2085 for Sapling)
    pub version_group_id: u32,
    /// The inputs for a transparent transaction, encoded as in Bitcoin.
    pub transparent_inputs: Vec<ZcashTransparentInput<N>>,
    /// The outputs for a transparent transaction, encoded as in Bitcoin,
    pub transparent_outputs: Vec<ZcashTransparentOutput>,
    /// The Unix epoch time (UTC) or block height, encoded as in Bitcoin. (4 bytes)
    pub lock_time: u32,
    /// The block height in the range {1 .. 499999999} after which the transaction will expire,
    /// or 0 to disable expiry (ZIP-203).
    pub expiry_height: u32,
    /// The inputs for a shielded transaction, encoded as a sequence of Zcash spend descriptions.
    pub shielded_inputs: Vec<SaplingSpend<N>>,
    /// The outputs for a shielded transaction, encoded as a sequence of Zcash output descriptions.
    pub shielded_outputs: Vec<SaplingOutput<N>>,
    /// The balancing value is the net value of spend transfers minus output transfers
    /// in a transaction (in zatoshi, represented as a signed integer).
    ///
    /// A positive balancing value takes value from the Sapling value pool,
    /// and adds it to the transparent value pool.
    ///
    /// A negative balancing value does the reverse.
    pub value_balance: ZcashAmount,
    /// The binding signature enforces the consistency of the balancing value with
    /// the value commitments in spend descriptions and output descriptions.
    ///
    /// Namely, it enforces:
    ///
    /// 1) That the value spent by spend transfers minus that produced by output transfers,
    /// is consistent with the balancing value field of the transaction.
    ///
    /// 2) That the signer knew the randomness used for the spend and output value commitments,
    /// in order to prevent output descriptions from being replayed by an adversary
    /// in a different transaction.
    pub binding_signature: Option<Vec<u8>>,
    /// The root of the Sapling note commitment tree at some block height in the past.
    pub anchor: Option<Fr>,
}

impl<N: ZcashNetwork> ZcashTransactionParameters<N> {
    /// Returns the Zcash transaction parameters
    pub fn new(version: &str, lock_time: u32, expiry_height: u32) -> Result<Self, TransactionError> {
        let (header, version_group_id) = fetch_header_and_version_group_id(version);

        Ok(Self {
            header,
            version_group_id,
            transparent_inputs: vec![],
            transparent_outputs: vec![],
            shielded_inputs: vec![],
            shielded_outputs: vec![],
            expiry_height,
            value_balance: ZcashAmount::ZERO,
            binding_signature: None,
            anchor: None,
            lock_time,
        })
    }

    /// Returns the transaction parameters with the given transparent input appended.
    pub fn add_transparent_input(
        &self,
        transaction_id: Vec<u8>,
        index: u32,
        address: Option<ZcashAddress<N>>,
        amount: Option<ZcashAmount>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
        sequence: Option<Vec<u8>>,
        sighash_code: SignatureHash,
    ) -> Result<Self, TransactionError> {
        let mut parameters = self.clone();
        parameters.transparent_inputs.push(ZcashTransparentInput::<N>::new(
            transaction_id,
            index,
            address,
            amount,
            redeem_script,
            script_pub_key,
            sequence,
            sighash_code,
        )?);
        Ok(parameters)
    }

    /// Returns the transaction parameters with the given transparent output appended.
    pub fn add_transparent_output(
        &self,
        address: &ZcashAddress<N>,
        amount: ZcashAmount,
    ) -> Result<Self, TransactionError> {
        let mut parameters = self.clone();
        parameters
            .transparent_outputs
            .push(ZcashTransparentOutput::new::<N>(address, amount)?);
        Ok(parameters)
    }

    /// Add a sapling shielded spend to the transaction
    pub fn add_sapling_input(
        &self,
        extended_private_key: &ZcashExtendedPrivateKey<N>,
        cmu: &[u8; 32],
        epk: &[u8; 32],
        enc_ciphertext: &str,
        input_anchor: Fr,
        witness: MerklePath<Node>,
    ) -> Result<Self, TransactionError> {
        let mut parameters = self.clone();

        // Verify all anchors are the same
        match &self.anchor {
            None => parameters.anchor = Some(input_anchor),
            Some(anchor) => {
                if anchor != &input_anchor {
                    return Err(TransactionError::ConflictingWitnessAnchors());
                }
            }
        };

        let sapling_spend =
            SaplingSpend::<N>::new(extended_private_key, cmu, epk, enc_ciphertext, input_anchor, witness)?;

        let value = match &sapling_spend.spend_parameters {
            Some(spend_parameters) => spend_parameters.note.value,
            None => return Err(TransactionError::MissingSpendParameters),
        };

        parameters.value_balance = parameters.value_balance.add(ZcashAmount::from_zatoshi(value as i64)?)?;
        parameters.shielded_inputs.push(sapling_spend);
        Ok(parameters)
    }

    /// Add a sapling shielded output to the transaction
    pub fn add_sapling_output(
        &self,
        ovk: Option<SaplingOutgoingViewingKey>,
        address: &ZcashAddress<N>,
        amount: ZcashAmount,
    ) -> Result<Self, TransactionError> {
        let ovk = match ovk {
            Some(ovk) => ovk,
            None => {
                // Generate a common ovk from rand HD seed
                // (optionally pass in a seed for wallet management purposes)
                let rng = &mut StdRng::from_entropy();
                let seed: [u8; 32] = rng.gen();
                let hash = blake2_256_hash("ZcTaddrToSapling", seed.to_vec(), None);
                let mut ovk = [0u8; 32];
                ovk.copy_from_slice(&prf_expand(hash.as_bytes(), &[0x01]).as_bytes()[0..32]);

                SaplingOutgoingViewingKey(ovk)
            }
        };

        let mut parameters = self.clone();
        let sapling_output = SaplingOutput::<N>::new(ovk, address, amount)?;

        let value = match &sapling_output.output_parameters {
            Some(output_parameters) => output_parameters.note.value,
            None => return Err(TransactionError::MissingOutputParameters),
        };

        parameters.value_balance = parameters.value_balance.sub(ZcashAmount::from_zatoshi(value as i64)?)?;
        parameters.shielded_outputs.push(sapling_output);
        Ok(parameters)
    }

    /// Read and output the Zcash transaction parameters
    pub fn read<R: Read>(mut reader: R) -> Result<Self, TransactionError> {
        let mut header = [0u8; 4];
        let mut version_group_id = [0u8; 4];
        let mut lock_time = [0u8; 4];
        let mut expiry_height = [0u8; 4];
        let mut value_balance = [0u8; 8];
        let mut binding_sig = [0u8; 64];

        reader.read(&mut header)?;
        reader.read(&mut version_group_id)?;

        let transparent_inputs = ZcashVector::read(&mut reader, ZcashTransparentInput::<N>::read)?;
        let transparent_outputs = ZcashVector::read(&mut reader, ZcashTransparentOutput::read)?;

        reader.read(&mut lock_time)?;
        reader.read(&mut expiry_height)?;
        reader.read(&mut value_balance)?;

        let shielded_inputs = ZcashVector::read(&mut reader, SaplingSpend::<N>::read)?;
        let shielded_outputs = ZcashVector::read(&mut reader, SaplingOutput::<N>::read)?;

        if read_variable_length_integer(&mut reader)? > 0 {
            return Err(TransactionError::UnsupportedJoinsplits);
        }

        let binding_signature = match reader.read(&mut binding_sig)? {
            0 => None,
            _ => Some(binding_sig.to_vec()),
        };

        Ok(Self {
            header: u32::from_le_bytes(header),
            version_group_id: u32::from_le_bytes(version_group_id),
            transparent_inputs,
            transparent_outputs,
            lock_time: u32::from_le_bytes(lock_time),
            expiry_height: u32::from_le_bytes(expiry_height),
            shielded_inputs,
            shielded_outputs,
            value_balance: ZcashAmount::from_zatoshi(i64::from_le_bytes(value_balance))?,
            binding_signature,
            anchor: None,
        })
    }
}

/// Represents an Zcash transaction id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZcashTransactionId {
    txid: Vec<u8>,
}

impl TransactionId for ZcashTransactionId {}

impl fmt::Display for ZcashTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &hex::encode(&self.txid))
    }
}

/// Represents a Zcash transaction
#[derive(Clone)]
pub struct ZcashTransaction<N: ZcashNetwork> {
    pub parameters: ZcashTransactionParameters<N>,
}

impl<N: ZcashNetwork> Transaction for ZcashTransaction<N> {
    type Address = ZcashAddress<N>;
    type Format = ZcashFormat;
    type PrivateKey = ZcashPrivateKey<N>;
    type PublicKey = ZcashPublicKey<N>;
    type TransactionId = ZcashTransactionId;
    type TransactionParameters = ZcashTransactionParameters<N>;

    /// Returns an unsigned transaction given the transaction parameters.
    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            parameters: parameters.clone(),
        })
    }

    /// Returns a signed transaction given the private key of the sender.
    fn sign(&self, private_key: &Self::PrivateKey) -> Result<Self, TransactionError> {
        let mut transaction = self.clone();
        for (vin, input) in self.parameters.transparent_inputs.iter().enumerate() {
            let address = match &input.outpoint.address {
                Some(address) => address,
                None => continue,
            };

            if address == &private_key.to_address(&address.format())?
                && !transaction.parameters.transparent_inputs[vin].is_signed
            {
                // Transaction hash
                let transaction_hash = match &address.format() {
                    ZcashFormat::P2PKH => transaction.generate_sighash(Some(vin), input.sighash_code)?,
                    _ => unimplemented!(),
                };

                // Signature
                let mut signature = match &private_key {
                    ZcashPrivateKey::<N>::P2PKH(p2pkh_spending_key) => {
                        let (signature, _) = secp256k1::sign(
                            &secp256k1::Message::parse_slice(&transaction_hash.as_bytes())?,
                            &p2pkh_spending_key.to_secp256k1_secret_key(),
                        );
                        signature.serialize_der().as_ref().to_vec()
                    },
                    _ => unimplemented!(),
                };
                signature.push((input.sighash_code as u32).to_le_bytes()[0]);
                let signature = [variable_length_integer(signature.len() as u64)?, signature].concat();

                // Public Viewing Key
                let public_viewing_key = match private_key.to_public_key() {
                    ZcashPublicKey::<N>::P2PKH(p2pkh_view_key) => match p2pkh_view_key.is_compressed() {
                        true => p2pkh_view_key.to_secp256k1_public_key().serialize_compressed().to_vec(),
                        false => p2pkh_view_key
                            .to_secp256k1_public_key()
                            .serialize()
                            .to_vec(),
                    },
                    _ => unimplemented!(),
                };
                let public_viewing_key: Vec<u8> = [vec![public_viewing_key.len() as u8], public_viewing_key].concat();

                match &address.format() {
                    ZcashFormat::P2PKH => {
                        transaction.parameters.transparent_inputs[vin].script =
                            [signature.clone(), public_viewing_key].concat();
                        transaction.parameters.transparent_inputs[vin].is_signed = true;
                    }
                    _ => unimplemented!(),
                };
            }
        }
        Ok(transaction)
    }

    /// Returns a transaction given the transaction bytes.
    fn from_transaction_bytes(transaction: &Vec<u8>) -> Result<Self, TransactionError> {
        Ok(Self {
            parameters: Self::TransactionParameters::read(&transaction[..])?,
        })
    }

    /// Returns the transaction in bytes.
    fn to_transaction_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let mut transaction = vec![];

        transaction.extend(&self.parameters.header.to_le_bytes());
        transaction.extend(&self.parameters.version_group_id.to_le_bytes());

        transaction.extend(variable_length_integer(self.parameters.transparent_inputs.len() as u64)?);
        for input in &self.parameters.transparent_inputs {
            // TODO (howardwu): Implement "raw" bool for serializing the raw transaction.
            transaction.extend(input.serialize(!input.is_signed, false)?);
        }

        transaction.extend(variable_length_integer(
            self.parameters.transparent_outputs.len() as u64
        )?);
        for output in &self.parameters.transparent_outputs {
            transaction.extend(output.serialize()?);
        }

        transaction.extend(&self.parameters.lock_time.to_le_bytes());
        transaction.extend(&self.parameters.expiry_height.to_le_bytes());
        transaction.extend(&self.parameters.value_balance.0.to_le_bytes());

        match &self.parameters.shielded_inputs.len() {
            0 => transaction.push(0u8),
            _ => {
                transaction.extend(variable_length_integer(self.parameters.shielded_inputs.len() as u64)?);
                for spend in &self.parameters.shielded_inputs {
                    if let Some(description) = &spend.spend_description {
                        transaction.extend(description.serialize(false)?);
                    };
                }
            }
        };

        match &self.parameters.shielded_outputs.len() {
            0 => transaction.push(0u8),
            _ => {
                transaction.extend(variable_length_integer(self.parameters.shielded_outputs.len() as u64)?);
                for output in &self.parameters.shielded_outputs {
                    if let Some(description) = &output.output_description {
                        transaction.extend(description.serialize()?);
                    };
                }
            }
        };

        // Hardcoded length of 0, as JoinSplit (Sprout) is unsupported, thus the length must be 0.
        transaction.push(0u8);

        if let Some(binding_sig) = &self.parameters.binding_signature {
            transaction.extend(binding_sig);
        };

        Ok(transaction)
    }

    /// Returns the transaction id.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let mut txid = Sha256::digest(&Sha256::digest(&self.to_transaction_bytes()?)).to_vec();
        txid.reverse();

        Ok(Self::TransactionId { txid })
    }
}

impl<N: ZcashNetwork> ZcashTransaction<N> {
    /// Build the sapling spends and outputs in the transaction
    pub fn build_sapling_transaction(
        &mut self,
        proving_ctx: &mut SaplingProvingContext,
        verifying_ctx: &mut SaplingVerificationContext,
        spend_params: &Parameters<Bls12>,
        spend_vk: &PreparedVerifyingKey<Bls12>,
        output_params: &Parameters<Bls12>,
        output_vk: &PreparedVerifyingKey<Bls12>,
    ) -> Result<(), TransactionError> {
        match &self.parameters.shielded_inputs.len() {
            0 => (),
            _ => {
                for spend in &mut self.parameters.shielded_inputs {
                    spend.create_sapling_spend_description(proving_ctx, spend_params, spend_vk)?;
                }
            }
        };

        match &self.parameters.shielded_outputs.len() {
            0 => (),
            _ => {
                for output in &mut self.parameters.shielded_outputs {
                    output.create_sapling_output_description(proving_ctx, verifying_ctx, output_params, output_vk)?;
                }
            }
        };

        let mut sighash = [0u8; 32];
        sighash.copy_from_slice(self.generate_sighash(None, SignatureHash::SIGHASH_ALL)?.as_bytes());

        self.generate_spend_auth_signatures(verifying_ctx, spend_vk, &sighash)?;
        self.generate_binding_sig(proving_ctx, verifying_ctx, &sighash)?;

        Ok(())
    }

    pub fn generate_spend_auth_signatures(
        &mut self,
        verifying_ctx: &mut SaplingVerificationContext,
        spend_vk: &PreparedVerifyingKey<Bls12>,
        sighash: &[u8; 32],
    ) -> Result<(), TransactionError> {
        for spend in &mut self.parameters.shielded_inputs {
            let spend_parameters = match &spend.spend_parameters {
                Some(spend_parameters) => spend_parameters,
                None => return Err(TransactionError::MissingSpendParameters),
            };

            match &mut spend.spend_description {
                Some(spend_description) => {
                    let spending_key = spend_parameters
                        .extended_private_key
                        .to_extended_spending_key()
                        .expsk
                        .to_bytes();
                    let ask = ExpandedSpendingKey::<Bls12>::read(&spending_key[..])?.ask;

                    let sig = spend_sig(
                        jubjubPrivateKey(ask),
                        spend_parameters.alpha,
                        &sighash,
                        &mut StdRng::from_entropy(),
                        &JUBJUB,
                    );

                    let mut spend_auth_sig = [0u8; 64];
                    sig.write(&mut spend_auth_sig[..])?;

                    spend_description.spend_auth_sig = Some(spend_auth_sig.to_vec());

                    let mut f = FrRepr::default();
                    f.read_le(&spend_description.anchor[..])?;
                    let anchor_fr = Fr::from_repr(f)?;

                    let public_key = jubjubPublicKey::<Bls12>::read(&spend_description.rk[..], &JUBJUB)?;
                    let value_commitment = edwards::Point::<Bls12, _>::read(&spend_description.cv[..], &JUBJUB)?;
                    let proof = Proof::<Bls12>::read(&spend_description.zk_proof[..])?;
                    let check_sig = jubjubSignature::read(&spend_auth_sig[..])?;

                    // Verify the spend description
                    // Consider removing spend checks because zcash nodes also do this check when broadcasting transactions

                    match verifying_ctx.check_spend(
                        value_commitment,
                        anchor_fr,
                        &spend_description.nullifier,
                        public_key,
                        &sighash,
                        check_sig,
                        proof,
                        spend_vk,
                        &JUBJUB,
                    ) {
                        true => {}
                        false => return Err(TransactionError::InvalidSpendDescription),
                    };
                }
                None => return Err(TransactionError::MissingSpendDescription),
            }
        }

        Ok(())
    }

    /// Add the binding signature
    pub fn generate_binding_sig(
        &mut self,
        proving_ctx: &mut SaplingProvingContext,
        verifying_ctx: &mut SaplingVerificationContext,
        sighash: &[u8; 32],
    ) -> Result<(), TransactionError> {
        let mut binding_sig = [0u8; 64];
        let sig = proving_ctx.binding_sig(Amount::from_i64(self.parameters.value_balance.0)?, &sighash, &JUBJUB)?;
        sig.write(&mut binding_sig[..])?;
        self.parameters.binding_signature = Some(binding_sig.to_vec());

        match verifying_ctx.final_check(
            Amount::from_i64(self.parameters.value_balance.0)?,
            &sighash,
            sig,
            &JUBJUB,
        ) {
            true => Ok(()),
            false => Err(TransactionError::InvalidBindingSig()),
        }
    }

    /// Generate the sighash
    /// https://github.com/zcash/zips/blob/master/zip-0243.rst
    pub fn generate_sighash(
        &self,
        input_index: Option<usize>,
        sighash_code: SignatureHash,
    ) -> Result<Hash, TransactionError> {
        let mut prev_outputs = vec![];
        let mut prev_sequences = vec![];
        let mut outputs = vec![];

        for input in &self.parameters.transparent_inputs {
            prev_outputs.extend(&input.outpoint.reverse_transaction_id);
            prev_outputs.extend(&input.outpoint.index.to_le_bytes());
            prev_sequences.extend(&input.sequence);
        }

        for output in &self.parameters.transparent_outputs {
            outputs.extend(&output.serialize()?);
        }

        let hash_prev_outputs = blake2_256_hash("ZcashPrevoutHash", prev_outputs, None);
        let hash_sequence = blake2_256_hash("ZcashSequencHash", prev_sequences, None);
        let hash_outputs = blake2_256_hash("ZcashOutputsHash", outputs, None);
        let hash_joinsplits = [0u8; 32];

        let hash_shielded_spends = match &self.parameters.shielded_inputs.len() {
            0 => [0u8; 32].to_vec(),
            _ => {
                let mut spend_descriptions = vec![];
                for spend in &self.parameters.shielded_inputs {
                    if let Some(description) = &spend.spend_description {
                        spend_descriptions.extend(description.serialize(true)?);
                    };
                }
                blake2_256_hash("ZcashSSpendsHash", spend_descriptions, None)
                    .as_bytes()
                    .to_vec()
            }
        };

        let hash_shielded_outputs = match &self.parameters.shielded_outputs.len() {
            0 => [0u8; 32].to_vec(),
            _ => {
                let mut output_descriptions = vec![];
                for output in &self.parameters.shielded_outputs {
                    if let Some(description) = &output.output_description {
                        output_descriptions.extend(description.serialize()?);
                    }
                }
                blake2_256_hash("ZcashSOutputHash", output_descriptions, None)
                    .as_bytes()
                    .to_vec()
            }
        };

        let mut preimage = vec![];
        preimage.extend(&self.parameters.header.to_le_bytes());
        preimage.extend(&self.parameters.version_group_id.to_le_bytes());
        preimage.extend(hash_prev_outputs.as_bytes());
        preimage.extend(hash_sequence.as_bytes());
        preimage.extend(hash_outputs.as_bytes());
        preimage.extend(&hash_joinsplits);
        preimage.extend(&hash_shielded_spends);
        preimage.extend(&hash_shielded_outputs);
        preimage.extend(&self.parameters.lock_time.to_le_bytes());
        preimage.extend(&self.parameters.expiry_height.to_le_bytes());
        preimage.extend(&self.parameters.value_balance.0.to_le_bytes());
        preimage.extend(&(sighash_code as u32).to_le_bytes());

        if let Some(index) = input_index {
            preimage.extend(&self.parameters.transparent_inputs[index].serialize(false, true)?);
        };

        Ok(blake2_256_hash("ZcashSigHash", preimage, Some("sapling")))
    }

    /// Update a transaction's input outpoint
    #[allow(dead_code)]
    pub fn update_outpoint(&self, outpoint: Outpoint<N>) -> Self {
        let mut new_transaction = self.clone();
        for (vin, input) in self.parameters.transparent_inputs.iter().enumerate() {
            if &outpoint.reverse_transaction_id == &input.outpoint.reverse_transaction_id
                && &outpoint.index == &input.outpoint.index
            {
                new_transaction.parameters.transparent_inputs[vin].outpoint = outpoint.clone();
            }
        }
        new_transaction
    }
}

impl<N: ZcashNetwork> FromStr for ZcashTransaction<N> {
    type Err = TransactionError;

    fn from_str(transaction: &str) -> Result<Self, Self::Err> {
        Self::from_transaction_bytes(&hex::decode(transaction)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_key::SaplingSpendingKey;
    use crate::{Mainnet, Testnet};

    use bellman::groth16::PreparedVerifyingKey;
    use zcash_primitives::merkle_tree::{CommitmentTree, MerklePath, IncrementalWitness};

    #[derive(Clone)]
    pub struct TransactionData<'a> {
        pub version: &'a str,
        pub lock_time: u32,
        pub expiry_height: u32,
        pub inputs: &'a [Input],
        pub outputs: &'a [Output],
        pub sapling_inputs: &'a [SaplingInput],
        pub sapling_outputs: &'a [Output],
        pub expected_signed_transaction: &'static str,
        pub expected_transaction_id: &'static str,
    }

    #[derive(Clone)]
    pub struct Input {
        pub private_key: &'static str,
        pub address_format: ZcashFormat,
        pub transaction_id: &'static str,
        pub index: u32,
        pub redeem_script: Option<&'static str>,
        pub script_pub_key: Option<&'static str>,
        pub utxo_amount: Option<ZcashAmount>,
        pub sequence: Option<[u8; 4]>,
        pub sighash_code: SignatureHash,
    }

    #[derive(Clone)]
    pub struct SaplingInput {
        pub extended_private_key: &'static str,
        pub cmu: &'static str,
        pub epk: &'static str,
        pub enc_ciphertext: &'static str,
        pub anchor: Option<&'static str>,
        pub witness: Option<&'static str>,
    }

    #[derive(Clone)]
    pub struct Output {
        pub address: &'static str,
        pub amount: ZcashAmount,
    }

    fn test_sapling_transaction<N: ZcashNetwork>(
        version: &str,
        lock_time: u32,
        expiry_height: u32,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        sapling_inputs: Vec<SaplingInput>,
        sapling_outputs: Vec<Output>,
        spend_params: &Parameters<Bls12>,
        spend_vk: &PreparedVerifyingKey<Bls12>,
        output_params: &Parameters<Bls12>,
        output_vk: &PreparedVerifyingKey<Bls12>,
    ) {
        // Build raw transaction

        let parameters = ZcashTransactionParameters::<N>::new(version, lock_time, expiry_height).unwrap();
        let mut transaction = ZcashTransaction::<N>::new(&parameters).unwrap();

        // Add transparent inputs

        for input in &inputs {
            let private_key = ZcashPrivateKey::<N>::from_str(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();

            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = input.redeem_script.map(|script| hex::decode(script).unwrap());
            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());

            transaction.parameters = transaction
                .parameters
                .add_transparent_input(
                    transaction_id,
                    input.index,
                    Some(address),
                    input.utxo_amount,
                    redeem_script,
                    script_pub_key,
                    sequence,
                    input.sighash_code,
                )
                .unwrap();
        }

        // Add transparent outputs

        for output in outputs {
            let address = ZcashAddress::<N>::from_str(output.address).unwrap();
            transaction.parameters = transaction
                .parameters
                .add_transparent_output(&address, output.amount)
                .unwrap();
        }

        // Build Sapling Spends

        let mut test_tree = CommitmentTree::<Node>::new();
        let mut sapling_spend_key: Option<SaplingSpendingKey<N>> = None;
        for input in sapling_inputs {
            let mut cmu = [0u8; 32];
            cmu.copy_from_slice(&hex::decode(input.cmu).unwrap());
            cmu.reverse();

            let mut epk = [0u8; 32];
            epk.copy_from_slice(&hex::decode(input.epk).unwrap());
            epk.reverse();

            let (witness, anchor) = match input.witness {
                Some(witness_str) => {
                    let witness_vec = hex::decode(&witness_str).unwrap();
                    let witness = MerklePath::<Node>::from_slice(&witness_vec[..]).unwrap();

                    let mut f = FrRepr::default();
                    f.read_le(&hex::decode(input.anchor.unwrap()).unwrap()[..]).unwrap();
                    let anchor = Fr::from_repr(f).unwrap();

                    (witness, anchor)
                }
                None => {
                    // Generate note witness for testing purposes only.
                    // Real transactions require a stateful client to fetch witnesses/anchors from sapling tree state.
                    let extended_spend_key =
                        ZcashExtendedPrivateKey::<N>::from_str(input.extended_private_key).unwrap();
                    let full_viewing_key = extended_spend_key
                        .to_extended_public_key()
                        .to_extended_full_viewing_key()
                        .fvk
                        .to_bytes();
                    let ivk = FullViewingKey::<Bls12>::read(&full_viewing_key[..], &JUBJUB)
                        .unwrap()
                        .vk
                        .ivk();
                    let mut f = FrRepr::default();
                    f.read_le(&cmu[..]).unwrap();
                    let cmu_fr = Fr::from_repr(f).unwrap();

                    let enc_ciphertext = hex::decode(input.enc_ciphertext).unwrap();
                    let epk_point = edwards::Point::<Bls12, _>::read(&epk[..], &JUBJUB)
                        .unwrap()
                        .as_prime_order(&JUBJUB)
                        .unwrap();
                    let (note, _, _) =
                        try_sapling_note_decryption(&ivk.into(), &epk_point, &cmu_fr, &enc_ciphertext).unwrap();
                    test_tree.append(Node::new(note.cm(&JUBJUB).into_repr())).unwrap();

                    let incremental_witness = IncrementalWitness::<Node>::from_tree(&test_tree);
                    let anchor: Fr = incremental_witness.root().into();
                    (incremental_witness.path().unwrap(), anchor)
                }
            };

            // Add Sapling Spend

            let extended_private_key = ZcashExtendedPrivateKey::<N>::from_str(input.extended_private_key).unwrap();
            transaction.parameters = transaction
                .parameters
                .add_sapling_input(&extended_private_key, &cmu, &epk, input.enc_ciphertext, anchor, witness)
                .unwrap();

            let extended_spend_key = ZcashExtendedPrivateKey::<N>::from_str(input.extended_private_key).unwrap();
            sapling_spend_key = Some(extended_spend_key.to_extended_spending_key().expsk);
        }

        // Select Output Viewing Key

        let ovk = match &sapling_spend_key {
            None => None,
            // Get the ovk from the sapling extended spend key
            Some(spend_key) => Some(spend_key.ovk),
        };

        // Build Sapling outputs

        for output in sapling_outputs {
            let address = ZcashAddress::<N>::from_str(output.address).unwrap();
            transaction.parameters = transaction
                .parameters
                .add_sapling_output(ovk, &address, output.amount)
                .unwrap();
        }

        let mut proving_ctx = initialize_proving_context();
        let mut verifying_ctx = initialize_verifying_context();

        // Generate the sapling spends/outputs and do verification checks

        transaction
            .build_sapling_transaction(
                &mut proving_ctx,
                &mut verifying_ctx,
                spend_params,
                spend_vk,
                output_params,
                output_vk,
            )
            .unwrap();

        // Sign the transparent transaction inputs

        for input in inputs {
            transaction = transaction
                .sign(&ZcashPrivateKey::from_str(input.private_key).unwrap())
                .unwrap();
        }

        let signed_transaction = hex::encode(transaction.to_transaction_bytes().unwrap());
        let new_signed_transaction = hex::encode(
            ZcashTransaction::<N>::from_str(&signed_transaction)
                .unwrap()
                .to_transaction_bytes()
                .unwrap(),
        );

        assert_eq!(signed_transaction, new_signed_transaction);

        println!("signed transaction: {}", signed_transaction);
        // Note:
        // No check for expected raw transaction because sapling transactions have randomness
        // All output/spend descriptions and proofs are verified upon creation.
    }

    fn test_transaction<N: ZcashNetwork>(
        version: &str,
        lock_time: u32,
        expiry_height: u32,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        expected_signed_transaction: &str,
        expected_transaction_id: &str,
    ) {
        // Build raw transaction

        let parameters = ZcashTransactionParameters::<N>::new(version, lock_time, expiry_height).unwrap();
        let mut transaction = ZcashTransaction::<N>::new(&parameters).unwrap();

        // Add transparent inputs

        for input in &inputs {
            let private_key = ZcashPrivateKey::<N>::from_str(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();

            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = input.redeem_script.map(|script| hex::decode(script).unwrap());
            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());

            transaction.parameters = transaction
                .parameters
                .add_transparent_input(
                    transaction_id,
                    input.index,
                    Some(address),
                    input.utxo_amount,
                    redeem_script,
                    script_pub_key,
                    sequence,
                    input.sighash_code,
                )
                .unwrap();
        }

        // Add transparent outputs

        for output in outputs {
            let address = ZcashAddress::<N>::from_str(output.address).unwrap();
            transaction.parameters = transaction
                .parameters
                .add_transparent_output(&address, output.amount)
                .unwrap();
        }

        // Sign the transparent transaction inputs

        for input in inputs {
            transaction = transaction
                .sign(&ZcashPrivateKey::from_str(input.private_key).unwrap())
                .unwrap();
        }

        let signed_transaction = hex::encode(transaction.to_transaction_bytes().unwrap());
        let transaction_id = transaction.to_transaction_id().unwrap().to_string();

        assert_eq!(expected_signed_transaction, signed_transaction);
        assert_eq!(expected_transaction_id, transaction_id);
    }

    fn test_reconstructed_transaction<N: ZcashNetwork>(
        version: &str,
        lock_time: u32,
        expiry_height: u32,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        expected_signed_transaction: &str,
        expected_transaction_id: &str,
    ) {
        // Build raw transaction

        let parameters = ZcashTransactionParameters::<N>::new(version, lock_time, expiry_height).unwrap();
        let mut transaction = ZcashTransaction::<N>::new(&parameters).unwrap();

        // Add transparent inputs

        for input in &inputs {
            let private_key = ZcashPrivateKey::<N>::from_str(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();

            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = input.redeem_script.map(|script| hex::decode(script).unwrap());
            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());

            transaction.parameters = transaction
                .parameters
                .add_transparent_input(
                    transaction_id,
                    input.index,
                    Some(address),
                    input.utxo_amount,
                    redeem_script,
                    script_pub_key,
                    sequence,
                    input.sighash_code,
                )
                .unwrap();
        }

        // Add transparent outputs

        for output in outputs {
            let address = ZcashAddress::<N>::from_str(output.address).unwrap();
            transaction.parameters = transaction
                .parameters
                .add_transparent_output(&address, output.amount)
                .unwrap();
        }

        let unsigned_raw_transaction = hex::encode(&transaction.to_transaction_bytes().unwrap());

        let mut new_transaction = ZcashTransaction::<N>::from_str(&unsigned_raw_transaction).unwrap();

        // Sign the transparent transaction inputs of the transaction reconstructed from hex
        for input in inputs {
            let partial_signed_transaction = hex::encode(&new_transaction.to_transaction_bytes().unwrap());
            new_transaction = ZcashTransaction::<N>::from_str(&partial_signed_transaction).unwrap();

            let mut reverse_transaction_id = hex::decode(input.transaction_id).unwrap();
            reverse_transaction_id.reverse();
            let tx_input = transaction
                .parameters
                .transparent_inputs
                .iter()
                .cloned()
                .find(|tx_input| {
                    tx_input.outpoint.reverse_transaction_id == reverse_transaction_id
                        && tx_input.outpoint.index == input.index
                });

            if let Some(tx_input) = tx_input {
                new_transaction = new_transaction.update_outpoint(tx_input.outpoint);
                new_transaction = new_transaction
                    .sign(&ZcashPrivateKey::from_str(input.private_key).unwrap())
                    .unwrap();
            }
        }

        let new_signed_transaction = hex::encode(new_transaction.to_transaction_bytes().unwrap());
        let new_transaction_id = new_transaction.to_transaction_id().unwrap().to_string();

        assert_eq!(expected_signed_transaction, &new_signed_transaction);
        assert_eq!(expected_transaction_id, &new_transaction_id);
    }

    fn test_transparent_transactions<N: ZcashNetwork>(transparent_transactions: Vec<TransactionData>) {
        transparent_transactions.iter().for_each(|transaction| {
            let mut pruned_inputs = transaction.inputs.to_vec();
            pruned_inputs.retain(|input| input.transaction_id != "");

            let mut pruned_outputs = transaction.outputs.to_vec();
            pruned_outputs.retain(|output| output.address != "");

            test_transaction::<N>(
                transaction.version,
                transaction.lock_time,
                transaction.expiry_height,
                pruned_inputs,
                pruned_outputs,
                transaction.expected_signed_transaction,
                transaction.expected_transaction_id,
            );
        });
    }

    fn test_reconstructed_transparent_transactions<N: ZcashNetwork>(transparent_transactions: Vec<TransactionData>) {
        transparent_transactions.iter().for_each(|transaction| {
            let mut pruned_inputs = transaction.inputs.to_vec();
            pruned_inputs.retain(|input| input.transaction_id != "");

            let mut pruned_outputs = transaction.outputs.to_vec();
            pruned_outputs.retain(|output| output.address != "");

            test_reconstructed_transaction::<N>(
                transaction.version,
                transaction.lock_time,
                transaction.expiry_height,
                pruned_inputs,
                pruned_outputs,
                transaction.expected_signed_transaction,
                transaction.expected_transaction_id,
            );
        });
    }

    fn test_sapling_transactions<N: ZcashNetwork>(sapling_transactions: Vec<TransactionData>) {
        let (spend_params, spend_vk, output_params, output_vk) = load_sapling_parameters();

        sapling_transactions.iter().for_each(|transaction| {
            let mut pruned_inputs = transaction.inputs.to_vec();
            pruned_inputs.retain(|input| input.transaction_id != "");

            let mut pruned_outputs = transaction.outputs.to_vec();
            pruned_outputs.retain(|output| output.address != "");

            let mut pruned_sapling_inputs = transaction.sapling_inputs.to_vec();
            pruned_sapling_inputs.retain(|sapling_input| sapling_input.extended_private_key != "");

            let mut pruned_sapling_outputs = transaction.sapling_outputs.to_vec();
            pruned_sapling_outputs.retain(|sapling_output| sapling_output.address != "");

            test_sapling_transaction::<N>(
                transaction.version,
                transaction.lock_time,
                transaction.expiry_height,
                pruned_inputs,
                pruned_outputs,
                pruned_sapling_inputs,
                pruned_sapling_outputs,
                &spend_params,
                &spend_vk,
                &output_params,
                &output_vk,
            );
        });
    }

    mod test_transparent_transactions {
        use super::*;

        mod test_testnet_transparent_transactions {
            use super::*;
            type N = Testnet;

            /// Keys and addresses were generated randomly and test transactions were built using the zcash-cli
            const TESTNET_TRANSACTIONS: [TransactionData; 4] = [
                TransactionData {
                    version: "sapling",
                    lock_time: 307241,
                    expiry_height: 307272,
                    inputs: &[
                        Input {
                            private_key: "cUacGttX6uipjEPinJv2BHuax2VNNpHGrf3psRABxtuAddpxLep7",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "d9042195d9a1b65b2f1f79d68ceb1a5ea6459c9651a6ad4dc1f465824785c6a8",
                            index: 1,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(50000000)),
                            sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        }
                    ],
                    outputs: &[
                        Output {
                            address: "tmMVUvhGDFmCAUsXdeGLhftcPJzB8LQ7VrV",
                            amount: ZcashAmount(40000000)
                        },
                        Output {
                            address: "tmHQEbDidJm3t6RDp4Y5F8inXd84CqHwTDA",
                            amount: ZcashAmount(9999755)
                        }
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f8901a8c685478265f4c14dada651969c45a65e1aeb8cd6791f2f5bb6a1d9952104d9010000006b483045022100ef50a15eece0f43a0efd13a2c45aecf85e8e999858721150a70e75b106d80ea702202b3ff79fdcd2ff101dcacd74a7f6e3adb1250955f7a80962b259d1e17742f2f70121037e8e3a964e0f59c52633e25f9cec2fc8bb9af5b23eace85f6264f68b47db5cb6feffffff02005a6202000000001976a9148132712c3ff19f3a151234616777420a6d7ef22688ac8b959800000000001976a9145453e4698f02a38abdaa521cd1ff2dee6fac187188ac29b0040048b004000000000000000000000000",
                    expected_transaction_id: "c721c1643f30fc1f0a884b589de4537691c1d652966c8e81c8f67a5203537883",
                },
                TransactionData {
                    version: "sapling",
                    lock_time: 450000,
                    expiry_height: 579945,
                    inputs: &[
                        Input {
                            private_key: "cVasUuNrNZCnfe4VAdVS2LpyxCh7UmFpdowUx1K9h5JigZxcpX4W",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "ce03f10f794d2db649a365b2bd460fcdf45288a7d36c13d0526457432ab82131",
                            index: 12,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(1000000000)),
                            sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        }
                    ],
                    outputs: &[
                        Output {
                            address: "tmTyLLYAaPpK2nsqKArgchdXVGJ4zsB6CQZ",
                            amount: ZcashAmount(900000000)
                        },
                        Output {
                            address: "tmBmPifMLsmRkNyBg2u1FHFWMXquWqGpQ8G",
                            amount: ZcashAmount(50000000)
                        },
                        Output {
                            address: "tmDrbFH5RELCJnMTEaWMo9VF3YaBgqTEgX6",
                            amount: ZcashAmount(49900000)
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f89013121b82a43576452d0136cd3a78852f4cd0f46bdb265a349b62d4d790ff103ce0c0000006a47304402201e563ac13e9ae03b0c0f19313dfc5ef32d633adc46d0e2ecad6185b46961e37902207d33d054cfaf1f25149298bb12f5f9dd063034415ec4ee0bad71437f846b04e00121029862bf5d37725419b03e9e3db90f60060de42d187c5ed28bdb41ed435742bd51feffffff0300e9a435000000001976a914c847ac8eafe8ecfac934a41c37b2720ab266b8b688ac80f0fa02000000001976a91416837e1ef0b93ef72d9a2cc235e4d342b476d1d788ace069f902000000001976a9142d6f726f415eaf3e8b609bb0cdc451d4777c800d88acd0dd060069d908000000000000000000000000",
                    expected_transaction_id: "5827a6dc9d8bd37469c8fe8facf0d22c9908b36bf3575e13cd7b651fd7f411e5",
                },
                TransactionData {
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 285895,
                    inputs: &[
                        Input {
                            private_key: "cQJJZoXt3fhmv7FVNqQX7H4kpVrihX2g6Mh5KpPreuT7XTGuUWiD",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "1ec22e34540e8748a369272d858421ff607c2b7991a88e154b352a9f7acd9431",
                            index: 0,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(100000000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "tmL1qkaq3yedV1kbGommnx7tVNXQVpq4cNy",
                            amount: ZcashAmount(99000000)
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f89013194cd7a9f2a354b158ea891792b7c60ff2184852d2769a348870e54342ec21e000000006a47304402203b1f53d5f4c56e5120cd9574328f68c7403772db8eb26b75566a1499a8da1c5002205b22f8870c467d206494448f364b3f2f632e747563dbcc74ddcf27bb3c8033020121030cb32083e4b93572483ac4a3a39df5de63047973eb424b3f202bf0438e80b7bcffffffff01c09ee605000000001976a91471000dc3823178a6a14b0d41547f1a4163bb6fd488ac00000000c75c04000000000000000000000000",
                    expected_transaction_id: "5818676da1a9eab35fd66f25471662b1269f30e0850feae91d65bbd3c203fd32",
                },
                TransactionData {
                    version: "sapling",
                    lock_time: 500000,
                    expiry_height: 575098,
                    inputs: &[
                        Input {
                            private_key: "cNmWGcSzDEwWB9FJkvsP4rUzrFt6nNRBUdfV8Krv6hSeDnTSjwzx",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "77533bf33c0835d20820f46f3dd484feb7c813d33e87400ed3066b1dfbfa3442",
                            index: 0,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(100000000)),
                            sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                        Input {
                            private_key: "cMefZsn9zKu7XPW6sGk6jXicgKQmT9DUE4Hj3wKLKQRfadSdDcWr",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "e39029f7936131571772a60c5ba390f52449dd0665aa3c5f422747f813a7ea52",
                            index: 1,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(100000000)),
                            sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "tmP9PseY1RvxiLompZ6mUSM9CymBpEbvU6J",
                            amount: ZcashAmount(45000000)
                        },
                        Output {
                            address: "tmT1UteSdKa1jXBpsd7GLoaBy4RpSsNgcuQ",
                            amount: ZcashAmount(100000000)
                        },
                        Output {
                            address: "tmE63tsYgu7Yv2AFMKWJJTW737adHpxCk4q",
                            amount: ZcashAmount(23000000)
                        },
                        Output {
                            address: "tmKDzQrKDbPGeET81pM3v5y6M7CiijyoeEo",
                            amount: ZcashAmount(31000000)
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f89024234fafb1d6b06d30e40873ed313c8b7fe84d43d6ff42008d235083cf33b5377000000006a47304402204b631eb3a5f335b3de5693decc757164c711785d9e9260e997b290f6f2265f6402204bdb57d435d966645d42ae40ce58f88a28922063d365cf49b04ffafb959e338d012103d417fc48280160dbf89ea4e3c34b3d47c79bfc43cc211846c22b3538c267a082feffffff52eaa713f84727425f3caa6506dd4924f590a35b0ca6721757316193f72990e3010000006b483045022100f5b4368cbc84a548b48b15acc5589d93c9cc5032476b331f7fd14bf93c0176da02205b93f2439e5ca49e1a0af344d0654b0ec4b22783c31579bd52722a890a8b2ac401210335232f77fae42c4737ddd8d8c9df538767065aa17b9e6a388b6081d2893b9801feffffff0440a5ae02000000001976a914935628220a6e53fec7a6829a69b1139099a95ee688ac00e1f505000000001976a914bdb78536ed86bab756d96c227ff05a156d0994f188acc0f35e01000000001976a9142ffb196b33124bcbac37e85142e14db096202c4a88acc005d901000000001976a914685425f98a20f92e880b10de6e84416683a7010c88ac20a107007ac608000000000000000000000000",
                    expected_transaction_id: "e6f1f483061a611d5ed0529cffdfb43a47d34d9a201a7f21dfe73b9003477fc1",
                },
            ];

            #[test]
            fn test_testnet_transactions() {
                test_transparent_transactions::<N>(TESTNET_TRANSACTIONS.to_vec());
            }

            #[test]
            fn test_reconstructed_testnet_transactions() {
                test_reconstructed_transparent_transactions::<N>(TESTNET_TRANSACTIONS.to_vec());
            }
        }

        mod test_real_testnet_transparent_transactions {
            use super::*;
            type N = Testnet;

            const REAL_TESTNET_TRANSACTIONS: [TransactionData; 5] = [
                TransactionData {
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 499999999,
                    inputs: &[
                        Input {
                            private_key: "cVDVjUASqQn7qokRZqpHTdFpTEkwbpf7ZzhgTsqt79y9XWDyPod6",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "72a67442781a84eee2b327f9bb7030d725cf0fc90798aa51cb45a8acfd08c12d",
                            index: 0,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(20000000000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "tmNP9aZHniVeXmsMQxrN2pDJt4aCd6MGcYE",
                            amount: ZcashAmount(10000000000)
                        },
                        Output {
                            address: "tmVK7tKxTjnXdaEuDhyoAdZ1iViM2CrTQuV",
                            amount: ZcashAmount(9999900000)
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f89012dc108fdaca845cb51aa9807c90fcf25d73070bbf927b3e2ee841a784274a672000000006b483045022100a6255438be743890d53bf5a0818f58370361a0ff82f88dca30fba0aec1b2859b022055950c72f1111babcf01f58087300eb80e3acfff169d05338d8e2c7a0dd0b1fe012102386cb1f3211d689bcf9fd763381a4d7a9a0d719667c979ac485d6d2ec69a17e0ffffffff0200e40b54020000001976a9148af7ebff7dad3862258a44992915615bfd9e6d4388ac605d0a54020000001976a914d6fdb988e0ca149cb74eda244d8fc52481d6452088ac00000000ff64cd1d0000000000000000000000",
                    expected_transaction_id: "d74cf2f55f267dc4bacaacaa09e3317ac74265d860045a535a9e663fc99818bf",
                },
                TransactionData {
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 576566,
                    inputs: &[
                        Input {
                            private_key: "cTQpmkaF8YNivhZKw6PposeYz1FN9PxmW2r776rBKBWcAP8nA4bf",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "d74cf2f55f267dc4bacaacaa09e3317ac74265d860045a535a9e663fc99818bf",
                            index: 1,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(9999900000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "tmFgo8Damu8M6fKF5rJzZnkFMERMvo97sjT",
                            amount: ZcashAmount(3333266667)
                        },
                        Output {
                            address: "tmLTBB1na4qudp1TMDqzxr6dcE8dAQXJxrK",
                            amount: ZcashAmount(3333266667)
                        },
                        Output {
                            address: "tmLmTTRLwYAsMWJgKWVW14echT89pYztU7u",
                            amount: ZcashAmount(3333266666)
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f8901bf1898c93f669e5a535a0460d86542c77a31e309aaaccabac47d265ff5f24cd7010000006b4830450221009b69008f53a9970c2f5c771b76462773baf18a2937cbc70af4dad9d7987fd13e022038a3d14301c657172759885a5e2e65d5c10b3208e6120cb819d66f56fae3c09401210332d388288132f696b4a75b2d2f40ccbd9a463d32e3c6c335f671df33f1a05973ffffffff03eb9cadc6000000001976a914418574564a7c48387a6557c491d14da904a4306c88aceb9cadc6000000001976a91475caaa31ae391da8121fe8d9577c30710bafc7f988acea9cadc6000000001976a914793fbe8ff3bae86202ad600fd60b86f59981b0c988ac0000000036cc08000000000000000000000000",
                    expected_transaction_id: "22da774bc331dad798ffdf1a18b1ad984ce4255ed5f687fcd44e6609624727fc",
                },
                TransactionData {
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 576600,
                    inputs: &[
                        Input {
                            private_key: "cN2PtrZdZrZmoxgsg7fKcJPLGPX4sHDaZaNBsiRZQbQyC7kxAGxb",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "22da774bc331dad798ffdf1a18b1ad984ce4255ed5f687fcd44e6609624727fc",
                            index: 0,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(3333266667)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                        Input {
                            private_key: "cT9pKXC1KMMG6g8dsCUGEHj3J4xnxwfBEhyv1ALs6Z6Ly9XH4qvj",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "22da774bc331dad798ffdf1a18b1ad984ce4255ed5f687fcd44e6609624727fc",
                            index: 1,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(3333266667)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "tmLmTTRLwYAsMWJgKWVW14echT89pYztU7u",
                            amount: ZcashAmount(1666500000)
                        },
                        Output {
                            address: "tmAgmYQnL7fnHvBHJExK2oZXrJBnkRfcq5f",
                            amount: ZcashAmount(5000000000)
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f8902fc27476209664ed4fc87f6d55e25e44c98adb1181adfff98d7da31c34b77da22000000006b483045022100ea49efe4132ce18d039cb2abe99ea52163611c25a35a8640a4bb15a88c93b60402202f7d4334bccd8f961d1becfd08bccdc1c0669533810cbbbfa5837f99ba94a7fe0121024aed9637c78499154afc06af10b2344233b3c968f1e7b1cfd9905fc38e440c12fffffffffc27476209664ed4fc87f6d55e25e44c98adb1181adfff98d7da31c34b77da22010000006a47304402203576c518c1f628469efcd182fa7d1d578cccdf7b51a41e44d119ca0c010747cc022069d9f390735567efff5e8f70afec6595060a79693540d6174b21681b21b4df70012102e49919f81e1fc11a65283e71dcce22dc65271f4ab6ef96f9e9b3d20fd62d1e87ffffffff02a0c55463000000001976a914793fbe8ff3bae86202ad600fd60b86f59981b0c988ac00f2052a010000001976a9140aab8113729e010d852820561dbee87459ad8dc888ac0000000058cc08000000000000000000000000",
                    expected_transaction_id: "19a785b82a42c160ad954183ec3e8831b0c624c16d82408e293a4353a033c58a",
                },
                TransactionData {
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 576600,
                    inputs: &[
                        Input {
                            private_key: "cR6NQzn89sCdRj1WmgQxF4mGJWi4bbgqzTDpmSfhmMQ2tfJCTPDF",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "d74cf2f55f267dc4bacaacaa09e3317ac74265d860045a535a9e663fc99818bf",
                            index: 0,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(10000000000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                        Input {
                            private_key: "cUSFcxAXwFkLVciaxm7Le3mZF3g1nX5MZsxwDs23sCwWgUekfd18",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "22da774bc331dad798ffdf1a18b1ad984ce4255ed5f687fcd44e6609624727fc",
                            index: 2,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(3333266666)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                        Input {
                            private_key: "cUSFcxAXwFkLVciaxm7Le3mZF3g1nX5MZsxwDs23sCwWgUekfd18",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "19a785b82a42c160ad954183ec3e8831b0c624c16d82408e293a4353a033c58a",
                            index: 0,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(1666500000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                        Input {
                            private_key: "cMjLTdEgp48viTAL5eFXxaEpdj7jBJAg8ehw114BjBiZdUbCJLCr",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "19a785b82a42c160ad954183ec3e8831b0c624c16d82408e293a4353a033c58a",
                            index: 1,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(5000000000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "tmFCcsdkr247okCfD61PBpzkP1GmkS7Zk6h",
                            amount: ZcashAmount(19999500000)
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f8904bf1898c93f669e5a535a0460d86542c77a31e309aaaccabac47d265ff5f24cd7000000006a47304402203f44fdfa0abb604a0b123fc95b4b0ad97bf535c9b2f9c2e37440a5627eabc6b902206c533152ba2efd78c16136f108847d8ea60e571f4dd7cbb47a5df582011cb3920121037517903ed1fafb50ab557970fc2d1948eaf88ad807308cc1fd50a63ca5f2d4d9fffffffffc27476209664ed4fc87f6d55e25e44c98adb1181adfff98d7da31c34b77da22020000006b48304502210089fe440a2b97bd12ad09c21cf4b3c811cddd17917fb5f4b84ec3fafa3c8ce26b022029e1bc2385d291eef1591775a73a77c5891afcfcf020a58c4fa35fb7d2995d280121020ef8f4c3fe101f3f47900c30423aeabfda7d502050c7067292afa5d971205b40ffffffff8ac533a053433a298e40826dc124c6b031883eec834195ad60c1422ab885a719000000006b483045022100d3c08145d11226c24acba293943f649b6acced719eaba5eee168705faa060046022077a220546a4654ee8bf14217da8c5dae9c64160b424be83557b24b79fb7b22400121020ef8f4c3fe101f3f47900c30423aeabfda7d502050c7067292afa5d971205b40ffffffff8ac533a053433a298e40826dc124c6b031883eec834195ad60c1422ab885a719010000006b483045022100a2649c5a237ac25db15ada343ea331865b9544a5ac32752c7800d3296085665602206c1722f0a3b0533f047e06ec2931fbe9dc9f6c01f4f1391fa02421369f8e4952012103b485498fb0843a5a058f251d7094fe8d2878faba8c17e7b3bbf854adb855a377ffffffff01e02610a8040000001976a9143c314002f07cf5ff5c84da1d9b456671b915bf8588ac0000000058cc08000000000000000000000000",
                    expected_transaction_id: "fb6b95e4b3f7d1125fe81f4235dd156b12fb1553fc204fd22b4db200e54ddb5c",
                },
                TransactionData {
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 499999999,
                    inputs: &[
                        Input {
                            private_key: "cRi5RmG4fRjydFToBr1Z1FgD3jhCdmrsLs7WHn46ZVstPrKzwVHS",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "fb6b95e4b3f7d1125fe81f4235dd156b12fb1553fc204fd22b4db200e54ddb5c",
                            index: 0,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(19999500000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "tmXYJ4cPwLTNYgs6y9tZxJJNC9sBiNDto7e",
                            amount: ZcashAmount(1000010000)
                        },
                        Output {
                            address: "tmEJE9sBgQfm2g3qXk4tZoWbhLkJmfxf6y7",
                            amount: ZcashAmount(1000010000)
                        },
                        Output {
                            address: "tmAuJ3R6tmb3mb8n1ps9DTNHatgYagaZpMd",
                            amount: ZcashAmount(1000010000)
                        },
                        Output {
                            address: "tmQQSuLgnnymA1FEo81Z32ng8JDu9q7zEnh",
                            amount: ZcashAmount(1000010000)
                        },
                        Output {
                            address: "tmEQbGRRVoFWFRqdPE7qCJXgeWBWV5vmcyF",
                            amount: ZcashAmount(15999450000)
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f89015cdb4de500b24d2bd24f20fc5315fb126b15dd35421fe85f12d1f7b3e4956bfb000000006b483045022100e0095db90aca41ff28eea19d9e7e99a776e31b842d8bebf16856313153e2ac5c02205c4842046b790f45a3cdb12cc57e0a32539df8108f2f0849d19c037b69fce44101210324518c52cb40b86c8e8ed345c434af290835b18dc9ac6e1e060c86d040ee9a5cffffffff0510f19a3b000000001976a914ef6be120406ad9306214d50dca65604d20c6377c88ac10f19a3b000000001976a9143248a77a3b917a2aec9f9f2c4da147ec0abf61af88ac10f19a3b000000001976a9140d09f4b898d3f87efb7c17d20e48d78cdff9fd8288ac10f19a3b000000001976a914a1270cf4c1141c65312bcc4c0c1d681d389405be88ac903ba4b9030000001976a914337cc6354d31515f291b90a9a01b4911aecda5a788ac00000000ff64cd1d0000000000000000000000",
                    expected_transaction_id: "35562b33fe8d03e0dcd9a2dd62154f3abdfcd7d29d61dcff0a09c1eb18a8f7ea",
                },
            ];

            #[test]
            fn test_real_testnet_transactions() {
                test_transparent_transactions::<N>(REAL_TESTNET_TRANSACTIONS.to_vec());
            }

            #[test]
            fn test_real_reconstructed_testnet_transactions() {
                test_reconstructed_transparent_transactions::<N>(REAL_TESTNET_TRANSACTIONS.to_vec());
            }
        }

        mod test_mainnet_transparent_transactions {
            use super::*;
            type N = Mainnet;

            /// Keys and addresses were generated randomly and test transactions were built using the zcash-cli
            const MAINNET_TRANSACTIONS: [TransactionData; 4] = [
                TransactionData {
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 0,
                    inputs: &[
                        Input {
                            private_key: "KwbK8JibyGAKz7h7uXAmW2hmM68SDGZenurVMKvUMoH5n97dEekL",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "1097b2e1ffbaf193ec0123c0d20b0e217f77250446485e3e9af906f314a01055",
                            index: 0,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(101000000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "t1S5TMtjLu73QwjMkYDwa67B39qqneqq4yY",
                            amount: ZcashAmount(100000000)
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f89015510a014f306f99a3e5e48460425777f210e0bd2c02301ec93f1baffe1b29710000000006a47304402207c2e6d5ec25a8ab67229f23a581ee8898eb087c2aa6c8db8acf21c3b96bab5fb02202ff7689945891a20961de1b4e18b40995fe7f07cb6dd1c97607c65259adeb1bd012102a7b8361f36eee68b96cbc72bab73295494161b8e670a29c99819e2b793939d25ffffffff0100e1f505000000001976a91459fec7e62fcf3e580656bc1bc6c220dad37709ab88ac00000000000000000000000000000000000000",
                    expected_transaction_id: "15315d7b5a852c7e3b8090fe08285a471bec73806b0c194538b61af2623c3c84",
                },
                TransactionData {
                    version: "sapling",
                    lock_time: 456789,
                    expiry_height: 600000,
                    inputs: &[
                        Input {
                            private_key: "KyWLtuy5hiPejU1muc2ENTQ6U6WVueWErEYtye96oeB9QrPZMj1t",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "f234d95b8313c7f8534e3dd3cc0549b307759ec3909626920c129e493ac84f39",
                            index: 0,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(200010000)),
                            sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "t1bq98GbMv8wbjkEQqQkMxiHi7Qefb67jXr",
                            amount: ZcashAmount(50000000)
                        },
                        Output {
                            address: "t1MkLsaPmTuc8XQjLENxppkCFUkCtTRCsZZ",
                            amount: ZcashAmount(50000000)
                        },
                        Output {
                            address: "t1KvUTiJ8LJeFygnzNFigUCpiUqak7Yzbqq",
                            amount: ZcashAmount(50000000)
                        },
                        Output {
                            address: "t1QNGuoLLkYXDfCFJUGGajQugMCUGRxbAvn",
                            amount: ZcashAmount(50000000)
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f8901394fc83a499e120c92269690c39e7507b34905ccd33d4e53f8c713835bd934f2000000006a473044022053637ac8ece0fd2c5cd2fa2c6abb6fec36317a7e60be6c5215ff83ab903409a502206cdcb354b7bca6a4aed08fc6409a6e0000ba263c47f6bb22ab74ad2fe270250501210325c97e86e09f91a9894b856c9b9ca6d7ea90754d66acc95fb57b46117492d3bdfeffffff0480f0fa02000000001976a914c4fafe5725a6ec3d2218458c00da884cd9a0507c88ac80f0fa02000000001976a9142a80f5573b12de286ecbe0f8d46acb9c2334375588ac80f0fa02000000001976a914167b3376103f458ea847ec6f5e763b0de2808f3e88ac80f0fa02000000001976a914473ce0a50b7a876fcba71973b49770b79cfb10b188ac55f80600c02709000000000000000000000000",
                    expected_transaction_id: "1754446d92cb41fcf88c44ac7286d2b752904a7e38ee921b082bceaa98910d08",
                },
                TransactionData {
                    version: "sapling",
                    lock_time: 456789,
                    expiry_height: 0,
                    inputs: &[
                        Input {
                            private_key: "KyXn7mdxMm4GC2BLPopZTjkSp17P86vvDh25enpDRcma6vUnicCk",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "ffb595919dd6a431bc74948317cd56be39802b6a2c9a9f0d08606c7b01edb250",
                            index: 1,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(500000000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                        Input {
                            private_key: "KwY2f9ohrQoHv39dat6hdBnprxtD165dikuW21nExQVhY7KU2VHW",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "466351234fb03d3c09c501194f778342314307e923fc7cd6eec9e3fc581a9474",
                            index: 2,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(500000000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                        Input {
                            private_key: "L1CTbTh1npyZLjVdpfc2uYwW4mwRD549KGAY8d3RP2Fbk38Kryh4",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "2ed71a12ed95aa64c1812c5bbaceddfc706054dc439d206b42c191a5f790305d",
                            index: 3,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(10000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "t1YEmnC2MMFnsAFQwiijeJYeEy4Hui8ZFju",
                            amount: ZcashAmount(1000000000)
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f890350b2ed017b6c60080d9f9a2c6a2b8039be56cd17839474bc31a4d69d9195b5ff010000006b483045022100adcab54a2e437df28eebf4c19f33061467d951a035f12125d3ba16dc3a7ed21c02204a13ba64160a5a11fb22ada860202995df5f51f05eb882fc197109fba298b96e012103f632eeb38fa2fcc7af1881f1b6c1f4fe6155ee6267d92657d9a95fdbb15c010effffffff74941a58fce3c9eed67cfc23e90743314283774f1901c5093c3db04f23516346020000006b483045022100a14d25f96742b6a06f201db6811ed1bbbeab80be29ea45ad8e54ce583337056502200e04272216609ca7cf38729156c860e59a1e88632697456fb0639efebc6509bd0121026fba2e786f9351532a8f93de404d0c44b54e01a7f10bf1a61f734bc4249b58f9ffffffff5d3090f7a591c1426b209d43dc546070fcddceba5b2c81c164aa95ed121ad72e030000006a473044022005e9df51bedd7f95d567ef472040fb295f7dc7d742e1a894d48f67f5239fd860022076d170cb5be8435628c738f0beecbeb85fc6fb1f8f74d5dd18db0fdc584df6650121020621d94a64caf7183bef70f89cfca4cd3d30a76ce0335f7f10eb787e266bb2cdffffffff0100ca9a3b000000001976a9149d92a791abc62a9ca93ced9086c2129d31757ee088ac55f80600000000000000000000000000000000",
                    expected_transaction_id: "7cea93d9eb01f99c395648f3f10e814986d381c4ebd5e3a03562fe904c39c633",
                },
                TransactionData {
                    version: "sapling",
                    lock_time: 584789,
                    expiry_height: 710482,
                    inputs: &[
                        Input {
                            private_key: "KxN4JLuVGg7A64gCrKxg2aiH1vsq3QGUhgXnARrsiqQpWFFdv7bU",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "0f4b24007bdf5eb11c1e62f186ef3478d70e46453ba06ae290ea323959af380d",
                            index: 1,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(360100000)), //3.601
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "t1JfgVaB5JXx7dQ8gvJzoQH6ng975V1B25G",
                            amount: ZcashAmount(10000000)
                        },
                        Output {
                            address: "t1MsywTe4TT3QtLjV6CwS1Y4Q1WSBE6vaPS",
                            amount: ZcashAmount(20000000)
                        },
                        Output {
                            address: "t1cx5apduMvoVGYxPkkM3ygsZv8uVHxdn7C",
                            amount: ZcashAmount(30000000)
                        },
                        Output {
                            address: "t1JMFpgce1Tex6jHMmJcUHVWZB57KGezWby",
                            amount: ZcashAmount(40000000)
                        },
                        Output {
                            address: "t1MPCPc6KGbC2shZauK1J7wAitkeLK7SVYU",
                            amount: ZcashAmount(50000000)
                        },
                        Output {
                            address: "t1g1VEHW9Z69acSHwxcr2tQgmUnV8kX5Kat",
                            amount: ZcashAmount(60000000)
                        },
                        Output {
                            address: "t1PqYvqKND2ex5rB1BaVQ1MzWumxV9qzhLz",
                            amount: ZcashAmount(70000000)
                        },
                        Output {
                            address: "t1JQKfrVZtFVBw6vQ1sSxCp7AbHjBfRrVVc",
                            amount: ZcashAmount(80000000)
                        }
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[],
                    expected_signed_transaction: "0400008085202f89010d38af593932ea90e26aa03b45460ed77834ef86f1621e1cb15edf7b00244b0f010000006b4830450221008092fa7e36ee33d24e4325d94d2edc79094a2cc7ee9b5a9b927327eaedeba8b10220221452eab944f6c11ea7c3db4737acec9bc7db2a0bb0a3c90e2c96a5cae40bd00121026c6b54c8303dedb35591698afa9fbc5501763c5a18341d1e7c0a2b68148c69bcffffffff0880969800000000001976a91408b6e1325af5b5017f0dab34965540fac91d3b2788ac002d3101000000001976a9142bf2cfe165f273fbf3e323c4c694769ad24afc9388ac80c3c901000000001976a914d14312fbd36be1b32a1461634694cc7ebe81bb6288ac005a6202000000001976a914053acc6851cc71df9715c68b7ca93e1ad6007c5288ac80f0fa02000000001976a9142681247d3de732e1867edfc085cc4197334c785188ac00879303000000001976a914f2d0702165e099a7cde104b3e3a963b0f79c7b2e88ac801d2c04000000001976a914416d5a8d0daa988ebf0f415bc35a41d74751d95788ac00b4c404000000001976a91405cf42203276331ca0b5b121730c89273cb1e5fc88ac55ec080052d70a000000000000000000000000",
                    expected_transaction_id: "dcf9242265a11313839a73409d768784ef034d9788255a93abc39a7e6acd648b",
                },
            ];

            #[test]
            fn test_mainnet_transactions() {
                test_transparent_transactions::<N>(MAINNET_TRANSACTIONS.to_vec());
            }

            #[test]
            fn test_reconstructed_mainnet_transactions() {
                test_reconstructed_transparent_transactions::<N>(MAINNET_TRANSACTIONS.to_vec());
            }
        }
    }

    mod test_sapling_transactions {
        use super::*;

        mod test_testnet_sapling_spend_transactions {
            use super::*;
            type N = Testnet;

            const TESTNET_SAPLING_SPEND_TRANSACTIONS: [TransactionData; 1] = [
                TransactionData {
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 499999999,
                    inputs: &[],
                    outputs: &[
                        Output {
                            address: "tmKXdkNCRxZ8Ha6voL4MVByBRkCPez5ak6Z",
                            amount: ZcashAmount(499960000)
                        },
                    ],
                    sapling_inputs: &[
                        SaplingInput {
                            extended_private_key: "secret-extended-key-test1qwq6zxvfqsqqpqzn4hxmcv7d9whwepfpx72aahddkf073x2cwr6fwar0p2ns4xkcu73xgs2pnxgux2nfx8a5nt2w7tm49ptnq9v3z4qncjlk8er7q27qewhcul9xtlxjqe56jyspamlhh8r4glmva2zxvkuejw8ypsfp5lsgc564r6g5w068kqlrcy0s0wnu0382tv2eqnlart5gjczwa0l72qgtaa794dqpva62206wwvemvath3t2f5j6x9nlvsgus0wavrvwavucculeth",
                            cmu: "40d9712ba3dd9787a0451462e4fdda07929305b06248dd8aaeabdce13985b576",
                            epk: "8dca2796416d9ab8409e40e3b3839eb28b5765ba9b7dcfb2c267ac54b85fc6be",
                            enc_ciphertext: "d259f0cb859e6bc1b92590600f2a5d9b3464c7c568c96926fb97b2ffcecd7f9c8bfb878e3650cf30378ec222797787ab2c354589cda6da227c9b72945751827857823848a03bddeef13ecc14570291ee6638da600e0f91ca0348a6146b9f176b60f053a7f4bd94f5d9c669e8958b3d03c2fd456caa4703ec1ffcf75759ffaf098502295c7eadbdab928e77740220339611c4c977b0185627f2ac6db5c0fca6c1d6a89f0ba6503f6d520e6814f0f592bc950023395b2907e39067242a87d74dc535a7decf37c4530b1b5f375cd588949cc9948c409ad3b7bf1bd6a307d076b34a1c93c330f7a42df419ef95965e747b43306f277255cc2fe4b7f4ec3e6ca06f7161ac4a89b703b2b99b201d3a2279b45d60b0f899931afc45a6be5496df192abade2039403132711d899bc8e02700d2f9cf225ca7de9b4c9e3899c9e63eb669e4b626006797ad61247bef423b27ad4e2d472c648420ac88d9f03abc9132d360b1e634684bb73eb251495f3c34a5ab6f73436b2b58e5fb89a5e41692ceea8f04d19b2dd76a796bda2d99f95b5aca03a750acb50f44924f7fea953fe33316255da6c5cadb80687875bc63b2865d79010a3d845d9bc1836a2726d3040ed05fe403f30a51597f8921e3c0c4544d1aab8d67a382410ce377654e79e27e9ff81bd8264d5fbd4e5915a7fa804424cc65ff19ca4d4dd0f3fb34585d18b75f6c39d99cc48e800bab6fa2324340922f62273fe371f2d725567fae988579a00bf7bc3b911cf03746cf47286f05d24c64c38f829d0d40a34799151176057cfe49d6b9fc6b9d983612d75d",
                            anchor: None,
                            witness: None,
                        },
                    ],
                    sapling_outputs: &[],
                    expected_signed_transaction: "",
                    expected_transaction_id: "",
                },
            ];

            #[test]
            fn test_sapling_spend_transactions() {
                test_sapling_transactions::<N>(TESTNET_SAPLING_SPEND_TRANSACTIONS.to_vec());
            }
        }

        mod test_real_testnet_sapling_spend_transactions {
            use super::*;
            type N = Testnet;

            const REAL_TESTNET_SAPLING_SPEND_TRANSACTIONS: [TransactionData; 3] = [
                TransactionData { // txid: 6a25dbdbb4da6f8ff115d44aad9519be23e17e8322244ed61160d02a9249eca2
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 499999999,
                    inputs: &[],
                    outputs: &[
                        Output {
                            address: "tmEn21pZv4FTPfXinSNfdtQyDVhnkRz9T7q",
                            amount: ZcashAmount(999980000)
                        },
                    ],
                    sapling_inputs: &[
                        SaplingInput {
                            extended_private_key: "secret-extended-key-test1qwq6zxvfqcqqpqx9yxfvz024pygvsyc5mk3tvx90c9xyvc8660xk9q3954rmdngzhsdms6h8mdwgmwgct0degp3x5aeruddxpxwg3c3gy4krptv47w2q6790n88h8uztvxzxjd9ndz4yx80vm8mqqjj73m5gyzz3edmnlxgp0y642f36dv3xl30pm7fetducd0rfcpg8nq9nuj5pxtlu35p946yk5nwa6gdzc5v4w7dpwzmdszqudq6ecn0esryntk9vly0fkh53grsnjunxl",
                            cmu: "6bea0e40d62442443a3475b3486b3b230e6f3895f6ec931bdcf378ab72e1f7b8",
                            epk: "bdfe7b1a08c3a43f8357be258d10ddbaf4f6ed58d99ba94184d4536b1ae7daac",
                            enc_ciphertext: "c8af78c4b420366f686c450c0652d28d0955c0bf26380d7cfd81501864b806ef868f1b5ec6d7ac2eb1809299074498a101ef370389129b90c7b10207a685148743b3c4f083538c62a33199ccf65d1987a73d5cf293a5691b4d57aba2b95d4c67c6d0001d4741bba826cd9c1f1695700146dcd65f4e61cc2b1dd96f03046c8c334d036c8f43d3d15c7f58c39dd35ecb2b34189710489c5aa0fa02d64f1d6d76014e6862be2e741025bd7f11f99a65518da4340854daa54b4719ed3716f3f409e7821e7cf973f2adeebc229458da60007b97c006398a0da0e5cf6753c44533e1fc97850705dbfd6cd68f1b618faf7e0b29c2c03ab3c8c7015db095e4ffcbb3be8e2a2fde2a40c7570e54cecc02348706251ff0ed88513051b9886b8a0d9681c2713f2d2162ef93c7c81c3cbc7e9a9685388c8690397b53ab217b048d22f5c9c019cce142eaef9f330ec5239dc4f61c0eafdb10bd4679e52a2863969c5cd6172f893a2a6e4af31c4b73456d339b127ca3e98595da3599f1a00c6804363e4b1d393f925d0f3eaa79e03d96411139fb024bbc2587334bb04f447f074e50639c627fd665d59253a261779ce5de22d678ceaad9a3e20078346d17bc6ca294df1ef3bfe239bbb1bb33bb34f6701874d48dab94c5649577aff9b98fa0f69adee522868da0cd31cd744f31b6f01d1701d36ae50af38a653651ce85dd432d90fbce2cdd06c69d644fdab912b89c7c69a7c19b95442c0ea62de16ad88ade0130c84ebead2ff99fe12bd686bbba322f9ff61531341513f6a4b51fa65c47cb45dd5cdeb85f0b9abf8f68a3",
                            anchor: Some("a4c8ea36def54b535c93a3d3d61daa5fbd04968b79ae3a518d2f1a097fcfe52d"),
                            witness: Some("2020b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c538142012935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d20e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef722028e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a20a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a20d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb582016d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a20fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712204c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850200769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c492008eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023208d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673206aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b15921620cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00206edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c201f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d3920d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f20bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c201b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab6512045e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a20c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc52720ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce7220bac21af2f8b1eba9d2eed719a3108efaa19b44386f2dd38212294253e6fa1102207b99abdc3730991cc9274727d7d82d28cb794edbc7034b4f0053ff7c4b680444204484e8faa977ac6a7372dfa525d10868666d9b8c8b06e95df0594bc33f5f7b5620b9e8757b6d27fcfd9adc914558e9bf055e125f610fd6170072b4778fa0c4f90b20db4ea7c2d058649c99ba7a9c700db7dfc53a2c14a4dd2a20dad9d35294b61559207ffb9317c7941ebc524eaceb48316ecdf9cdf39d190ab12c16836f885a0ab24820d8283386ef2ef07ebdbb4383c12a739a953a4d6e0d6fb1139a4036d693bfbb6c201a0564d96a7d7b6beb993318e8de10c44bb6eb0d91c674a8c04b0a15ccb33c7020bc540156b432138ebd0ab33dd371ee22ed7f5d3f987af37de468a7f74c055f5c2021cac521ca62e3b84381d8303660a7ca9fa99af47ee7080ea7f35f48c865b065f71a010000000000"),
                        },
                    ],
                    sapling_outputs: &[],
                    expected_signed_transaction: "",
                    expected_transaction_id: "",
                },
                TransactionData { // txid: 1733902a65cf474339693642f2afed279d2f60f78cff1528d5e2a79179cede8a
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 499999999,
                    inputs: &[],
                    outputs: &[],
                    sapling_inputs: &[
                        SaplingInput {
                            extended_private_key: "secret-extended-key-test1qwq6zxvfqsqqpqzn4hxmcv7d9whwepfpx72aahddkf073x2cwr6fwar0p2ns4xkcu73xgs2pnxgux2nfx8a5nt2w7tm49ptnq9v3z4qncjlk8er7q27qewhcul9xtlxjqe56jyspamlhh8r4glmva2zxvkuejw8ypsfp5lsgc564r6g5w068kqlrcy0s0wnu0382tv2eqnlart5gjczwa0l72qgtaa794dqpva62206wwvemvath3t2f5j6x9nlvsgus0wavrvwavucculeth",
                            cmu: "40d9712ba3dd9787a0451462e4fdda07929305b06248dd8aaeabdce13985b576",
                            epk: "8dca2796416d9ab8409e40e3b3839eb28b5765ba9b7dcfb2c267ac54b85fc6be",
                            enc_ciphertext: "d259f0cb859e6bc1b92590600f2a5d9b3464c7c568c96926fb97b2ffcecd7f9c8bfb878e3650cf30378ec222797787ab2c354589cda6da227c9b72945751827857823848a03bddeef13ecc14570291ee6638da600e0f91ca0348a6146b9f176b60f053a7f4bd94f5d9c669e8958b3d03c2fd456caa4703ec1ffcf75759ffaf098502295c7eadbdab928e77740220339611c4c977b0185627f2ac6db5c0fca6c1d6a89f0ba6503f6d520e6814f0f592bc950023395b2907e39067242a87d74dc535a7decf37c4530b1b5f375cd588949cc9948c409ad3b7bf1bd6a307d076b34a1c93c330f7a42df419ef95965e747b43306f277255cc2fe4b7f4ec3e6ca06f7161ac4a89b703b2b99b201d3a2279b45d60b0f899931afc45a6be5496df192abade2039403132711d899bc8e02700d2f9cf225ca7de9b4c9e3899c9e63eb669e4b626006797ad61247bef423b27ad4e2d472c648420ac88d9f03abc9132d360b1e634684bb73eb251495f3c34a5ab6f73436b2b58e5fb89a5e41692ceea8f04d19b2dd76a796bda2d99f95b5aca03a750acb50f44924f7fea953fe33316255da6c5cadb80687875bc63b2865d79010a3d845d9bc1836a2726d3040ed05fe403f30a51597f8921e3c0c4544d1aab8d67a382410ce377654e79e27e9ff81bd8264d5fbd4e5915a7fa804424cc65ff19ca4d4dd0f3fb34585d18b75f6c39d99cc48e800bab6fa2324340922f62273fe371f2d725567fae988579a00bf7bc3b911cf03746cf47286f05d24c64c38f829d0d40a34799151176057cfe49d6b9fc6b9d983612d75d",
                            anchor: Some("a9cea23799a2a99a4f141bb997ea1698fa2f45fc3ac3916aaa1982ea2326ee48"),
                            witness: Some("2020b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c538142012935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d20e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef722028e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a20a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a20d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb582016d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a20fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712204c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850200769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c492008eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023208d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673206aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b15921620cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00206edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c201f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d3920d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f20bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c201b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab6512045e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a20c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc52720ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce72206a963be7305e1bd7e01f031baeed91551fec981609a52e8346c4f58e4b58214c2038cbc4cb015400c0436372d5583297ff9c1a3b2f7c99348afe44535cb3bdb33e2073de2ff5ca8ff6e2ffdf5861de3e669da231490093e6fb85486c7d4f04af664120c525cc77cac8a206aec5bdcbf2f02e9bf692a71b837b5956d14a447b936a8d06206e7f74f94b4c1bbd1e3a389730fe67f65d99cdbebd9a5dda0fd8a6babf0b1d0c20918ec10271032b8f755de870cde81da73b931f4641087d3a3e010ffab3468a4d203632627cc328c6f53f4b2edd3463e6aa7e3989ee714680ce7e415223ef8c8f3120e94edebe993a74cab0a49c6c6b2ac2538f97342faff86a24136c0ac1bd57253620bde37373a13118f8e504812bdb3a60ffbfa3da31e20fc3e1545041828f14d6132075a1481793b3a67864fa65adb30840dd4369899b3d4756fa268ba45cca2f0d2cef19010000000000"),
                        },
                    ],
                    sapling_outputs: &[
                        Output {
                            address: "ztestsapling1ml8v92nfl07t7tsncwf9x0upqgncljpcrs3c53esgjupkagfffk98ngwhdqcw5pc8v4r2wmx0lk",
                            amount: ZcashAmount(249980000)
                        },
                        Output {
                            address: "ztestsapling1nnx9cu3u0jy2zwwru2u4mpffkdtkw5r2er399xwlpj5d340znfufdl0l8ec2ag94zgur54hlmn8",
                            amount: ZcashAmount(249980000)
                        },
                    ],
                    expected_signed_transaction: "",
                    expected_transaction_id: "",
                },
                TransactionData { // txid: a333b3523cab6def651813ea76e885b964c0c0c0ba20ea2ea98664e85ea4b9b5
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 499999999,
                    inputs: &[],
                    outputs: &[],
                    sapling_inputs: &[
                        SaplingInput {
                            extended_private_key: "secret-extended-key-test1qwq6zxvfquqqpqprdealqmnm5u8udxapgt5twpvwcnaam2u8ycff2c094ucu9fcf86vhtnvjj8d4g2g499qnnrqqt4q9untr4pf44n9k57hnzjdptggqs7hy3emfgrflahl72jfx2uvkzvmeukxhh2kye8pcnzm55pdvpusf79ujph6c0pupn9ty090xsx8r57jqv3aqk2x7kfgzmmlh26d5npuyaz45gjusx9h5w2d3nflk0na6vnk08dvv5p7rz75yw966u83pg7gw8r82v",
                            cmu: "6dc0792cd8cf8fb71229ec522862539b7e9f3f53acbb2cedcc1b21ea1bcfac91",
                            epk: "669a7bcdc0d9906a1c4101008b2557896d85a496e63359b350e9773c640d18e6",
                            enc_ciphertext: "c41762618b4e50a94d1f6c19d3d9a62fdc2add170702fd8004b17cad3c0fd2855d8f86db5c740e91d4b831e945f4d510eaa11cc6d80cb0c5f7c7e5391cf9d940f06054b7e24255c02e81d63ceaaa37c4c8236e9ebe546819316806bdc1ce60fb1862274811bd8248d5b0d4cbf6027bb5765b4e3d3558e8dd6b42790e53000f229a5cdb031d9ded5fec16231a208be48b149db04606e3fcec0164d8c4ea6dcd9c56140e3ae1bfa6a649db730f80119928901fbb6a1b018831650fbebb2fc8169e46a07dffdb09f070da9db4b41f929bf6949f70465087337421af2242ae7fe12f295dc1017cffaed9aa03e094971489230e90a3feb86235f89508cd4ef16637d443d72f88f9894de9b4fa6597127d7ab6526572b1283a357ffdd586b0944b42cbb579c8aeb50f0c371995fcb89d83069d533967d0563e9de74a600d3cf774a182d16727f66a9c62db38debc70f7327e7e1d6d4e3edadd8d1cae7e2af52fb72c499d91d416b970b3dc8b233a3e915937f5fd2bf1f782a5045ab825a13594543bd50cf6c99dd49a42c7aabf5e4b5178067dd8f5bc10e7d8ca400f045cba9cb5ed39cd3f3d389c7cb06de3de636fcae6954be389194aee12b4852031c1a2a56f91b0348850291c3581463186e1d1c36e2752ef0f8c87455397e1d6f6b5c8294eda53a7fabe495bcbfe921c9f973187ac91217366f53361912a2f2e9c987c04ed8aaff9b0d1948f60f24429233b66b2fa7e212a88af0093a586e199cc7b24cdf38f290f659ccbfcf509101f2755a32b995333648287adba3efbf44662d0566fe1d5235b5e3c69",
                            anchor: Some("b14aacb3c78e036f924078f0231a211cc0c169fcea96af813fe059f975cc2c06"),
                            witness: Some("2020b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c538142012935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d20e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef722028e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a20a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a20d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb582016d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a20fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712204c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850200769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c492008eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023208d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673206aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b15921620cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00206edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c201f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d3920d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f20bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c201b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab6512045e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a20c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc52720ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce7220bac21af2f8b1eba9d2eed719a3108efaa19b44386f2dd38212294253e6fa1102207b99abdc3730991cc9274727d7d82d28cb794edbc7034b4f0053ff7c4b680444204484e8faa977ac6a7372dfa525d10868666d9b8c8b06e95df0594bc33f5f7b5620b9e8757b6d27fcfd9adc914558e9bf055e125f610fd6170072b4778fa0c4f90b20db4ea7c2d058649c99ba7a9c700db7dfc53a2c14a4dd2a20dad9d35294b61559207ffb9317c7941ebc524eaceb48316ecdf9cdf39d190ab12c16836f885a0ab248204cdeae12395dd7e80047919e81031d425377bc14fdb82c8dfea869943cbf001b20ffe9fc03f18b176c998806439ff0bb8ad193afdb27b2ccbc88856916dd804e342096ae2abb5c1a38ac9664d9473a54c1106bcb9151dbf2ff66fb27b5512b92d22c2012d58b0466abebf7c2e0ab9f84c06044e8126c4b177d423ce179d4d8468dc505fa1a010000000000"),
                        },
                        SaplingInput {
                            extended_private_key: "secret-extended-key-test1qwq6zxvfpqqqpq90l4tj7ruxk3t6sj7g0r43hksurrgrcdny0mfwj9gjt3ez2euwmrvxqn26mr9g9flkhd54dake6njrshrscstpvqjvuy4cphcan6rspragf93krxptsmqdmgz5h7zlzcddf9r4zjctk43e5m7jtwer9csdcud24uhwua9zunwjp47fjs6s5qdzzhdylnr2g7n95sk0klurqfqgdnza0vqk756qmg89lu2pu39nap29u846gs23g5x2jqjhzpggtvskqf7rc",
                            cmu: "05c58d46d8d479e13c427d174b6c12e84460c0849fabe0c2f7ebab66048bd512",
                            epk: "d2a85b034e12f6659974cfa03d3062d60bee3d1ff581d499f13e217a181cf6e0",
                            enc_ciphertext: "611fce5e0c1b4541815537c69cb2567129c490547919e082d04d1e1b68d16ca876570d4d98a0fd5938583bc4d8a759919933bf6cc3e147b4afabbeaefa1b6cd1d5b9c3c4b2fbfd2ab227a4f0e5f4bc3265f9aeb41f497236991f255873c452f36dfd6edc4e352abc38888a6050c73f5655c514043a1c9bdebb06ffc471dd66a5280a54c63c0e64e32737360278caf5ddd25d7235b6aa332131c7d3ddbee1982170d42021e3fdc8ecb9863cc3a6064dcb491dd45df56b4879b3f0040a5f47a44675b38642ae582706c0d10a4f5b2e0783f2403f9b062aa5cad9b1bcaca361c113779bca01ac31561b3308de6238938e0691073d2c36e16f5093c24be66adf6619d2dabac11ee4a81928b27ad3031356076350887cd857f99e520e2dd7f41886c75478e840d5fa8701f4680b1506f3d22be2959c8f98948a13ff8188fc11d36cd85713fc5131b4445984a49c1579a004a9bcebf0f439bf42cc6ef43c1b08c12e40ac182234f8e8b614e16ed14a8d8dadcbe68b43688409dcac8b1cce8a766494a2e62c633671bd618a0fc03cbc647074fef9c508a00a6cd3b3b4144f63aa9006990f294bef762c5d98dbb201bba57703b8fcd2ac624afdda783635842cbafb722d8805ef0495d5c5ce2e5aa72a2e81dad612fae8870833bb04bd0cf8abb82e972430cce59c632bfab023ef2e099dd108c940a6362475b8f0dddf60479351131c7f8ddb63b0d8297e236e0d32d13467e9e52d29f0fb104cdea64255f178f155a1ef5bcb1935b760dd3791372ca4fe95c3d121a3af922e27bc781bd5a8b99991b45343168fef",
                            anchor: Some("b14aacb3c78e036f924078f0231a211cc0c169fcea96af813fe059f975cc2c06"),
                            witness: Some("2020b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c538142012935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d20e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef722028e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a20a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a20d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb582016d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a20fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712204c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850200769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c492008eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023208d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673206aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b15921620cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00206edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c201f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d3920d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f20bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c201b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab6512045e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a20c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc52720ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce7220bac21af2f8b1eba9d2eed719a3108efaa19b44386f2dd38212294253e6fa1102207b99abdc3730991cc9274727d7d82d28cb794edbc7034b4f0053ff7c4b680444204484e8faa977ac6a7372dfa525d10868666d9b8c8b06e95df0594bc33f5f7b5620b9e8757b6d27fcfd9adc914558e9bf055e125f610fd6170072b4778fa0c4f90b20db4ea7c2d058649c99ba7a9c700db7dfc53a2c14a4dd2a20dad9d35294b61559207ffb9317c7941ebc524eaceb48316ecdf9cdf39d190ab12c16836f885a0ab248204cdeae12395dd7e80047919e81031d425377bc14fdb82c8dfea869943cbf001b20ffe9fc03f18b176c998806439ff0bb8ad193afdb27b2ccbc88856916dd804e342096ae2abb5c1a38ac9664d9473a54c1106bcb9151dbf2ff66fb27b5512b92d22c2091accf1bea211bcced2cbbac533f9f7e9b53622852ec2912b78fcfd82c79c06dfb1a010000000000"),
                        },
                    ],
                    sapling_outputs: &[
                        Output {
                            address: "ztestsapling1vtt4em42w9qgt65x8hj55ua7m8dcxyvfm23a5zkw957v2xtk57jj0x06dnkamgp3tlz5g5053t5",
                            amount: ZcashAmount(499950000)
                        },
                    ],
                    expected_signed_transaction: "",
                    expected_transaction_id: "",
                },
            ];

            #[test]
            fn test_real_sapling_spend_transactions() {
                test_sapling_transactions::<N>(REAL_TESTNET_SAPLING_SPEND_TRANSACTIONS.to_vec());
            }

        }

        mod test_real_testnet_sapling_output_transactions {
            use super::*;
            type N = Testnet;

            const REAL_TESTNET_SAPLING_OUTPUT_TRANSACTIONS: [TransactionData; 3] = [
                TransactionData {
                    // txid: 289f33b35eb814d4c8df4d38f9d4eefe2a63c88e8af609dc64456bfa6a591495
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 499999999,
                    inputs: &[
                        Input {
                            private_key: "cUBFqbapRJBAKbpVq7LBDUrSY4UWquuTcA1UrLCvdym1zHiWFPBb",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "cdb426cbd9dfe1c27df683a891977d0a5be6cc87e3b618917bb124caba7a78f2",
                            index: 0,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(1000010000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL,
                        },
                    ],
                    outputs: &[],
                    sapling_inputs: &[],
                    sapling_outputs: &[
                        Output {
                            address:
                            "ztestsapling1z9thqxgzavwxfr58x72784y8uasz2hvzfvvzu3dl9prk3kyym04nf5vzwgpf5ddz2cu3ytf9jmg",
                            amount: ZcashAmount(1000000000)
                        },
                    ],
                    expected_signed_transaction: "",
                    expected_transaction_id: "",
                },
                TransactionData {
                    // txid: a018f5777860c7617266c43c9fecf53b939f96af70c1c21675351a51d373ac2a
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 499999999,
                    inputs: &[
                        Input {
                            private_key: "cUnh9NAShCGCur8PjxQnRz96n93Hs6tNAo6fmH41ig1vKzrXtWdC",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "35562b33fe8d03e0dcd9a2dd62154f3abdfcd7d29d61dcff0a09c1eb18a8f7ea",
                            index: 0,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(1000010000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL,
                        },
                        Input {
                            private_key: "cPZUjmuvdkcBMNyHn6wqXcVVqPbVrtxfcQc7UcrD2aD9mdrPBSf9",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "35562b33fe8d03e0dcd9a2dd62154f3abdfcd7d29d61dcff0a09c1eb18a8f7ea",
                            index: 1,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(1000010000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL,
                        },
                    ],
                    outputs: &[],
                    sapling_inputs: &[],
                    sapling_outputs: &[
                        Output {
                            address:
                            "ztestsapling1w4q82skzstjkql5t9x96yl8pxkm0yaymlgp3z9w0z9nzgmqj20fz749wyc4j550gvp8uyauughk",
                            amount: ZcashAmount(1000000000)
                        },
                        Output {
                            address:
                            "ztestsapling18zxfnamtuvl0hapcmmturn47ttgjftmfpjmk4nvph0yjfywhyrmp97hnepw8gf9gka925apsj5d",
                            amount: ZcashAmount(1000000000)
                        },
                    ],
                    expected_signed_transaction: "",
                    expected_transaction_id: "",
                },
                TransactionData {
                    // txid: f2f2408a3742c58ce24d96840bdfa1ff26b7042928075fb02ddb1847d1fd2038
                    version: "sapling",
                    lock_time: 0,
                    expiry_height: 499999999,
                    inputs: &[
                        Input {
                            private_key: "cMwUGSqBqKSavhstEH6Jsuf7cpqFf15ywuEaoUBmBuesdZxng41H",
                            address_format: ZcashFormat::P2PKH,
                            transaction_id: "35562b33fe8d03e0dcd9a2dd62154f3abdfcd7d29d61dcff0a09c1eb18a8f7ea",
                            index: 2,
                            redeem_script: None,
                            script_pub_key: None,
                            utxo_amount: Some(ZcashAmount(1000010000)),
                            sequence: Some([0xff, 0xff, 0xff, 0xff]),
                            sighash_code: SignatureHash::SIGHASH_ALL,
                        },
                    ],
                    outputs: &[
                        Output {
                            address: "tmGZKXeeSu2sVS72Lg1KAuKKUxg2S4iGXZ7",
                            amount: ZcashAmount(500000000),
                        },
                    ],
                    sapling_inputs: &[],
                    sapling_outputs: &[
                        Output {
                            address:
                            "ztestsapling1j9kgn4sawrk8zdq63a6uarf8xggk9ugm9wfynlkg2z2lgh7p47tt69686xepn0t323dgs5ttaqn",
                            amount: ZcashAmount(500000000),
                        },
                    ],
                    expected_signed_transaction: "",
                    expected_transaction_id: "",
                },
            ];

            #[test]
            fn test_sapling_output_transactions() {
                test_sapling_transactions::<N>(REAL_TESTNET_SAPLING_OUTPUT_TRANSACTIONS.to_vec());
            }
        }
    }

    mod test_invalid_transparent_transactions {
        use super::*;
        type N = Mainnet;

        const INVALID_INPUTS: [Input; 4] = [
            Input {
                private_key: "KwNJ5ppQ1wCbXdpW5GBoxcBex1avA99cBFgBvgH16rf5pmBLu6WX",
                address_format: ZcashFormat::P2PKH,
                transaction_id: "61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d",
                index: 0,
                redeem_script: None,
                script_pub_key: Some("0000000000"),
                utxo_amount: None,
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "KxyXFjrX9FjFX3HWWbRNxBrfZCRmD8A5kG31meyXtJDRPXrCXufK",
                address_format: ZcashFormat::P2PKH,
                transaction_id: "7dabce",
                index: 0,
                redeem_script: None,
                script_pub_key: Some("a914e39b100350d6896ad0f572c9fe452fcac549fe7b87"),
                utxo_amount: Some(ZcashAmount(10000)),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "KxyXFjrX9FjFX3HWWbRNxBrfZCRmD8A5kG31meyXtJDRPXrCXufK",
                address_format: ZcashFormat::P2PKH,
                transaction_id: "7dabce",
                index: 0,
                redeem_script: None,
                script_pub_key: Some("000014ff3e3ce0fc1febf95e0e0eac49a205ad04a7d47688ac"),
                utxo_amount: Some(ZcashAmount(10000)),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "",
                address_format: ZcashFormat::P2PKH,
                transaction_id: "",
                index: 0,
                redeem_script: Some(""),
                script_pub_key: None,
                utxo_amount: None,
                sequence: None,
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
        ];

        #[test]
        fn test_invalid_inputs() {
            for input in INVALID_INPUTS.iter() {
                let transaction_id = hex::decode(input.transaction_id).unwrap();
                let redeem_script = input.redeem_script.map(|script| hex::decode(script).unwrap());
                let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
                let sequence = input.sequence.map(|seq| seq.to_vec());

                let private_key = ZcashPrivateKey::<N>::from_str(input.private_key);
                match private_key {
                    Ok(private_key) => {
                        let address = private_key.to_address(&input.address_format).unwrap();
                        let invalid_input = ZcashTransparentInput::<N>::new(
                            transaction_id,
                            input.index,
                            Some(address),
                            input.utxo_amount,
                            redeem_script,
                            script_pub_key,
                            sequence,
                            input.sighash_code,
                        );
                        assert!(invalid_input.is_err());
                    }
                    _ => assert!(private_key.is_err()),
                }
            }
        }
    }

    mod test_invalid_sapling_transactions {
        use super::*;
        type N = Testnet;

        const INVALID_SAPLING_INPUTS: [SaplingInput; 2] = [
            SaplingInput {
                extended_private_key: "secret-extended-key-test1qwq6zxvfqsqqpqzn4hxmcv7d9whwepfpx72aahddkf073x2cwr6fwar0p2ns4xkcu73xgs2pnxgux2nfx8a5nt2w7tm49ptnq9v3z4qncjlk8er7q27qewhcul9xtlxjqe56jyspamlhh8r4glmva2zxvkuejw8ypsfp5lsgc564r6g5w068kqlrcy0s0wnu0382tv2eqnlart5gjczwa0l72qgtaa794dqpva62206wwvemvath3t2f5j6x9nlvsgus0wavrvwavucculeth",
                cmu: "40d9712ba3dd9787a0451462e4fdda07929305b06248dd8aaeabdce13985b576",
                epk: "0000000000000000000000000000000000000000000000000000000000000000",
                enc_ciphertext: "d259f0cb859e6bc1b92590600f2a5d9b3464c7c568c96926fb97b2ffcecd7f9c8bfb878e3650cf30378ec222797787ab2c354589cda6da227c9b72945751827857823848a03bddeef13ecc14570291ee6638da600e0f91ca0348a6146b9f176b60f053a7f4bd94f5d9c669e8958b3d03c2fd456caa4703ec1ffcf75759ffaf098502295c7eadbdab928e77740220339611c4c977b0185627f2ac6db5c0fca6c1d6a89f0ba6503f6d520e6814f0f592bc950023395b2907e39067242a87d74dc535a7decf37c4530b1b5f375cd588949cc9948c409ad3b7bf1bd6a307d076b34a1c93c330f7a42df419ef95965e747b43306f277255cc2fe4b7f4ec3e6ca06f7161ac4a89b703b2b99b201d3a2279b45d60b0f899931afc45a6be5496df192abade2039403132711d899bc8e02700d2f9cf225ca7de9b4c9e3899c9e63eb669e4b626006797ad61247bef423b27ad4e2d472c648420ac88d9f03abc9132d360b1e634684bb73eb251495f3c34a5ab6f73436b2b58e5fb89a5e41692ceea8f04d19b2dd76a796bda2d99f95b5aca03a750acb50f44924f7fea953fe33316255da6c5cadb80687875bc63b2865d79010a3d845d9bc1836a2726d3040ed05fe403f30a51597f8921e3c0c4544d1aab8d67a382410ce377654e79e27e9ff81bd8264d5fbd4e5915a7fa804424cc65ff19ca4d4dd0f3fb34585d18b75f6c39d99cc48e800bab6fa2324340922f62273fe371f2d725567fae988579a00bf7bc3b911cf03746cf47286f05d24c64c38f829d0d40a34799151176057cfe49d6b9fc6b9d983612d75d",
                anchor: Some("a9cea23799a2a99a4f141bb997ea1698fa2f45fc3ac3916aaa1982ea2326ee48"),
                witness: Some("2020b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c538142012935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d20e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef722028e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a20a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a20d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb582016d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a20fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712204c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850200769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c492008eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023208d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673206aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b15921620cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00206edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c201f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d3920d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f20bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c201b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab6512045e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a20c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc52720ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce72206a963be7305e1bd7e01f031baeed91551fec981609a52e8346c4f58e4b58214c2038cbc4cb015400c0436372d5583297ff9c1a3b2f7c99348afe44535cb3bdb33e2073de2ff5ca8ff6e2ffdf5861de3e669da231490093e6fb85486c7d4f04af664120c525cc77cac8a206aec5bdcbf2f02e9bf692a71b837b5956d14a447b936a8d06206e7f74f94b4c1bbd1e3a389730fe67f65d99cdbebd9a5dda0fd8a6babf0b1d0c20918ec10271032b8f755de870cde81da73b931f4641087d3a3e010ffab3468a4d203632627cc328c6f53f4b2edd3463e6aa7e3989ee714680ce7e415223ef8c8f3120e94edebe993a74cab0a49c6c6b2ac2538f97342faff86a24136c0ac1bd57253620bde37373a13118f8e504812bdb3a60ffbfa3da31e20fc3e1545041828f14d6132075a1481793b3a67864fa65adb30840dd4369899b3d4756fa268ba45cca2f0d2cef19010000000000"),
            },
            SaplingInput {
                extended_private_key: "secret-extended-key-test1qwq6zxvfqsqqpqzn4hxmcv7d9whwepfpx72aahddkf073x2cwr6fwar0p2ns4xkcu73xgs2pnxgux2nfx8a5nt2w7tm49ptnq9v3z4qncjlk8er7q27qewhcul9xtlxjqe56jyspamlhh8r4glmva2zxvkuejw8ypsfp5lsgc564r6g5w068kqlrcy0s0wnu0382tv2eqnlart5gjczwa0l72qgtaa794dqpva62206wwvemvath3t2f5j6x9nlvsgus0wavrvwavucculeth",
                cmu: "40d9712ba3dd9787a0451462e4fdda07929305b06248dd8aaeabdce13985b576",
                epk: "8dca2796416d9ab8409e40e3b3839eb28b5765ba9b7dcfb2c267ac54b85fc6be",
                enc_ciphertext: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                anchor: Some("a9cea23799a2a99a4f141bb997ea1698fa2f45fc3ac3916aaa1982ea2326ee48"),
                witness: Some("2020b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c538142012935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d20e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef722028e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a20a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a20d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb582016d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a20fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712204c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850200769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c492008eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023208d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673206aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b15921620cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00206edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c201f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d3920d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f20bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c201b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab6512045e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a20c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc52720ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce72206a963be7305e1bd7e01f031baeed91551fec981609a52e8346c4f58e4b58214c2038cbc4cb015400c0436372d5583297ff9c1a3b2f7c99348afe44535cb3bdb33e2073de2ff5ca8ff6e2ffdf5861de3e669da231490093e6fb85486c7d4f04af664120c525cc77cac8a206aec5bdcbf2f02e9bf692a71b837b5956d14a447b936a8d06206e7f74f94b4c1bbd1e3a389730fe67f65d99cdbebd9a5dda0fd8a6babf0b1d0c20918ec10271032b8f755de870cde81da73b931f4641087d3a3e010ffab3468a4d203632627cc328c6f53f4b2edd3463e6aa7e3989ee714680ce7e415223ef8c8f3120e94edebe993a74cab0a49c6c6b2ac2538f97342faff86a24136c0ac1bd57253620bde37373a13118f8e504812bdb3a60ffbfa3da31e20fc3e1545041828f14d6132075a1481793b3a67864fa65adb30840dd4369899b3d4756fa268ba45cca2f0d2cef19010000000000"),
            },
        ];

        #[test]
        fn test_invalid_sapling_inputs() {
            for input in INVALID_SAPLING_INPUTS.iter() {
                let mut cmu = [0u8; 32];
                cmu.copy_from_slice(&hex::decode(input.cmu).unwrap());
                cmu.reverse();

                let mut epk = [0u8; 32];
                epk.copy_from_slice(&hex::decode(input.epk).unwrap());
                epk.reverse();

                let (witness, anchor) = match input.witness {
                    Some(witness_str) => {
                        let witness_vec = hex::decode(&witness_str).unwrap();
                        let witness = MerklePath::<Node>::from_slice(&witness_vec[..]).unwrap();

                        let mut f = FrRepr::default();
                        f.read_le(&hex::decode(input.anchor.unwrap()).unwrap()[..]).unwrap();
                        let anchor = Fr::from_repr(f).unwrap();

                        (witness, anchor)
                    }
                    // Test with set witness/anchors instead of randomly generated
                    None => unreachable!(),
                };

                let extended_private_key = ZcashExtendedPrivateKey::<N>::from_str(input.extended_private_key).unwrap();
                let sapling_spend =
                    SaplingSpend::<N>::new(&extended_private_key, &cmu, &epk, input.enc_ciphertext, anchor, witness);

                assert!(sapling_spend.is_err());
            }
        }

        #[test]
        fn test_invalid_sapling_transactions_conflicting_anchor() {
            let version = "sapling";
            let lock_time = 0;
            let expiry_height = 499999999;

            let sapling_inputs = [
                SaplingInput {
                    extended_private_key: "secret-extended-key-test1qwq6zxvfqcqqpqx9yxfvz024pygvsyc5mk3tvx90c9xyvc8660xk9q3954rmdngzhsdms6h8mdwgmwgct0degp3x5aeruddxpxwg3c3gy4krptv47w2q6790n88h8uztvxzxjd9ndz4yx80vm8mqqjj73m5gyzz3edmnlxgp0y642f36dv3xl30pm7fetducd0rfcpg8nq9nuj5pxtlu35p946yk5nwa6gdzc5v4w7dpwzmdszqudq6ecn0esryntk9vly0fkh53grsnjunxl",
                    cmu: "6bea0e40d62442443a3475b3486b3b230e6f3895f6ec931bdcf378ab72e1f7b8",
                    epk: "bdfe7b1a08c3a43f8357be258d10ddbaf4f6ed58d99ba94184d4536b1ae7daac",
                    enc_ciphertext: "c8af78c4b420366f686c450c0652d28d0955c0bf26380d7cfd81501864b806ef868f1b5ec6d7ac2eb1809299074498a101ef370389129b90c7b10207a685148743b3c4f083538c62a33199ccf65d1987a73d5cf293a5691b4d57aba2b95d4c67c6d0001d4741bba826cd9c1f1695700146dcd65f4e61cc2b1dd96f03046c8c334d036c8f43d3d15c7f58c39dd35ecb2b34189710489c5aa0fa02d64f1d6d76014e6862be2e741025bd7f11f99a65518da4340854daa54b4719ed3716f3f409e7821e7cf973f2adeebc229458da60007b97c006398a0da0e5cf6753c44533e1fc97850705dbfd6cd68f1b618faf7e0b29c2c03ab3c8c7015db095e4ffcbb3be8e2a2fde2a40c7570e54cecc02348706251ff0ed88513051b9886b8a0d9681c2713f2d2162ef93c7c81c3cbc7e9a9685388c8690397b53ab217b048d22f5c9c019cce142eaef9f330ec5239dc4f61c0eafdb10bd4679e52a2863969c5cd6172f893a2a6e4af31c4b73456d339b127ca3e98595da3599f1a00c6804363e4b1d393f925d0f3eaa79e03d96411139fb024bbc2587334bb04f447f074e50639c627fd665d59253a261779ce5de22d678ceaad9a3e20078346d17bc6ca294df1ef3bfe239bbb1bb33bb34f6701874d48dab94c5649577aff9b98fa0f69adee522868da0cd31cd744f31b6f01d1701d36ae50af38a653651ce85dd432d90fbce2cdd06c69d644fdab912b89c7c69a7c19b95442c0ea62de16ad88ade0130c84ebead2ff99fe12bd686bbba322f9ff61531341513f6a4b51fa65c47cb45dd5cdeb85f0b9abf8f68a3",
                    anchor: Some("a4c8ea36def54b535c93a3d3d61daa5fbd04968b79ae3a518d2f1a097fcfe52d"),
                    witness: Some("2020b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c538142012935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d20e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef722028e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a20a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a20d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb582016d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a20fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712204c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850200769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c492008eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023208d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673206aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b15921620cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00206edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c201f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d3920d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f20bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c201b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab6512045e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a20c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc52720ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce7220bac21af2f8b1eba9d2eed719a3108efaa19b44386f2dd38212294253e6fa1102207b99abdc3730991cc9274727d7d82d28cb794edbc7034b4f0053ff7c4b680444204484e8faa977ac6a7372dfa525d10868666d9b8c8b06e95df0594bc33f5f7b5620b9e8757b6d27fcfd9adc914558e9bf055e125f610fd6170072b4778fa0c4f90b20db4ea7c2d058649c99ba7a9c700db7dfc53a2c14a4dd2a20dad9d35294b61559207ffb9317c7941ebc524eaceb48316ecdf9cdf39d190ab12c16836f885a0ab24820d8283386ef2ef07ebdbb4383c12a739a953a4d6e0d6fb1139a4036d693bfbb6c201a0564d96a7d7b6beb993318e8de10c44bb6eb0d91c674a8c04b0a15ccb33c7020bc540156b432138ebd0ab33dd371ee22ed7f5d3f987af37de468a7f74c055f5c2021cac521ca62e3b84381d8303660a7ca9fa99af47ee7080ea7f35f48c865b065f71a010000000000"),
                },
                SaplingInput {
                    extended_private_key: "secret-extended-key-test1qwq6zxvfqcqqpqx9yxfvz024pygvsyc5mk3tvx90c9xyvc8660xk9q3954rmdngzhsdms6h8mdwgmwgct0degp3x5aeruddxpxwg3c3gy4krptv47w2q6790n88h8uztvxzxjd9ndz4yx80vm8mqqjj73m5gyzz3edmnlxgp0y642f36dv3xl30pm7fetducd0rfcpg8nq9nuj5pxtlu35p946yk5nwa6gdzc5v4w7dpwzmdszqudq6ecn0esryntk9vly0fkh53grsnjunxl",
                    cmu: "6bea0e40d62442443a3475b3486b3b230e6f3895f6ec931bdcf378ab72e1f7b8",
                    epk: "bdfe7b1a08c3a43f8357be258d10ddbaf4f6ed58d99ba94184d4536b1ae7daac",
                    enc_ciphertext: "c8af78c4b420366f686c450c0652d28d0955c0bf26380d7cfd81501864b806ef868f1b5ec6d7ac2eb1809299074498a101ef370389129b90c7b10207a685148743b3c4f083538c62a33199ccf65d1987a73d5cf293a5691b4d57aba2b95d4c67c6d0001d4741bba826cd9c1f1695700146dcd65f4e61cc2b1dd96f03046c8c334d036c8f43d3d15c7f58c39dd35ecb2b34189710489c5aa0fa02d64f1d6d76014e6862be2e741025bd7f11f99a65518da4340854daa54b4719ed3716f3f409e7821e7cf973f2adeebc229458da60007b97c006398a0da0e5cf6753c44533e1fc97850705dbfd6cd68f1b618faf7e0b29c2c03ab3c8c7015db095e4ffcbb3be8e2a2fde2a40c7570e54cecc02348706251ff0ed88513051b9886b8a0d9681c2713f2d2162ef93c7c81c3cbc7e9a9685388c8690397b53ab217b048d22f5c9c019cce142eaef9f330ec5239dc4f61c0eafdb10bd4679e52a2863969c5cd6172f893a2a6e4af31c4b73456d339b127ca3e98595da3599f1a00c6804363e4b1d393f925d0f3eaa79e03d96411139fb024bbc2587334bb04f447f074e50639c627fd665d59253a261779ce5de22d678ceaad9a3e20078346d17bc6ca294df1ef3bfe239bbb1bb33bb34f6701874d48dab94c5649577aff9b98fa0f69adee522868da0cd31cd744f31b6f01d1701d36ae50af38a653651ce85dd432d90fbce2cdd06c69d644fdab912b89c7c69a7c19b95442c0ea62de16ad88ade0130c84ebead2ff99fe12bd686bbba322f9ff61531341513f6a4b51fa65c47cb45dd5cdeb85f0b9abf8f68a3",
                    anchor: Some("b14aacb3c78e036f924078f0231a211cc0c169fcea96af813fe059f975cc2c06"),
                    witness: Some("2020b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c538142012935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d20e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef722028e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a20a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a20d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb582016d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a20fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712204c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850200769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c492008eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023208d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673206aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b15921620cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00206edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c201f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d3920d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f20bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c201b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab6512045e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a20c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc52720ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce7220bac21af2f8b1eba9d2eed719a3108efaa19b44386f2dd38212294253e6fa1102207b99abdc3730991cc9274727d7d82d28cb794edbc7034b4f0053ff7c4b680444204484e8faa977ac6a7372dfa525d10868666d9b8c8b06e95df0594bc33f5f7b5620b9e8757b6d27fcfd9adc914558e9bf055e125f610fd6170072b4778fa0c4f90b20db4ea7c2d058649c99ba7a9c700db7dfc53a2c14a4dd2a20dad9d35294b61559207ffb9317c7941ebc524eaceb48316ecdf9cdf39d190ab12c16836f885a0ab24820d8283386ef2ef07ebdbb4383c12a739a953a4d6e0d6fb1139a4036d693bfbb6c201a0564d96a7d7b6beb993318e8de10c44bb6eb0d91c674a8c04b0a15ccb33c7020bc540156b432138ebd0ab33dd371ee22ed7f5d3f987af37de468a7f74c055f5c2021cac521ca62e3b84381d8303660a7ca9fa99af47ee7080ea7f35f48c865b065f71a010000000000"),
                },
                SaplingInput {
                    extended_private_key: "secret-extended-key-test1qwq6zxvfqcqqpqx9yxfvz024pygvsyc5mk3tvx90c9xyvc8660xk9q3954rmdngzhsdms6h8mdwgmwgct0degp3x5aeruddxpxwg3c3gy4krptv47w2q6790n88h8uztvxzxjd9ndz4yx80vm8mqqjj73m5gyzz3edmnlxgp0y642f36dv3xl30pm7fetducd0rfcpg8nq9nuj5pxtlu35p946yk5nwa6gdzc5v4w7dpwzmdszqudq6ecn0esryntk9vly0fkh53grsnjunxl",
                    cmu: "6bea0e40d62442443a3475b3486b3b230e6f3895f6ec931bdcf378ab72e1f7b8",
                    epk: "bdfe7b1a08c3a43f8357be258d10ddbaf4f6ed58d99ba94184d4536b1ae7daac",
                    enc_ciphertext: "c8af78c4b420366f686c450c0652d28d0955c0bf26380d7cfd81501864b806ef868f1b5ec6d7ac2eb1809299074498a101ef370389129b90c7b10207a685148743b3c4f083538c62a33199ccf65d1987a73d5cf293a5691b4d57aba2b95d4c67c6d0001d4741bba826cd9c1f1695700146dcd65f4e61cc2b1dd96f03046c8c334d036c8f43d3d15c7f58c39dd35ecb2b34189710489c5aa0fa02d64f1d6d76014e6862be2e741025bd7f11f99a65518da4340854daa54b4719ed3716f3f409e7821e7cf973f2adeebc229458da60007b97c006398a0da0e5cf6753c44533e1fc97850705dbfd6cd68f1b618faf7e0b29c2c03ab3c8c7015db095e4ffcbb3be8e2a2fde2a40c7570e54cecc02348706251ff0ed88513051b9886b8a0d9681c2713f2d2162ef93c7c81c3cbc7e9a9685388c8690397b53ab217b048d22f5c9c019cce142eaef9f330ec5239dc4f61c0eafdb10bd4679e52a2863969c5cd6172f893a2a6e4af31c4b73456d339b127ca3e98595da3599f1a00c6804363e4b1d393f925d0f3eaa79e03d96411139fb024bbc2587334bb04f447f074e50639c627fd665d59253a261779ce5de22d678ceaad9a3e20078346d17bc6ca294df1ef3bfe239bbb1bb33bb34f6701874d48dab94c5649577aff9b98fa0f69adee522868da0cd31cd744f31b6f01d1701d36ae50af38a653651ce85dd432d90fbce2cdd06c69d644fdab912b89c7c69a7c19b95442c0ea62de16ad88ade0130c84ebead2ff99fe12bd686bbba322f9ff61531341513f6a4b51fa65c47cb45dd5cdeb85f0b9abf8f68a3",
                    anchor: Some("a9cea23799a2a99a4f141bb997ea1698fa2f45fc3ac3916aaa1982ea2326ee48"),
                    witness: Some("2020b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c538142012935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d20e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef722028e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a20a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a20d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb582016d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a20fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712204c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850200769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c492008eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023208d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673206aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b15921620cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00206edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c201f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d3920d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f20bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c201b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab6512045e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a20c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc52720ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce7220bac21af2f8b1eba9d2eed719a3108efaa19b44386f2dd38212294253e6fa1102207b99abdc3730991cc9274727d7d82d28cb794edbc7034b4f0053ff7c4b680444204484e8faa977ac6a7372dfa525d10868666d9b8c8b06e95df0594bc33f5f7b5620b9e8757b6d27fcfd9adc914558e9bf055e125f610fd6170072b4778fa0c4f90b20db4ea7c2d058649c99ba7a9c700db7dfc53a2c14a4dd2a20dad9d35294b61559207ffb9317c7941ebc524eaceb48316ecdf9cdf39d190ab12c16836f885a0ab24820d8283386ef2ef07ebdbb4383c12a739a953a4d6e0d6fb1139a4036d693bfbb6c201a0564d96a7d7b6beb993318e8de10c44bb6eb0d91c674a8c04b0a15ccb33c7020bc540156b432138ebd0ab33dd371ee22ed7f5d3f987af37de468a7f74c055f5c2021cac521ca62e3b84381d8303660a7ca9fa99af47ee7080ea7f35f48c865b065f71a010000000000"),
                },
            ];

            // Build raw transaction

            let parameters = ZcashTransactionParameters::<N>::new(version, lock_time, expiry_height).unwrap();
            let mut transaction = ZcashTransaction::<N>::new(&parameters).unwrap();

            // Build Sapling Spends

            for (index, input) in sapling_inputs.iter().enumerate() {
                let mut cmu = [0u8; 32];
                cmu.copy_from_slice(&hex::decode(input.cmu).unwrap());
                cmu.reverse();

                let mut epk = [0u8; 32];
                epk.copy_from_slice(&hex::decode(input.epk).unwrap());
                epk.reverse();

                let (witness, anchor) = match input.witness {
                    Some(witness_str) => {
                        let witness_vec = hex::decode(&witness_str).unwrap();
                        let witness = MerklePath::<Node>::from_slice(&witness_vec[..]).unwrap();

                        let mut f = FrRepr::default();
                        f.read_le(&hex::decode(input.anchor.unwrap()).unwrap()[..]).unwrap();
                        let anchor = Fr::from_repr(f).unwrap();

                        (witness, anchor)
                    }
                    _ => unreachable!(),
                };

                // Add Sapling Spend

                let extended_private_key = ZcashExtendedPrivateKey::<N>::from_str(input.extended_private_key).unwrap();
                let status = transaction.parameters.add_sapling_input(
                    &extended_private_key,
                    &cmu,
                    &epk,
                    input.enc_ciphertext,
                    anchor,
                    witness,
                );

                match index {
                    0 => {
                        assert!(status.is_ok());
                        transaction.parameters = status.unwrap();
                    }
                    _ => assert!(status.is_err()),
                };
            }
        }

        #[test]
        fn test_invalid_sapling_transactions_incorrect_build_order() {
            let (_, mut spend_vk, _, _) = load_sapling_parameters();

            let version = "sapling";
            let lock_time = 0;
            let expiry_height = 499999999;

            let sapling_input = SaplingInput {
                extended_private_key: "secret-extended-key-test1qwq6zxvfqcqqpqx9yxfvz024pygvsyc5mk3tvx90c9xyvc8660xk9q3954rmdngzhsdms6h8mdwgmwgct0degp3x5aeruddxpxwg3c3gy4krptv47w2q6790n88h8uztvxzxjd9ndz4yx80vm8mqqjj73m5gyzz3edmnlxgp0y642f36dv3xl30pm7fetducd0rfcpg8nq9nuj5pxtlu35p946yk5nwa6gdzc5v4w7dpwzmdszqudq6ecn0esryntk9vly0fkh53grsnjunxl",
                cmu: "6bea0e40d62442443a3475b3486b3b230e6f3895f6ec931bdcf378ab72e1f7b8",
                epk: "bdfe7b1a08c3a43f8357be258d10ddbaf4f6ed58d99ba94184d4536b1ae7daac",
                enc_ciphertext: "c8af78c4b420366f686c450c0652d28d0955c0bf26380d7cfd81501864b806ef868f1b5ec6d7ac2eb1809299074498a101ef370389129b90c7b10207a685148743b3c4f083538c62a33199ccf65d1987a73d5cf293a5691b4d57aba2b95d4c67c6d0001d4741bba826cd9c1f1695700146dcd65f4e61cc2b1dd96f03046c8c334d036c8f43d3d15c7f58c39dd35ecb2b34189710489c5aa0fa02d64f1d6d76014e6862be2e741025bd7f11f99a65518da4340854daa54b4719ed3716f3f409e7821e7cf973f2adeebc229458da60007b97c006398a0da0e5cf6753c44533e1fc97850705dbfd6cd68f1b618faf7e0b29c2c03ab3c8c7015db095e4ffcbb3be8e2a2fde2a40c7570e54cecc02348706251ff0ed88513051b9886b8a0d9681c2713f2d2162ef93c7c81c3cbc7e9a9685388c8690397b53ab217b048d22f5c9c019cce142eaef9f330ec5239dc4f61c0eafdb10bd4679e52a2863969c5cd6172f893a2a6e4af31c4b73456d339b127ca3e98595da3599f1a00c6804363e4b1d393f925d0f3eaa79e03d96411139fb024bbc2587334bb04f447f074e50639c627fd665d59253a261779ce5de22d678ceaad9a3e20078346d17bc6ca294df1ef3bfe239bbb1bb33bb34f6701874d48dab94c5649577aff9b98fa0f69adee522868da0cd31cd744f31b6f01d1701d36ae50af38a653651ce85dd432d90fbce2cdd06c69d644fdab912b89c7c69a7c19b95442c0ea62de16ad88ade0130c84ebead2ff99fe12bd686bbba322f9ff61531341513f6a4b51fa65c47cb45dd5cdeb85f0b9abf8f68a3",
                anchor: Some("a4c8ea36def54b535c93a3d3d61daa5fbd04968b79ae3a518d2f1a097fcfe52d"),
                witness: Some("2020b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c538142012935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d20e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef722028e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a20a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a20d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb582016d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a20fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712204c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850200769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c492008eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023208d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673206aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b15921620cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00206edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c201f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d3920d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f20bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c201b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab6512045e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a20c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc52720ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce7220bac21af2f8b1eba9d2eed719a3108efaa19b44386f2dd38212294253e6fa1102207b99abdc3730991cc9274727d7d82d28cb794edbc7034b4f0053ff7c4b680444204484e8faa977ac6a7372dfa525d10868666d9b8c8b06e95df0594bc33f5f7b5620b9e8757b6d27fcfd9adc914558e9bf055e125f610fd6170072b4778fa0c4f90b20db4ea7c2d058649c99ba7a9c700db7dfc53a2c14a4dd2a20dad9d35294b61559207ffb9317c7941ebc524eaceb48316ecdf9cdf39d190ab12c16836f885a0ab24820d8283386ef2ef07ebdbb4383c12a739a953a4d6e0d6fb1139a4036d693bfbb6c201a0564d96a7d7b6beb993318e8de10c44bb6eb0d91c674a8c04b0a15ccb33c7020bc540156b432138ebd0ab33dd371ee22ed7f5d3f987af37de468a7f74c055f5c2021cac521ca62e3b84381d8303660a7ca9fa99af47ee7080ea7f35f48c865b065f71a010000000000"),
            };

            let output = Output {
                address: "tmMVUvhGDFmCAUsXdeGLhftcPJzB8LQ7VrV",
                amount: ZcashAmount(40000000),
            };

            let parameters = ZcashTransactionParameters::<N>::new(version, lock_time, expiry_height).unwrap();
            let mut transaction = ZcashTransaction::<N>::new(&parameters).unwrap();

            let address = ZcashAddress::<N>::from_str(output.address).unwrap();
            transaction.parameters = transaction
                .parameters
                .add_transparent_output(&address, output.amount)
                .unwrap();

            // Build Sapling Spends

            let mut cmu = [0u8; 32];
            cmu.copy_from_slice(&hex::decode(sapling_input.cmu).unwrap());
            cmu.reverse();

            let mut epk = [0u8; 32];
            epk.copy_from_slice(&hex::decode(sapling_input.epk).unwrap());
            epk.reverse();

            let (witness, anchor) = match sapling_input.witness {
                Some(witness_str) => {
                    let witness_vec = hex::decode(&witness_str).unwrap();
                    let witness = MerklePath::<Node>::from_slice(&witness_vec[..]).unwrap();

                    let mut f = FrRepr::default();
                    f.read_le(&hex::decode(sapling_input.anchor.unwrap()).unwrap()[..])
                        .unwrap();
                    let anchor = Fr::from_repr(f).unwrap();

                    (witness, anchor)
                }
                _ => unreachable!(),
            };

            // Add Sapling Spend

            let extended_private_key =
                ZcashExtendedPrivateKey::<N>::from_str(sapling_input.extended_private_key).unwrap();
            transaction.parameters = transaction
                .parameters
                .add_sapling_input(
                    &extended_private_key,
                    &cmu,
                    &epk,
                    sapling_input.enc_ciphertext,
                    anchor,
                    witness,
                )
                .unwrap();

            let mut verifying_ctx = initialize_verifying_context();
            let mut sighash = [0u8; 32];
            sighash.copy_from_slice(
                transaction
                    .generate_sighash(None, SignatureHash::SIGHASH_ALL)
                    .unwrap()
                    .as_bytes(),
            );

            assert!(transaction
                .generate_spend_auth_signatures(&mut verifying_ctx, &mut spend_vk, &sighash)
                .is_err())
        }
    }

    mod test_helper_functions {
        use super::*;

        const LENGTH_VALUES: [(u64, [u8; 9]); 14] = [
            (20, [0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (32, [0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (200, [0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (252, [0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (253, [0xfd, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (40000, [0xfd, 0x40, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (65535, [0xfd, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (65536, [0xfe, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (2000000000, [0xfe, 0x00, 0x94, 0x35, 0x77, 0x00, 0x00, 0x00, 0x00]),
            (2000000000, [0xfe, 0x00, 0x94, 0x35, 0x77, 0x00, 0x00, 0x00, 0x00]),
            (4294967295, [0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]),
            (4294967296, [0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
            (
                500000000000000000,
                [0xff, 0x00, 0x00, 0xb2, 0xd3, 0x59, 0x5b, 0xf0, 0x06],
            ),
            (
                18446744073709551615,
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        #[test]
        fn test_variable_length_integer() {
            LENGTH_VALUES.iter().for_each(|(size, expected_output)| {
                let variable_length_int = variable_length_integer(*size).unwrap();
                let pruned_expected_output = &expected_output[..variable_length_int.len()];
                assert_eq!(hex::encode(pruned_expected_output), hex::encode(&variable_length_int));
            });
        }
    }
}
