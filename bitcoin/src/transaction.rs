use crate::address::BitcoinAddress;
use crate::format::BitcoinFormat;
use crate::network::BitcoinNetwork;
use crate::private_key::BitcoinPrivateKey;
use crate::public_key::BitcoinPublicKey;
use crate::witness_program::WitnessProgram;
use wagyu_model::{PrivateKey, Transaction, TransactionError, TransactionId};

use base58::FromBase58;
use bech32::{Bech32, FromBase32};
use secp256k1;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fmt, io::Read, str::FromStr};

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

pub struct BitcoinVector;

impl BitcoinVector {
    /// Read and output a vector with a variable length integer
    pub fn read<R: Read, E, F>(mut reader: R, func: F) -> Result<Vec<E>, TransactionError>
    where
        F: Fn(&mut R) -> Result<E, TransactionError>,
    {
        let count = read_variable_length_integer(&mut reader)?;
        (0..count).map(|_| func(&mut reader)).collect()
    }

    /// Read and output a vector with a variable length integer and the integer itself
    pub fn read_witness<R: Read, E, F>(
        mut reader: R,
        func: F,
    ) -> Result<(usize, Result<Vec<E>, TransactionError>), TransactionError>
    where
        F: Fn(&mut R) -> Result<E, TransactionError>,
    {
        let count = read_variable_length_integer(&mut reader)?;
        Ok((count, (0..count).map(|_| func(&mut reader)).collect()))
    }
}

/// Generate the script_pub_key of a corresponding address
pub fn create_script_pub_key<N: BitcoinNetwork>(address: &BitcoinAddress<N>) -> Result<Vec<u8>, TransactionError> {
    match address.format() {
        BitcoinFormat::P2PKH => {
            let bytes = &address.to_string().from_base58()?;
            let pub_key_hash = bytes[1..(bytes.len() - 4)].to_vec();

            let mut script = vec![];
            script.push(Opcode::OP_DUP as u8);
            script.push(Opcode::OP_HASH160 as u8);
            script.extend(variable_length_integer(pub_key_hash.len() as u64)?);
            script.extend(pub_key_hash);
            script.push(Opcode::OP_EQUALVERIFY as u8);
            script.push(Opcode::OP_CHECKSIG as u8);
            Ok(script)
        }
        BitcoinFormat::P2SH_P2WPKH => {
            let script_bytes = &address.to_string().from_base58()?;
            let script_hash = script_bytes[1..(script_bytes.len() - 4)].to_vec();

            let mut script = vec![];
            script.push(Opcode::OP_HASH160 as u8);
            script.extend(variable_length_integer(script_hash.len() as u64)?);
            script.extend(script_hash);
            script.push(Opcode::OP_EQUAL as u8);
            Ok(script)
        }
        BitcoinFormat::Bech32 => {
            let bech32 = Bech32::from_str(&address.to_string())?;
            let (v, program) = bech32.data().split_at(1);
            let program = Vec::from_base32(program)?;
            let mut program_bytes = vec![v[0].to_u8(), program.len() as u8];
            program_bytes.extend(program);

            Ok(WitnessProgram::new(&program_bytes)?.to_scriptpubkey())
        }
    }
}

/// Represents a Bitcoin signature hash
/// https://en.bitcoin.it/wiki/OP_CHECKSIG
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum SignatureHash {
    /// Signs all inputs and outputs.
    SIGHASH_ALL = 0x01,
    /// Signs all inputs and none of the outputs.
    /// (e.g. "blank check" transaction, where any address can redeem the output)
    SIGHASH_NONE = 0x02,
    /// Signs all inputs and one corresponding output per input.
    /// (e.g. signing vin 0 will result in signing vout 0)
    SIGHASH_SINGLE = 0x03,
    /// Signs only one input and all outputs.
    /// Allows anyone to add or remove other inputs, forbids changing any outputs.
    /// (e.g. "crowdfunding" transaction, where the output is the "goal" address)
    SIGHASH_ALL_SIGHASH_ANYONECANPAY = 0x81,
    /// Signs only one input and none of the outputs.
    /// Allows anyone to add or remove other inputs or any outputs.
    /// (e.g. "dust collector" transaction, where "dust" can be aggregated and spent together)
    SIGHASH_NONE_SIGHASH_ANYONECANPAY = 0x82,
    /// Signs only one input and one corresponding output per input.
    /// Allows anyone to add or remove other inputs.
    SIGHASH_SINGLE_SIGHASH_ANYONECANPAY = 0x83,
}

impl fmt::Display for SignatureHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignatureHash::SIGHASH_ALL => write!(f, "SIGHASH_ALL"),
            SignatureHash::SIGHASH_NONE => write!(f, "SIGHASH_NONE"),
            SignatureHash::SIGHASH_SINGLE => write!(f, "SIGHASH_SINGLE"),
            SignatureHash::SIGHASH_ALL_SIGHASH_ANYONECANPAY => write!(f, "SIGHASH_ALL | SIGHASH_ANYONECANPAY"),
            SignatureHash::SIGHASH_NONE_SIGHASH_ANYONECANPAY => write!(f, "SIGHASH_NONE | SIGHASH_ANYONECANPAY"),
            SignatureHash::SIGHASH_SINGLE_SIGHASH_ANYONECANPAY => write!(f, "SIGHASH_SINGLE | SIGHASH_ANYONECANPAY"),
        }
    }
}

impl SignatureHash {
    fn from_byte(byte: &u8) -> Self {
        match byte {
            0x01 => SignatureHash::SIGHASH_ALL,
            0x02 => SignatureHash::SIGHASH_NONE,
            0x03 => SignatureHash::SIGHASH_SINGLE,
            0x81 => SignatureHash::SIGHASH_ALL_SIGHASH_ANYONECANPAY,
            0x82 => SignatureHash::SIGHASH_NONE_SIGHASH_ANYONECANPAY,
            0x83 => SignatureHash::SIGHASH_SINGLE_SIGHASH_ANYONECANPAY,
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

/// Represents a Bitcoin transaction outpoint
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Outpoint<N: BitcoinNetwork> {
    /// The previous transaction hash (32 bytes) (uses reversed hash order from Bitcoin RPC)
    pub reverse_transaction_id: Vec<u8>,
    /// The index of the transaction input (4 bytes)
    pub index: u32,
    /// The amount associated with this input (used for SegWit transaction signatures)
    pub amount: Option<u64>,
    /// The script public key associated with spending this input
    pub script_pub_key: Option<Vec<u8>>,
    /// An optional redeem script (for SegWit transactions)
    pub redeem_script: Option<Vec<u8>>,
    /// The address of the outpoint
    pub address: Option<BitcoinAddress<N>>,
}

/// Represents a Bitcoin transaction input
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTransactionInput<N: BitcoinNetwork> {
    /// The outpoint (36 bytes)
    pub outpoint: Outpoint<N>,
    /// The transaction input script (variable size)
    pub script_sig: Vec<u8>,
    /// The sequence number (4 bytes) (0xFFFFFFFF unless lock > 0)
    /// Also used in replace-by-fee (BIP 125)
    pub sequence: Vec<u8>,
    /// The signature hash (4 bytes) (used in signing raw transaction only)
    pub sighash_code: SignatureHash,
    /// The witnesses in a SegWit transaction
    pub witnesses: Vec<Vec<u8>>,
    /// If true, the input has been signed
    pub is_signed: bool,
}

impl<N: BitcoinNetwork> BitcoinTransactionInput<N> {
    const DEFAULT_SEQUENCE: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

    /// Returns a new Bitcoin transaction input without the script (unlocking).
    pub fn new(
        address: &BitcoinAddress<N>,
        transaction_id: Vec<u8>,
        index: u32,
        amount: u64,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
        sequence: Option<Vec<u8>>,
        sighash: SignatureHash,
    ) -> Result<Self, TransactionError> {
        if transaction_id.len() != 32 {
            return Err(TransactionError::InvalidTransactionId(transaction_id.len()));
        }

        // Byte-wise reverse of computed SHA-256 hash values
        // https://bitcoin.org/en/developer-reference#hash-byte-order
        let mut reverse_transaction_id = transaction_id;
        reverse_transaction_id.reverse();

        let script_pub_key = script_pub_key.unwrap_or(create_script_pub_key::<N>(address)?);
        let redeem_script = match address.format() {
            BitcoinFormat::P2PKH => match redeem_script {
                Some(_) => return Err(TransactionError::InvalidInputs("P2PKH".into())),
                None => match script_pub_key[0] != Opcode::OP_DUP as u8
                    && script_pub_key[1] != Opcode::OP_HASH160 as u8
                    && script_pub_key[script_pub_key.len() - 1] != Opcode::OP_CHECKSIG as u8
                {
                    true => return Err(TransactionError::InvalidScriptPubKey("P2PKH".into())),
                    false => None,
                },
            },
            BitcoinFormat::P2SH_P2WPKH => match redeem_script {
                Some(redeem_script) => match script_pub_key[0] != Opcode::OP_HASH160 as u8
                    && script_pub_key[script_pub_key.len() - 1] != Opcode::OP_EQUAL as u8
                {
                    true => return Err(TransactionError::InvalidScriptPubKey("P2SH_P2WPKH".into())),
                    false => Some(redeem_script),
                },
                None => return Err(TransactionError::InvalidInputs("P2SH_P2WPKH".into())),
            },
            BitcoinFormat::Bech32 => match redeem_script.is_some() {
                true => return Err(TransactionError::InvalidInputs("Bech32".into())),
                false => None,
            },
        };

        Ok(Self {
            outpoint: Outpoint {
                reverse_transaction_id,
                index,
                amount: Some(amount),
                redeem_script,
                script_pub_key: Some(script_pub_key),
                address: Some(address.clone()),
            },
            script_sig: vec![],
            sequence: sequence.unwrap_or(BitcoinTransactionInput::<N>::DEFAULT_SEQUENCE.to_vec()),
            sighash_code: sighash,
            witnesses: vec![],
            is_signed: false,
        })
    }

    /// Read and output a Bitcoin transaction input
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

        let script_sig: Vec<u8> = BitcoinVector::read(&mut reader, |s| {
            let mut byte = [0u8; 1];
            s.read(&mut byte)?;
            Ok(byte[0])
        })?;

        let mut sequence = [0u8; 4];
        reader.read(&mut sequence)?;

        let script_sig_len = read_variable_length_integer(&script_sig[..])?;
        let sighash = SignatureHash::from_byte(&match script_sig_len {
            0 => 0x01,
            length => script_sig[length],
        });

        Ok(Self {
            outpoint,
            script_sig: script_sig.to_vec(),
            sequence: sequence.to_vec(),
            sighash_code: sighash,
            witnesses: vec![],
            is_signed: script_sig.len() > 0,
        })
    }

    /// Returns the serialized transaction input.
    pub fn serialize(&self, raw: bool) -> Result<Vec<u8>, TransactionError> {
        let mut input = vec![];
        input.extend(&self.outpoint.reverse_transaction_id);
        input.extend(&self.outpoint.index.to_le_bytes());

        match raw {
            true => input.extend(vec![0x00]),
            false => match self.script_sig.len() {
                0 => {
                    let format = match &self.outpoint.address {
                        Some(address) => address.format(),
                        None => return Err(TransactionError::MissingOutpointAddress),
                    };
                    match format {
                        BitcoinFormat::Bech32 => input.extend(vec![0x00]),
                        _ => {
                            let script_pub_key = match &self.outpoint.script_pub_key {
                                Some(script) => script,
                                None => return Err(TransactionError::MissingOutpointScriptPublicKey),
                            };
                            input.extend(variable_length_integer(script_pub_key.len() as u64)?);
                            input.extend(script_pub_key);
                        }
                    }
                }
                _ => {
                    input.extend(variable_length_integer(self.script_sig.len() as u64)?);
                    input.extend(&self.script_sig);
                }
            },
        };

        input.extend(&self.sequence);
        Ok(input)
    }
}

/// Represents a Bitcoin transaction output
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTransactionOutput {
    /// The amount (in Satoshi)
    pub amount: u64,
    /// The public key script
    pub script_pub_key: Vec<u8>,
}

impl BitcoinTransactionOutput {
    /// Returns a Bitcoin transaction output.
    pub fn new<N: BitcoinNetwork>(address: &BitcoinAddress<N>, amount: u64) -> Result<Self, TransactionError> {
        Ok(Self {
            amount,
            script_pub_key: create_script_pub_key::<N>(address)?,
        })
    }

    /// Read and output a Bitcoin transaction output
    pub fn read<R: Read>(mut reader: &mut R) -> Result<Self, TransactionError> {
        let mut amount = [0u8; 8];
        reader.read(&mut amount)?;

        let script_pub_key: Vec<u8> = BitcoinVector::read(&mut reader, |s| {
            let mut byte = [0u8; 1];
            s.read(&mut byte)?;
            Ok(byte[0])
        })?;

        Ok(Self {
            amount: u64::from_le_bytes(amount),
            script_pub_key,
        })
    }

    /// Returns the serialized transaction output.
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let mut output = vec![];
        output.extend(&self.amount.to_le_bytes());
        output.extend(variable_length_integer(self.script_pub_key.len() as u64)?);
        output.extend(&self.script_pub_key);
        Ok(output)
    }
}

/// Represents an Bitcoin transaction id and witness transaction id
/// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTransactionId {
    txid: Vec<u8>,
    wtxid: Vec<u8>,
}

impl TransactionId for BitcoinTransactionId {}

impl fmt::Display for BitcoinTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &hex::encode(&self.txid))
    }
}

/// Represents the Bitcoin transaction parameters
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTransactionParameters<N: BitcoinNetwork> {
    /// The version number (4 bytes)
    pub version: u32,
    /// The transaction inputs
    pub inputs: Vec<BitcoinTransactionInput<N>>,
    /// The transaction outputs
    pub outputs: Vec<BitcoinTransactionOutput>,
    /// The lock time (4 bytes)
    pub lock_time: u32,
    /// An optional 2 bytes to indicate SegWit transactions
    pub segwit_flag: bool,
}

impl<N: BitcoinNetwork> BitcoinTransactionParameters<N> {
    /// Read and output the Bitcoin transaction parameters
    pub fn read<R: Read>(mut reader: R) -> Result<Self, TransactionError> {
        let mut version = [0u8; 4];
        reader.read(&mut version)?;

        let mut inputs = BitcoinVector::read(&mut reader, BitcoinTransactionInput::<N>::read)?;

        let segwit_flag = match inputs.is_empty() {
            true => {
                let mut flag = [0u8; 1];
                reader.read(&mut flag)?;
                match flag[0] {
                    1 => {
                        inputs = BitcoinVector::read(&mut reader, BitcoinTransactionInput::<N>::read)?;
                        true
                    }
                    _ => return Err(TransactionError::InvalidSegwitFlag(flag[0] as usize)),
                }
            }
            false => false,
        };

        let outputs = BitcoinVector::read(&mut reader, BitcoinTransactionOutput::read)?;

        if segwit_flag {
            for input in &mut inputs {
                let witnesses: Vec<Vec<u8>> = BitcoinVector::read(&mut reader, |s| {
                    let (size, witness) = BitcoinVector::read_witness(s, |sr| {
                        let mut byte = [0u8; 1];
                        sr.read(&mut byte)?;
                        Ok(byte[0])
                    })?;

                    Ok([variable_length_integer(size as u64)?, witness?].concat())
                })?;

                if witnesses.len() > 0 {
                    input.sighash_code = SignatureHash::from_byte(&witnesses[0][&witnesses[0].len() - 1]);
                }
                input.witnesses = witnesses;
            }
        }

        let mut lock_time = [0u8; 4];
        reader.read(&mut lock_time)?;

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: u32::from_le_bytes(version),
            inputs,
            outputs,
            lock_time: u32::from_le_bytes(lock_time),
            segwit_flag,
        };

        Ok(transaction_parameters)
    }
}

/// Represents a Bitcoin transaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTransaction<N: BitcoinNetwork> {
    /// The transaction parameters (version, inputs, outputs, lock_time, segwit_flag)
    parameters: BitcoinTransactionParameters<N>,
}

impl<N: BitcoinNetwork> Transaction for BitcoinTransaction<N> {
    type Address = BitcoinAddress<N>;
    type Format = BitcoinFormat;
    type PrivateKey = BitcoinPrivateKey<N>;
    type PublicKey = BitcoinPublicKey<N>;
    type TransactionId = BitcoinTransactionId;
    type TransactionParameters = BitcoinTransactionParameters<N>;

    /// Returns an unsigned transaction given the transaction parameters.
    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            parameters: parameters.clone(),
        })
    }

    /// Returns a signed transaction given the private key of the sender.
    fn sign(&self, private_key: &Self::PrivateKey) -> Result<Self, TransactionError> {
        let mut transaction = self.clone();
        for (vin, input) in self.parameters.inputs.iter().enumerate() {
            let address = match &input.outpoint.address {
                Some(address) => address,
                None => return Err(TransactionError::MissingOutpointAddress),
            };

            if address == &private_key.to_address(&address.format())? && !transaction.parameters.inputs[vin].is_signed {
                // Transaction hash
                let preimage = match &address.format() {
                    BitcoinFormat::P2PKH => transaction.p2pkh_hash_preimage(vin, input.sighash_code)?,
                    _ => transaction.segwit_hash_preimage(vin, input.sighash_code)?,
                };
                let transaction_hash = Sha256::digest(&Sha256::digest(&preimage));

                // Signature
                let mut signature = secp256k1::Secp256k1::signing_only()
                    .sign(
                        &secp256k1::Message::from_slice(&transaction_hash)?,
                        &private_key.to_secp256k1_secret_key(),
                    )
                    .serialize_der()
                    .to_vec();
                signature.push((input.sighash_code as u32).to_le_bytes()[0]);
                let signature = [variable_length_integer(signature.len() as u64)?, signature].concat();

                // Public key
                let public_key = private_key.to_public_key();
                let public_key_bytes = match (&address.format(), public_key.is_compressed()) {
                    (BitcoinFormat::P2PKH, false) => {
                        public_key.to_secp256k1_public_key().serialize_uncompressed().to_vec()
                    }
                    _ => public_key.to_secp256k1_public_key().serialize().to_vec(),
                };
                let public_key = [vec![public_key_bytes.len() as u8], public_key_bytes].concat();

                match &address.format() {
                    BitcoinFormat::P2PKH => {
                        transaction.parameters.inputs[vin].script_sig = [signature.clone(), public_key].concat();
                        transaction.parameters.inputs[vin].is_signed = true;
                    }
                    BitcoinFormat::P2SH_P2WPKH => {
                        let input_script = match &input.outpoint.redeem_script {
                            Some(redeem_script) => redeem_script.clone(),
                            None => return Err(TransactionError::InvalidInputs("P2SH_P2WPKH".into())),
                        };
                        transaction.parameters.segwit_flag = true;
                        transaction.parameters.inputs[vin].script_sig =
                            [variable_length_integer(input_script.len() as u64)?, input_script].concat();
                        transaction.parameters.inputs[vin]
                            .witnesses
                            .append(&mut vec![signature.clone(), public_key]);
                        transaction.parameters.inputs[vin].is_signed = true;
                    }
                    BitcoinFormat::Bech32 => {
                        transaction.parameters.segwit_flag = true;
                        transaction.parameters.inputs[vin]
                            .witnesses
                            .append(&mut vec![signature.clone(), public_key]);
                        transaction.parameters.inputs[vin].is_signed = true;
                    }
                };
            }
        }
        Ok(transaction)
    }

    /// Returns a transaction given the transaction bytes.
    /// Note:: Raw transaction hex does not include enough
    fn from_transaction_bytes(transaction: &Vec<u8>) -> Result<Self, TransactionError> {
        Ok(Self {
            parameters: Self::TransactionParameters::read(&transaction[..])?,
        })
    }

    /// Returns the transaction in bytes.
    fn to_transaction_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let mut transaction = self.parameters.version.to_le_bytes().to_vec();

        if self.parameters.segwit_flag {
            transaction.extend(vec![0x00, 0x01]);
        }

        transaction.extend(variable_length_integer(self.parameters.inputs.len() as u64)?);
        let mut has_witness = false;
        for input in &self.parameters.inputs {
            has_witness = input.witnesses.len() > 0;
            // TODO (howardwu): Implement "raw" bool for serializing the raw transaction.
            transaction.extend(input.serialize(false)?);
        }

        transaction.extend(variable_length_integer(self.parameters.outputs.len() as u64)?);
        for output in &self.parameters.outputs {
            transaction.extend(output.serialize()?);
        }

        if has_witness {
            for input in &self.parameters.inputs {
                match input.witnesses.len() {
                    0 => transaction.extend(vec![0x00]),
                    _ => {
                        transaction.extend(variable_length_integer(input.witnesses.len() as u64)?);
                        for witness in &input.witnesses {
                            transaction.extend(witness);
                        }
                    }
                };
            }
        }

        transaction.extend(&self.parameters.lock_time.to_le_bytes());

        Ok(transaction)
    }

    /// Returns the transaction id.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let mut txid = Sha256::digest(&Sha256::digest(&self.to_transaction_bytes_without_witness()?)).to_vec();
        let mut wtxid = Sha256::digest(&Sha256::digest(&self.to_transaction_bytes()?)).to_vec();

        txid.reverse();
        wtxid.reverse();

        Ok(Self::TransactionId { txid, wtxid })
    }
}

impl<N: BitcoinNetwork> BitcoinTransaction<N> {
    /// Return the P2PKH hash preimage of the raw transaction.
    pub fn p2pkh_hash_preimage(&self, vin: usize, sighash: SignatureHash) -> Result<Vec<u8>, TransactionError> {
        let mut preimage = self.parameters.version.to_le_bytes().to_vec();
        preimage.extend(variable_length_integer(self.parameters.inputs.len() as u64)?);
        for (index, input) in self.parameters.inputs.iter().enumerate() {
            preimage.extend(input.serialize(index != vin)?);
        }
        preimage.extend(variable_length_integer(self.parameters.outputs.len() as u64)?);
        for output in &self.parameters.outputs {
            preimage.extend(output.serialize()?);
        }
        preimage.extend(&self.parameters.lock_time.to_le_bytes());
        preimage.extend(&(sighash as u32).to_le_bytes());
        Ok(preimage)
    }

    /// Return the SegWit hash preimage of the raw transaction
    /// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
    pub fn segwit_hash_preimage(&self, vin: usize, sighash: SignatureHash) -> Result<Vec<u8>, TransactionError> {
        let mut prev_outputs = vec![];
        let mut prev_sequences = vec![];
        let mut outputs = vec![];

        for input in &self.parameters.inputs {
            prev_outputs.extend(&input.outpoint.reverse_transaction_id);
            prev_outputs.extend(&input.outpoint.index.to_le_bytes());
            prev_sequences.extend(&input.sequence);
        }

        for output in &self.parameters.outputs {
            outputs.extend(&output.serialize()?);
        }

        let input = &self.parameters.inputs[vin];
        let format = match &input.outpoint.address {
            Some(address) => address.format(),
            None => return Err(TransactionError::MissingOutpointAddress),
        };

        let script = match format {
            BitcoinFormat::Bech32 => match &input.outpoint.script_pub_key {
                Some(script) => script[1..].to_vec(),
                None => return Err(TransactionError::MissingOutpointScriptPublicKey),
            },
            BitcoinFormat::P2SH_P2WPKH => match &input.outpoint.redeem_script {
                Some(redeem_script) => redeem_script[1..].to_vec(),
                None => return Err(TransactionError::InvalidInputs("P2SH_P2WPKH".into())),
            },
            BitcoinFormat::P2PKH => return Err(TransactionError::UnsupportedPreimage("P2PKH".into())),
        };

        let mut script_code = vec![];
        script_code.push(Opcode::OP_DUP as u8);
        script_code.push(Opcode::OP_HASH160 as u8);
        script_code.extend(script);
        script_code.push(Opcode::OP_EQUALVERIFY as u8);
        script_code.push(Opcode::OP_CHECKSIG as u8);

        let script_code = [variable_length_integer(script_code.len() as u64)?, script_code].concat();
        let hash_prev_outputs = Sha256::digest(&Sha256::digest(&prev_outputs));
        let hash_sequence = Sha256::digest(&Sha256::digest(&prev_sequences));
        let hash_outputs = Sha256::digest(&Sha256::digest(&outputs));
        let outpoint_amount = match &input.outpoint.amount {
            Some(amount) => amount.to_le_bytes(),
            None => return Err(TransactionError::MissingOutpointAmount),
        };

        let mut preimage = vec![];
        preimage.extend(&self.parameters.version.to_le_bytes());
        preimage.extend(hash_prev_outputs);
        preimage.extend(hash_sequence);
        preimage.extend(&input.outpoint.reverse_transaction_id);
        preimage.extend(&input.outpoint.index.to_le_bytes());
        preimage.extend(&script_code);
        preimage.extend(&outpoint_amount);
        preimage.extend(&input.sequence);
        preimage.extend(hash_outputs);
        preimage.extend(&self.parameters.lock_time.to_le_bytes());
        preimage.extend(&(sighash as u32).to_le_bytes());

        Ok(preimage)
    }

    /// Returns the transaction with the traditional serialization (no witness).
    fn to_transaction_bytes_without_witness(&self) -> Result<Vec<u8>, TransactionError> {
        let mut transaction = self.parameters.version.to_le_bytes().to_vec();

        transaction.extend(variable_length_integer(self.parameters.inputs.len() as u64)?);
        for input in &self.parameters.inputs {
            transaction.extend(input.serialize(false)?);
        }

        transaction.extend(variable_length_integer(self.parameters.outputs.len() as u64)?);
        for output in &self.parameters.outputs {
            transaction.extend(output.serialize()?);
        }

        transaction.extend(&self.parameters.lock_time.to_le_bytes());

        Ok(transaction)
    }
}

impl<N: BitcoinNetwork> FromStr for BitcoinTransaction<N> {
    type Err = TransactionError;

    fn from_str(transaction: &str) -> Result<Self, Self::Err> {
        Self::from_transaction_bytes(&hex::decode(transaction)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mainnet;
    use wagyu_model::crypto::hash160;

    pub struct TransactionTestCase<'a> {
        pub version: u32,
        pub lock_time: u32,
        pub inputs: &'a [Input],
        pub outputs: &'a [Output],
        pub expected_signed_transaction: &'a str,
        pub expected_transaction_id: &'a str,
    }

    #[derive(Debug, Clone)]
    pub struct Input {
        pub private_key: &'static str,
        pub address_format: BitcoinFormat,
        pub transaction_id: &'static str,
        pub index: u32,
        pub redeem_script: Option<&'static str>,
        pub script_pub_key: Option<&'static str>,
        pub utxo_amount: u64,
        pub sequence: Option<[u8; 4]>,
        pub sighash_code: SignatureHash,
    }

    #[derive(Clone)]
    pub struct Output {
        pub address: &'static str,
        pub amount: u64,
    }

    fn test_transaction<N: BitcoinNetwork>(
        version: u32,
        lock_time: u32,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        expected_signed_transaction: &str,
        expected_transaction_id: &str,
    ) {
        let mut input_vec = vec![];
        for input in &inputs {
            let private_key = BitcoinPrivateKey::from_str(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();
            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = match (input.redeem_script, input.address_format.clone()) {
                (Some(script), _) => Some(hex::decode(script).unwrap()),
                (None, BitcoinFormat::P2SH_P2WPKH) => {
                    let mut redeem_script = vec![0x00, 0x14];
                    redeem_script.extend(&hash160(
                        &private_key.to_public_key().to_secp256k1_public_key().serialize(),
                    ));
                    Some(redeem_script)
                }
                (None, _) => None,
            };
            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());
            let transaction_input = BitcoinTransactionInput::<N>::new(
                &address,
                transaction_id,
                input.index,
                input.utxo_amount,
                redeem_script,
                script_pub_key,
                sequence,
                input.sighash_code,
            )
            .unwrap();

            input_vec.push(transaction_input);
        }

        let mut output_vec = vec![];
        for output in outputs {
            let address = BitcoinAddress::<N>::from_str(output.address).unwrap();
            output_vec.push(BitcoinTransactionOutput::new(&address, output.amount).unwrap());
        }

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time,
            segwit_flag: false,
        };

        let mut transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();

        for input in inputs {
            transaction = transaction
                .sign(&BitcoinPrivateKey::from_str(input.private_key).unwrap())
                .unwrap();
        }

        let signed_transaction = hex::encode(&transaction.to_transaction_bytes().unwrap());
        let transaction_id = hex::encode(&transaction.to_transaction_id().unwrap().txid);

        assert_eq!(expected_signed_transaction, &signed_transaction);
        assert_eq!(expected_transaction_id, &transaction_id);

        let mut new_transaction = BitcoinTransaction::<N>::from_str(&signed_transaction).unwrap();
        for input in transaction.parameters.inputs {
            new_transaction = update_outpoint(new_transaction, input.outpoint);
        }

        let new_signed_transaction = hex::encode(new_transaction.to_transaction_bytes().unwrap());
        let new_transaction_id = hex::encode(new_transaction.to_transaction_id().unwrap().txid);

        assert_eq!(expected_signed_transaction, &new_signed_transaction);
        assert_eq!(expected_transaction_id, &new_transaction_id);
    }

    /// Update a transaction's input outpoint
    fn update_outpoint<N: BitcoinNetwork>(
        transaction: BitcoinTransaction<N>,
        outpoint: Outpoint<N>,
    ) -> BitcoinTransaction<N> {
        let mut new_transaction = transaction.clone();
        for (vin, input) in transaction.parameters.inputs.iter().enumerate() {
            if &outpoint.reverse_transaction_id == &input.outpoint.reverse_transaction_id
                && &outpoint.index == &input.outpoint.index
            {
                new_transaction.parameters.inputs[vin].outpoint = outpoint.clone();
            }
        }
        new_transaction
    }

    mod test_valid_mainnet_transactions {
        use super::*;
        type N = Mainnet;

        const TRANSACTIONS: [TransactionTestCase; 9] = [
            TransactionTestCase { // p2pkh to p2pkh - based on https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/test/integration/transactions.js
                version: 1,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy",
                        address_format: BitcoinFormat::P2PKH,
                        transaction_id: "61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 0,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP",
                        amount: 12000
                    },
                ],
                expected_signed_transaction: "01000000019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d561000000006b48304502210088828c0bdfcdca68d8ae0caeb6ec62cd3fd5f9b2191848edae33feb533df35d302202e0beadd35e17e7f83a733f5277028a9b453d525553e3f5d2d7a7aa8010a81d60121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff01e02e0000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac00000000",
                expected_transaction_id: "7a68099c3f338fa61696a3c54404c88491e3b249e85574d6bbba01ac00ae33ff",
            },
            TransactionTestCase { // p2sh_p2wpkh to p2pkh - based on https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
                version: 1,
                lock_time: 1170,
                inputs: &[
                    Input {
                        private_key: "5Kbxro1cmUF9mTJ8fDrTfNB6URTBsFMUG52jzzumP2p9C94uKCh",
                        address_format: BitcoinFormat::P2SH_P2WPKH,
                        transaction_id: "77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 1000000000,
                        sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "1Fyxts6r24DpEieygQiNnWxUdb18ANa5p7",
                        amount: 199996600
                    },
                    Output {
                        address: "1Q5YjKVj5yQWHBBsyEBamkfph3cA6G9KK8",
                        amount: 800000000,
                    },
                ],
                expected_signed_transaction: "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000",
                expected_transaction_id: "ef48d9d0f595052e0f8cdcf825f7a5e50b6a388a81f206f3f4846e5ecd7a0c23",
            },
            TransactionTestCase { //p2sh_p2wpkh to segwit
                version: 2,
                lock_time: 140,
                inputs: &[
                    Input {
                        private_key: "KwtetKxofS1Lhp7idNJzb5B5WninBRfELdwkjvTMZZGME4G72kMz",
                        address_format: BitcoinFormat::P2SH_P2WPKH,
                        transaction_id: "375e1622b2690e395df21b33192bad06d2706c139692d43ea84d38df3d183313",
                        index: 0,
                        redeem_script: Some("0014b93f973eb2bf0b614bddc0f47286788c98c535b4"), // Manually specify redeem_script
                        script_pub_key: None,
                        utxo_amount: 1000000000,
                        sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "3H3Kc7aSPP4THLX68k4mQMyf1gvL6AtmDm",
                        amount: 100000000
                    },
                    Output {
                        address: "3MSu6Ak7L6RY5HdghczUcXzGaVVCusAeYj",
                        amount: 899990000,
                    },
                ],
                expected_signed_transaction: "020000000001011333183ddf384da83ed49296136c70d206ad2b19331bf25d390e69b222165e370000000017160014b93f973eb2bf0b614bddc0f47286788c98c535b4feffffff0200e1f5050000000017a914a860f76561c85551594c18eecceffaee8c4822d787f0c1a4350000000017a914d8b6fcc85a383261df05423ddf068a8987bf0287870247304402206214bf6096f0050f8442be6107448f89983a7399974f7160ba02e80f96383a3f02207b2a169fed3f48433850f39599396f8c8237260a57462795a83b85cceff5b1aa012102e1a2ba641bbad8399bf6e16a7824faf9175d246aef205599364cc5b4ad64962f8c000000",
                expected_transaction_id: "51f563f37b80c1fab7cc21eea1d6991ab9bd9069ddafb372e1c36e5fc5b56447",
            },
            TransactionTestCase { // p2pkh and p2sh_p2wpkh to p2pkh - based on https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/test/integration/transactions.js
                version: 1,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "L1Knwj9W3qK3qMKdTvmg3VfzUs3ij2LETTFhxza9LfD5dngnoLG1",
                        address_format: BitcoinFormat::P2PKH,
                        transaction_id: "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
                        index: 6,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 0,
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                    Input {
                        private_key: "KwcN2pT3wnRAurhy7qMczzbkpY5nXMW2ubh696UBc1bcwctTx26z",
                        address_format: BitcoinFormat::P2PKH,
                        transaction_id: "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 0,
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sighash_code: SignatureHash::SIGHASH_ALL
                    }
                ],
                outputs: &[
                    Output {
                        address: "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb",
                        amount: 180000
                    },
                    Output {
                        address: "1JtK9CQw1syfWj1WtFMWomrYdV3W2tWBF9",
                        amount: 170000
                    },
                ],
                expected_signed_transaction: "01000000024c94e48a870b85f41228d33cf25213dfcc8dd796e7211ed6b1f9a014809dbbb5060000006a473044022041450c258ce7cac7da97316bf2ea1ce66d88967c4df94f3e91f4c2a30f5d08cb02203674d516e6bb2b0afd084c3551614bd9cec3c2945231245e891b145f2d6951f0012103e05ce435e462ec503143305feb6c00e06a3ad52fbf939e85c65f3a765bb7baacffffffff3077d9de049574c3af9bc9c09a7c9db80f2d94caaf63988c9166249b955e867d000000006b483045022100aeb5f1332c79c446d3f906e4499b2e678500580a3f90329edf1ba502eec9402e022072c8b863f8c8d6c26f4c691ac9a6610aa4200edc697306648ee844cfbc089d7a012103df7940ee7cddd2f97763f67e1fb13488da3fbdd7f9c68ec5ef0864074745a289ffffffff0220bf0200000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac10980200000000001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac00000000",
                expected_transaction_id: "af0ae7ab766f49c33312d33541868c2185ad559cc0457e7af398311bda4f18f7",
            },
            TransactionTestCase { // p2sh_p2wsh to multiple address types
                version: 2,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "Kxxkik2L9KgrGgvdkEvYSkgAxaY4qPGfvxe1M1KBVBB7Ls3xDD8o",
                        address_format: BitcoinFormat::P2SH_P2WPKH,
                        transaction_id: "7c95424e4c86467eaea85b878985fa77d191bad2b9c5cac5a0cb98f760616afa",
                        index: 55,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 2000000,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "3DTGFEmobt8BaJpfPe62HvCQKp2iGsnYqD",
                        amount: 30000
                    },
                    Output {
                        address: "1NxCpkhj6n8orGdhPpxCD3B52WvoR4CS7S",
                        amount: 2000000
                    },
                ],
                expected_signed_transaction: "02000000000101fa6a6160f798cba0c5cac5b9d2ba91d177fa8589875ba8ae7e46864c4e42957c37000000171600143d295b6276ff8e4579f3350873db3e839e230f41ffffffff02307500000000000017a9148107a4409368488413295580eb88cbf7609cce658780841e00000000001976a914f0cb63944bcbbeb75c26492196939ae419c515a988ac024730440220243435ca67a713f6715d14d761b5ab073e88b30559a02f8b1add1aee8082f1c902207dfea838a2e815132999035245d9ebf51b4c740cbe4d95c609c7012ba9beb86301210324804353b8e10ce351d073da432fb046a4d13edf22052577a6e09cf9a5090cda00000000",
                expected_transaction_id: "ba4dfdff505035b1d70842bbcb3be160528b3b5261292124a9c1b58a0d34f7f8",
            },
            TransactionTestCase { // p2sh_p2wsh and p2pkh to multiple address types
                version: 2,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "L3EEWFaodvuDcH7yeTtugQDvNxnBs8Fkzerqf8tgmHYKQ4QkQJDE",
                        address_format: BitcoinFormat::P2PKH,
                        transaction_id: "6b88c087247aa2f07ee1c5956b8e1a9f4c7f892a70e324f1bb3d161e05ca107b",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 0,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                    Input {
                        private_key: "KzZtscUzkZS38CYqYfRZ8pUKfUr1JnAnwJLK25S8a6Pj6QgPYJkq",
                        address_format: BitcoinFormat::P2SH_P2WPKH,
                        transaction_id: "93ca92c0653260994680a4caa40cfc7b0aac02a077c4f022b007813d6416c70d",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 100000,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "36NCSwdvrL7XpiRSsfYWY99azC4xWgtL3X",
                        amount: 50000
                    },
                    Output {
                        address: "17rB37JzbUVmFuKMx8fexrHjdWBtDurpuL",
                        amount: 123456
                    },
                ],
                expected_signed_transaction: "020000000001027b10ca051e163dbbf124e3702a897f4c9f1a8e6b95c5e17ef0a27a2487c0886b000000006b483045022100b15c1d8e7de7c1d77612f80ab49c48c3d0c23467a0becaa86fcd98009d2dff6002200f3b2341a591889f38e629dc4b938faf9165aecedc4e3be768b13ef491cbb37001210264174f4ff6006a98be258fe1c371b635b097b000ce714c6a2842d5c269dbf2e9ffffffff0dc716643d8107b022f0c477a002ac0a7bfc0ca4caa4804699603265c092ca9301000000171600142b654d833c287e239f73ba8165bbadf4dee3c00effffffff0250c300000000000017a914334982bfd308f92f8ea5d22e9f7ee52f2265543b8740e20100000000001976a9144b1d83c75928642a41f2945c8a3be48550822a9a88ac0002483045022100a37e7aeb82332d5dc65d1582bb917acbf2d56a90f5a792a932cfec3c09f7a534022033baa11aa0f3ad4ba9723c703e65dce724ccb79c00838e09b96892087e43f1c8012102d9c6aaa344ee7cc41466e4705780020deb70720bef8ddb9b4e83e75df02e1d8600000000",
                expected_transaction_id: "0c76c2ad441b7853966ba2dae6fc3f0b890b81761ea3e1421f8df02e80a08050",
            },
            TransactionTestCase { // p2pkh to bech32
                version: 2,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "5JsX1A2JNjqVmLFUUhUJuDsVjFH2yfoVdV5qtFQpWhLkYzamKKy",
                        address_format: BitcoinFormat::P2PKH,
                        transaction_id: "bda2ebcbf0bd6bc4ee1c330a64a9ff95e839cc2d25c593a01e704996bc1e869c",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 0,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        amount: 1234
                    },
                    Output {
                        address: "bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9",
                        amount: 111
                    },
                ],
                expected_signed_transaction: "02000000019c861ebc9649701ea093c5252dcc39e895ffa9640a331ceec46bbdf0cbeba2bd000000008a473044022077be9faa83fc2289bb59eb7538c3801f513d3640466a48cea9845f3b26f14cd802207b80fda8836610c487e8b59105e682d1c438f98f6324d1ea74cdec5d2d74ef04014104cc58298806e4e233ad1acb81feeb90368e05ad79a1d4b3698156dc4766ca077f39fbb47f52cbd5282c15a8a9fb08401e678acb9ef2fd28e043164723e9f29bb2ffffffff02d204000000000000160014e8df018c7e326cc253faac7e46cdc51e68542c426f00000000000000220020c7a1f1a4d6b4c1802a59631966a18359de779e8a6a65973735a3ccdfdabc407d00000000",
                expected_transaction_id: "954c460ad8d9ea42e3679a4a70910a3be2e19c2cc8d6018d68038d9416db495e",
            },
            TransactionTestCase { // p2sh-p2wpkh to bech32
                version: 2,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "KzZtscUzkZS38CYqYfRZ8pUKfUr1JnAnwJLK25S8a6Pj6QgPYJkq",
                        address_format: BitcoinFormat::P2SH_P2WPKH,
                        transaction_id: "1a2290470e0aa7549ab1e04b2453274374149ffee517a57715e5206e4142c233",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 1500000,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", // witness version 1
                        amount: 100000000
                    },
                    Output {
                        address: "bc1qquxqz4f7wzen367stgwt25tf640gp4vud5vez0",
                        amount: 42500001
                    },
                ],
                expected_signed_transaction: "0200000000010133c242416e20e51577a517e5fe9f1474432753244be0b19a54a70a0e4790221a01000000171600142b654d833c287e239f73ba8165bbadf4dee3c00effffffff0200e1f505000000002a5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6a17f880200000000160014070c01553e70b338ebd05a1cb55169d55e80d59c02483045022100b5cf710307329d8634842c1894057ef243e172284e0908b215479e3b1889f62302205dfdd0287899e3034c95526bcfb1f437a0ca66de42a63c3c36aabb5b893459fb012102d9c6aaa344ee7cc41466e4705780020deb70720bef8ddb9b4e83e75df02e1d8600000000",
                expected_transaction_id: "7f9c4bc972b1b7749b9883b34bb26be3eb9fd8c4877818ae4c7c27e4cb5eda67",
            },
            TransactionTestCase { // p2pkh and bech32(p2wpkh) to multiple address types
                version: 1,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "L1X6apYnZ39CLFJFX6Ny7oriHX3nmeBcjkobeYgmk6arbyZfouJu",
                        address_format: BitcoinFormat::P2PKH,
                        transaction_id: "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: Some("76a9148631bf621f7c6671f8d2d646327b636cbbe79f8c88ac"), // Manually specify script_pub_key
                        utxo_amount: 0,
                        sequence: Some([0xee, 0xff, 0xff, 0xff]),
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                    Input {
                        private_key: "5JZGuGYM4vfKvpxaJg5g5D3uvVYVQ74UUdueCVvWCNacrAkkvGi",
                        address_format: BitcoinFormat::Bech32,
                        transaction_id: "8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 600000000,
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "bc1qgwu40h9vf3q9ua7llnsr29fws920enj8gflr4d",
                        amount: 10
                    },
                    Output {
                        address: "1AD97NRftXXd2rkHDU17x8uq21LWYJFNa1",
                        amount: 5555555
                    },
                    Output {
                        address: "3AnU6mchUQHZwgcRUD6JJaHe91fJ7UhajZ",
                        amount: 9182631
                    },
                ],
                expected_signed_transaction: "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000006b4830450221009eed10e4b7cc9eb23efc36dc9b0907d0b4dd224ae5d0ee9c92d7912c9a9cde7e02203ede96d667901abfb9f3997aba8e08c6b9de218db920916203f2632c713cd99c012103f4edae249cb015280d48cae959d1823440eeab74f9fc9752a8a18cba76c892b6eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff030a0000000000000016001443b957dcac4c405e77dffce035152e8154fcce4763c55400000000001976a9146504e4b146b24898cf7881b0bdcd059dc35dd5a888aca71d8c000000000017a91463c110106d813c69514b3d97e1a1e6c94ad1b56a870002483045022100cfff608b18a97cc46cf8d22e97e78b22343cfcc19028918a5cd06fc9031f532302201b877de8872619a832387d7d0e15482521e449ce0d4daeb2d080995317883cd60121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635700000000",
                expected_transaction_id: "62ee2045fa2e3ee0353fed70b39adac13cb4114dbafa3a60a12084104d14f1b0",
            }
        ];

        #[test]
        fn test_mainnet_transactions() {
            TRANSACTIONS.iter().for_each(|transaction| {
                test_transaction::<N>(
                    transaction.version,
                    transaction.lock_time,
                    transaction.inputs.to_vec(),
                    transaction.outputs.to_vec(),
                    transaction.expected_signed_transaction,
                    transaction.expected_transaction_id,
                );
            });
        }
    }

    mod test_real_mainnet_transactions {
        use super::*;
        type N = Mainnet;

        const REAL_TRANSACTIONS: [TransactionTestCase; 5] = [
            TransactionTestCase { // Transaction 1 -> Segwit P2SH_P2WPKH to P2PKH and Bech32(P2WPKH)
                version: 1,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "L1fUQgwdWcqGUAr3kFznuAP36Vw3oFeGHH29XRYMwxN1HpSw5yBm",
                        address_format: BitcoinFormat::P2SH_P2WPKH,
                        transaction_id: "a5766fafb27aba97e7aeb3e71be79806dd23f03bbd1b61135bf5792159f42ab6",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 80000,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "176DPNootfp2bSiE7KQUZp1VZj5EyGQeCt",
                        amount: 35000
                    },
                    Output {
                        address: "bc1qcsjz44ce84j3650qfu9k87tyd3z8h4qyxz470n",
                        amount: 35000
                    },
                ],
                expected_signed_transaction: "01000000000101b62af4592179f55b13611bbd3bf023dd0698e71be7b3aee797ba7ab2af6f76a50000000017160014b5ccbe3c5a285af4afada113a8619827fb30b2eeffffffff02b8880000000000001976a91442cd2c7460acc561c96b11c4aa96d0346b84db7f88acb888000000000000160014c4242ad7193d651d51e04f0b63f9646c447bd404024730440220449ca32ff3f8da3c17c1813dac91010cb1fea7a77b2f63065184b8318e1b9ed70220315da34cfeae62c26557c40f5ac5cde46b2801349e6677fc96597b4bfee04b0b012102973e9145ca85357b06de3009a12db171d70bae8a648dc8188e49723a2a46459100000000",
                expected_transaction_id: "60805eb82c53d9c53900ad6d1c423ffc2235caa0c266625afd9cf03e856bf92c",
            },
            TransactionTestCase { // Transaction 2 -> P2PKH to P2SH_P2WPKH and P2PKH uncompressed
                version: 1,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "KzZQ4ZzAecDmeDqxEJqSKpCfpPCa1x74ouyBhXUgMV2UdqNcaJiJ",
                        address_format: BitcoinFormat::P2PKH,
                        transaction_id: "60805eb82c53d9c53900ad6d1c423ffc2235caa0c266625afd9cf03e856bf92c",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 0,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "3QDTHVyuJrHixUhhsdZXQ7M8P9MQngmw1P",
                        amount: 12000
                    },
                    Output {
                        address: "1C5RdoaGMVyQy8qjk96NsL4dW79aVPYrCK",
                        amount: 12000
                    },
                ],
                expected_signed_transaction: "01000000012cf96b853ef09cfd5a6266c2a0ca3522fc3f421c6dad0039c5d9532cb85e8060000000006a473044022079471aadca4be014260a4788e7dc7d7168712c8f21c536f326caccb843569ab802206c7b464e3fbe0518f147ee7c5fa39c05e04e7ed17fbe464a2773b179fe0ef35401210384faa5d9710f727523906f6d2fe781b40cf58a3139d02eeaad293dd03be7b69cffffffff02e02e00000000000017a914f7146aaa6f24a1012528c1d27cfe49d256d5a70187e02e0000000000001976a914797f9c80ef57ba7f30b31598383683923a5a7a7c88ac00000000",
                expected_transaction_id: "76ef90fa70e4c10adc358432a979683a2cf1855ff545f88c5022dea8863ed5ab",
            },
            TransactionTestCase { // Transaction 3 -> Bech32 (P2WPKH) to P2SH_P2WPKH
                version: 1,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "L5HiUByNV6D4anzT5aMhheZpG9oKdcvoPXjWJopEPiEzFisNTM7X",
                        address_format: BitcoinFormat::Bech32,
                        transaction_id: "60805eb82c53d9c53900ad6d1c423ffc2235caa0c266625afd9cf03e856bf92c",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 35000,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "3QDTHVyuJrHixUhhsdZXQ7M8P9MQngmw1P",
                        amount: 25000
                    },
                ],
                expected_signed_transaction: "010000000001012cf96b853ef09cfd5a6266c2a0ca3522fc3f421c6dad0039c5d9532cb85e80600100000000ffffffff01a86100000000000017a914f7146aaa6f24a1012528c1d27cfe49d256d5a701870247304402206af8b1cad8d8138631f2b2b08535643afb0c9597e1dd9b8daa4a565be274c96902203844c6af50658fb244370afaaffdb6f6e85ca681b80cd094bfd4f3eeae4febf0012103dcf5a50ac66bde7fe9f01c4710fb5d438d51f1da1ce138863d34fee6499f328900000000",
                expected_transaction_id: "32464234781c37831398b5d2f1e1766f8dbb55ac3b41ed047e365c07e9b03429",
            },
            TransactionTestCase { // Transaction 4 -> Segwit P2SH_P2WPKH to Bech32(P2WPKH) and itself
                version: 1,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "L5TmwLMEyEqMAYj1qd7Fx9YRhNJTCvNn4ofr98ErbgHA99GjLBXC",
                        address_format: BitcoinFormat::P2SH_P2WPKH,
                        transaction_id: "32464234781c37831398b5d2f1e1766f8dbb55ac3b41ed047e365c07e9b03429",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 25000,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                    Input {
                        private_key: "L5TmwLMEyEqMAYj1qd7Fx9YRhNJTCvNn4ofr98ErbgHA99GjLBXC",
                        address_format: BitcoinFormat::P2SH_P2WPKH,
                        transaction_id: "76ef90fa70e4c10adc358432a979683a2cf1855ff545f88c5022dea8863ed5ab",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 12000,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "bc1qzkuhp5jxuvwx90eg65wkxuw6y2pfe740yw6h5s",
                        amount: 12000
                    },
                    Output {
                        address: "3QDTHVyuJrHixUhhsdZXQ7M8P9MQngmw1P",
                        amount: 15000
                    },
                ],
                expected_signed_transaction: "010000000001022934b0e9075c367e04ed413bac55bb8d6f76e1f1d2b5981383371c78344246320000000017160014354816a98500d7df9201d46e008c203dd5143b92ffffffffabd53e86a8de22508cf845f55f85f12c3a6879a9328435dc0ac1e470fa90ef760000000017160014354816a98500d7df9201d46e008c203dd5143b92ffffffff02e02e00000000000016001415b970d246e31c62bf28d51d6371da22829cfaaf983a00000000000017a914f7146aaa6f24a1012528c1d27cfe49d256d5a7018702483045022100988bc569371f74d6e49f20ae05ab06abfbe7ba92bbc177b61e38c0c9f430646702207a874da47387b6cfc066c26c24c99ccb75dac6772a0f94b7327703bdb156c4c8012103f850b5fa8fe53be8675dd3045ed89c8a4235155b484d88eb62d0afed7cb9ef050247304402204296465f1f95480f058ccebd70a0f80b9f092021a15793c954f39373e1e6500102206ca2d3f6cb68d1a9fde36ed6ded6509e2284c6afe860abf7f49c3ae18944ffdf012103f850b5fa8fe53be8675dd3045ed89c8a4235155b484d88eb62d0afed7cb9ef0500000000",
                expected_transaction_id: "6a06bd83718f24dd1883332939e59fdd26b95d8a328eac37a45b7c489618eac8",
            },
            TransactionTestCase { // Transaction 5 -> P2SH_P2WPKH, P2PKH uncompressed, and Bech32(P2WPKH) to Bech32(P2WPKH)
                version: 1,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "L5TmwLMEyEqMAYj1qd7Fx9YRhNJTCvNn4ofr98ErbgHA99GjLBXC",
                        address_format: BitcoinFormat::P2SH_P2WPKH,
                        transaction_id: "6a06bd83718f24dd1883332939e59fdd26b95d8a328eac37a45b7c489618eac8",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 15000,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                    Input {
                        private_key: "5KRoKpnWWav74XDgz28opnJUsBozUg8STwEQPq354yUa3MiXySn",
                        address_format: BitcoinFormat::P2PKH,
                        transaction_id: "76ef90fa70e4c10adc358432a979683a2cf1855ff545f88c5022dea8863ed5ab",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 0,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                    Input {
                        private_key: "Kzs2rY8y9brmULJ3VK9gZHiZAhNJ2ttjn7ZuyJbG52pToZfCpQDr",
                        address_format: BitcoinFormat::Bech32,
                        transaction_id: "6a06bd83718f24dd1883332939e59fdd26b95d8a328eac37a45b7c489618eac8",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: 12000,
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "bc1qmj865gnmg3hv7eh74qmvu5fcde43ecd7haa5hy",
                        amount: 30000
                    },
                ],
                expected_signed_transaction: "01000000000103c8ea1896487c5ba437ac8e328a5db926dd9fe53929338318dd248f7183bd066a0100000017160014354816a98500d7df9201d46e008c203dd5143b92ffffffffabd53e86a8de22508cf845f55f85f12c3a6879a9328435dc0ac1e470fa90ef76010000008b4830450221008bf28b9f9e2c6d7d0ef9705b7fd914e7693b2f4f3584deff6dfa9dc83fc9f73402201cdbf5cd78bf04ccedfa11f17cff3728965dd328d30fad4f91ba2be57fb2ccab014104db232c08ac5f0332d317e6cd805f3e29e98b93fc9ca74831a6c5d27a0368cdb0862d536a445250a8de9d92cf1d450c7dc9b8efd6ca2ff0865d553f85f1bd346fffffffffc8ea1896487c5ba437ac8e328a5db926dd9fe53929338318dd248f7183bd066a0000000000ffffffff013075000000000000160014dc8faa227b446ecf66fea836ce51386e6b1ce1be02483045022100c77d6548c8f068d7088d1a5eab91be1f4bd394fdd7e7334699ccb1533af2c6300220621399e24b9f84bb580fab62ced44b979f0b5a06a1c429ffe4f8c2ae27f740fb012103f850b5fa8fe53be8675dd3045ed89c8a4235155b484d88eb62d0afed7cb9ef05000247304402205b3676bb82313d8ed25dec2efc30aa24076b4a5c0dc0e2b2953507a8135a470102207cad2e535a5cac8b947c9d37aeb9162ec745c61b7133eafba790442faa2a19000121030f36fbc8825fcdc2b79e5764b6bb70c2038bf4dba63dbf71483320e4d7f63a0500000000",
                expected_transaction_id: "b2eb46fe6f8075caf013cd8e947f3b9dc06a416896d28aef450c9ec8d310361f",
            }
        ];

        #[test]
        fn test_real_mainnet_transactions() {
            REAL_TRANSACTIONS.iter().for_each(|transaction| {
                test_transaction::<N>(
                    transaction.version,
                    transaction.lock_time,
                    transaction.inputs.to_vec(),
                    transaction.outputs.to_vec(),
                    transaction.expected_signed_transaction,
                    transaction.expected_transaction_id,
                );
            });
        }
    }

    mod test_invalid_transactions {
        use super::*;
        type N = Mainnet;

        const INVALID_INPUTS: [Input; 7] = [
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: BitcoinFormat::P2SH_P2WPKH,
                transaction_id: "61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d",
                index: 0,
                redeem_script: None,
                script_pub_key: None,
                utxo_amount: 0,
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: BitcoinFormat::P2PKH,
                transaction_id: "7dabce",
                index: 0,
                redeem_script: None,
                script_pub_key: Some("a914e39b100350d6896ad0f572c9fe452fcac549fe7b87"),
                utxo_amount: 10000,
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: BitcoinFormat::P2SH_P2WPKH,
                transaction_id: "7dabce",
                index: 0,
                redeem_script: Some("00142b6e15d83c28acd7e2373ba81bb4adf4dee3c01a"),
                script_pub_key: None,
                utxo_amount: 10000,
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: BitcoinFormat::P2SH_P2WPKH,
                transaction_id: "7dabce588a8a57786790",
                index: 0,
                redeem_script: Some("00142b6e15d83c28acd7e2373ba81bb4adf4dee3c01a"),
                script_pub_key: None,
                utxo_amount: 10000,
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: BitcoinFormat::P2SH_P2WPKH,
                transaction_id: "7dabce588a8a57786790d27810514f5ffccff4148a8105894da57c985d02cdbb7dabce",
                index: 0,
                redeem_script: Some("00142b6e15d83c28acd7e2373ba81bb4adf4dee3c01a"),
                script_pub_key: None,
                utxo_amount: 10000,
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: BitcoinFormat::Bech32,
                transaction_id: "61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d",
                index: 0,
                redeem_script: Some("00142b6e15d83c28acd7e2373ba81bb4adf4dee3c01a"),
                script_pub_key: None,
                utxo_amount: 0,
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "",
                address_format: BitcoinFormat::P2PKH,
                transaction_id: "",
                index: 0,
                redeem_script: Some(""),
                script_pub_key: None,
                utxo_amount: 0,
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

                let private_key = BitcoinPrivateKey::<N>::from_str(input.private_key);
                match private_key {
                    Ok(private_key) => {
                        let address = private_key.to_address(&input.address_format).unwrap();
                        let invalid_input = BitcoinTransactionInput::<N>::new(
                            &address,
                            transaction_id,
                            input.index,
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
