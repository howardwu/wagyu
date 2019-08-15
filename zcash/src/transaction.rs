use crate::address::{ZcashAddress, Format};
use crate::network::ZcashNetwork;
use crate::private_key::ZcashPrivateKey;
use crate::public_key::ZcashPublicKey;

use base58::{FromBase58};
use blake2b_simd::{Hash, Params};
use secp256k1;
use serde::Serialize;
use std::{fmt, marker::PhantomData, str::FromStr};
use wagyu_model::{PrivateKey, TransactionError, Transaction};

/// Represents the signature hash opcode
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum SigHashCode {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 128,
}

/// Represents the commonly used script opcodes
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum OPCodes {
    OP_DUP = 0x76,
    OP_HASH160 = 0xa9,
    OP_CHECKSIG = 0xac,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
}

impl fmt::Display for SigHashCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SigHashCode::SIGHASH_ALL => write!(f, "SIGHASH_ALL"),
            SigHashCode::SIGHASH_NONE => write!(f, "SIGHASH_NONE"),
            SigHashCode::SIGHASH_SINGLE => write!(f, "SIGHASH_SINGLE"),
            SigHashCode::SIGHASH_ANYONECANPAY => write!(f, "SIGHASH_ANYONECANPAY"),
        }
    }
}

impl fmt::Display for OPCodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OPCodes::OP_DUP => write!(f, "OP_DUP"),
            OPCodes::OP_HASH160 => write!(f, "OP_HASH160"),
            OPCodes::OP_CHECKSIG => write!(f, "OP_CHECKSIG"),
            OPCodes::OP_EQUAL => write!(f, "OP_EQUAL"),
            OPCodes::OP_EQUALVERIFY => write!(f, "OP_EQUALVERIFY"),
        }
    }
}

/// Represents a Zcash transaction - Sapling
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZcashTransaction<N: ZcashNetwork> {
    /// Transactions header - overwintered flag and transaction version (04000080 for sapling)
    pub header : u32,
    /// Version group ID (0x892F2085 for sapling)
    pub version_group_id : u32,
    /// Transaction inputs
    pub inputs: Vec<ZcashTransactionInput<N>>,
    /// Transaction outputs
    pub outputs: Vec<ZcashTransactionOutput<N>>,
    /// Lock time - 4 bytes
    pub lock_time: u32,
    /// Expiration block (0 to disable)
    pub expiry_height: u32,
    /// Net value of sapling spend transfers minus output transfers
    pub value_balance: i64,
    /// Transaction shielded spends
    pub shielded_spends: Option<Vec<ShieldedSpend>>,
    /// Transaction shielded outputs
    pub shielded_outputs: Option<Vec<ShieldedOutput>>,
    /// Transaction join splits
    pub join_splits: Option<Vec<JoinSplit>>,
}

/// Represents a Zcash transaction input
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZcashTransactionInput<N: ZcashNetwork> {
    /// OutPoint - transaction id and index - 36 bytes
    pub out_point: OutPoint<N>,
    /// Tx-in script - Variable size
    pub script: Vec<u8>,
    /// Sequence number - 4 bytes (normally 0xFFFFFFFF, unless lock > 0)
    /// Also used in replace-by-fee - BIP 125.
    pub sequence: Vec<u8>,
    /// SIGHASH Code - 4 Bytes (used in signing raw transaction only)
    pub sig_hash_code: SigHashCode,
    /// Witnesses used in segwit transactions
    pub witnesses: Vec<Vec<u8>>,
}

/// Represents a Zcash transaction output
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZcashTransactionOutput<N: ZcashNetwork> {
    /// Transfer amount in Satoshi
    pub amount: u64,
    /// Output public key script
    pub output_public_key: Vec<u8>,
    /// PhantomData
    _network: PhantomData<N>,
}

/// Represents a specific UTXO
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint<N: ZcashNetwork> {
    /// Previous transaction hash (using Zcash RPC's reversed hash order) - 32 bytes
    pub reverse_transaction_id: Vec<u8>,
    /// Index of the transaction being used - 4 bytes
    pub index: u32,
    /// Amount associated with the UTXO - used for segwit transaction signatures
    pub amount: u64,
    /// Script public key asssociated with claiming this particular input UTXO
    pub script_pub_key: Vec<u8>,
    /// Optional redeem script - for segwit transactions
    pub redeem_script: Vec<u8>,
    /// Address of the outpoint
    pub address: ZcashAddress<N>,
}

/// Represents a Zcash transaction Shielded Spend
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShieldedSpend {}

/// Represents a Zcash transaction Shielded Output
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShieldedOutput {}

/// Represents a Zcash transaction Join Split
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JoinSplit {}

impl <N: ZcashNetwork> Transaction for ZcashTransaction<N> {
    type Address = ZcashAddress<N>;
    type Format = Format;
    type PrivateKey = ZcashPrivateKey<N>;
    type PublicKey = ZcashPublicKey<N>;
}

impl <N: ZcashNetwork> ZcashTransaction<N> {
    /// Returns a raw unsigned zcash transaction
    pub fn build_raw_transaction(
        header: u32,
        version_group_id: u32,
        inputs: Vec<ZcashTransactionInput<N>>,
        outputs: Vec<ZcashTransactionOutput<N>>,
        lock_time: u32,
        expiry_height: u32,
        value_balance: i64,
        shielded_spends: Option<Vec<ShieldedSpend>>,
        shielded_outputs: Option<Vec<ShieldedOutput>>,
        join_splits: Option<Vec<JoinSplit>>,
    ) -> Result<Self, TransactionError> {
        Ok(
            Self {
                header,
                version_group_id,
                inputs,
                outputs,
                lock_time,
                expiry_height,
                value_balance,
                shielded_spends,
                shielded_outputs,
                join_splits,
            }
        )
    }

    /// Returns the transaction as a byte vector
    pub fn serialize_transaction(&mut self, raw: bool) -> Result<Vec<u8>, TransactionError> {
        let mut serialized_transaction: Vec<u8> = Vec::new();

        serialized_transaction.extend(&self.header.to_le_bytes());
        serialized_transaction.extend(&self.version_group_id.to_le_bytes());
        serialized_transaction.extend(variable_length_integer(self.inputs.len() as u64)?);

        for input in &self.inputs {
            serialized_transaction.extend(input.serialize(raw, false)?);
        }

        serialized_transaction.extend(variable_length_integer(self.outputs.len() as u64)?);

        for output in  &self.outputs {
            serialized_transaction.extend(output.serialize()?);
        }

        serialized_transaction.extend(&self.lock_time.to_le_bytes());
        serialized_transaction.extend(&self.expiry_height.to_le_bytes());
        serialized_transaction.extend(&self.value_balance.to_le_bytes());

        match &self.shielded_spends {
            Some(_shielded_spends) => unimplemented!(),
            None => serialized_transaction.push(0u8),
        }

        match &self.shielded_outputs {
            Some(_shielded_outputs) => unimplemented!(),
            None => serialized_transaction.push(0u8),
        }

        match &self.join_splits {
            Some(_join_splits) => unimplemented!(),
            None => serialized_transaction.push(0u8),
        }

        Ok(serialized_transaction)
    }

    /// Signs the raw transaction, updates the transaction, and returns the signature
    pub fn sign_raw_transaction(&mut self,
                                private_key: <Self as Transaction>::PrivateKey,
                                input_index: usize,
    ) -> Result<Vec<u8>, TransactionError> {
        let input = &self.inputs[input_index];
        let transaction_hash_preimage = match input.out_point.address.format() {
            Format::P2PKH => self.generate_hash_preimage(input_index, input.sig_hash_code)?,
            _ => unimplemented!(),
        };

        let transaction_hash = blake2_256_hash("ZcashSigHash", transaction_hash_preimage, Some("sapling"));
        let message = secp256k1::Message::from_slice(&transaction_hash.as_bytes())?;
        let spending_key = &private_key;
        let mut signature = match spending_key {
            ZcashPrivateKey::P2PKH(p2pkh_spending_key) => {
                secp256k1::Secp256k1::signing_only().sign(&message, &p2pkh_spending_key.to_secp256k1_secret_key()).serialize_der().to_vec()
            },
            _ => unimplemented!(),
        };

        signature.push((input.sig_hash_code as u32).to_le_bytes()[0]);
        let signature = [variable_length_integer(signature.len() as u64)?, signature].concat();

        let viewing_key = private_key.to_public_key();
        let viewing_key_bytes = match viewing_key {
            ZcashPublicKey::P2PKH(p2pkh_view_key) => {
                match p2pkh_view_key.is_compressed() {
                    true => p2pkh_view_key.to_secp256k1_public_key().serialize().to_vec(),
                    false => p2pkh_view_key.to_secp256k1_public_key().serialize_uncompressed().to_vec(),
                }
            }
            _ => unimplemented!(),
        };

        let public_key: Vec<u8> = [vec![viewing_key_bytes.len() as u8], viewing_key_bytes].concat();

        match input.out_point.address.format() {
            Format::P2PKH => self.inputs[input_index].script = [signature.clone(), public_key].concat(),
            _ => unimplemented!(),
        };

        Ok(signature)
    }

    /// Return the hash preimage of the raw transaction
    /// https://github.com/zcash/zips/blob/master/zip-0243.rs
    pub fn generate_hash_preimage(
        &self,
        input_index: usize,
        sig_hash_code: SigHashCode
    ) -> Result<Vec<u8>, TransactionError> {

        let mut prev_outputs: Vec<u8> = Vec::new();
        let mut prev_sequences: Vec<u8> = Vec::new();
        let mut outputs: Vec<u8> = Vec::new();

        for input in &self.inputs {
            prev_outputs.extend(&input.out_point.reverse_transaction_id);
            prev_outputs.extend(&input.out_point.index.to_le_bytes());
            prev_sequences.extend(&input.sequence);
        }

        for output in &self.outputs {
            outputs.extend(&output.serialize()?);
        }

        let hash_prev_outputs = blake2_256_hash("ZcashPrevoutHash", prev_outputs, None);
        let hash_sequence = blake2_256_hash("ZcashSequencHash", prev_sequences, None);
        let hash_outputs = blake2_256_hash("ZcashOutputsHash", outputs, None);
        let hash_joinsplits = [0u8; 32];
        let hash_shielded_spends = [0u8; 32];
        let hash_shielded_outputs = [0u8; 32];

        let mut transaction_hash_preimage: Vec<u8> = Vec::new();
        transaction_hash_preimage.extend(&self.header.to_le_bytes());
        transaction_hash_preimage.extend(&self.version_group_id.to_le_bytes());
        transaction_hash_preimage.extend(hash_prev_outputs.as_bytes());
        transaction_hash_preimage.extend(hash_sequence.as_bytes());
        transaction_hash_preimage.extend(hash_outputs.as_bytes());
        transaction_hash_preimage.extend(&hash_joinsplits);
        transaction_hash_preimage.extend(&hash_shielded_spends);
        transaction_hash_preimage.extend(&hash_shielded_outputs);
        transaction_hash_preimage.extend(&self.lock_time.to_le_bytes());
        transaction_hash_preimage.extend(&self.expiry_height.to_le_bytes());
        transaction_hash_preimage.extend(&self.value_balance.to_le_bytes());
        transaction_hash_preimage.extend(&(sig_hash_code as u32).to_le_bytes());
        transaction_hash_preimage.extend( &self.inputs[input_index].serialize(false,true)?);

        Ok(transaction_hash_preimage)
    }
}

impl <N: ZcashNetwork> ZcashTransactionInput<N> {
    const DEFAULT_SEQUENCE: [u8; 4] =  [0xff, 0xff, 0xff, 0xff];

    /// Create a new Zcash Transaction input without the script
    pub fn new(
        address: ZcashAddress<N>,
        transaction_id: Vec<u8>,
        index: u32,
        amount: Option<u64>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
        sequence: Option<Vec<u8>>,
        sig_hash_code: SigHashCode
    ) -> Result<Self,  TransactionError> {
        if transaction_id.len() != 32 {
            return Err(TransactionError::InvalidTransactionId(transaction_id.len()));
        }

        // Reverse hash order - https://bitcoin.org/en/developer-reference#hash-byte-order
        let mut reverse_transaction_id = transaction_id;
        reverse_transaction_id.reverse();

        let script_pub_key = script_pub_key.unwrap_or(generate_script_pub_key::<N>(&address.to_string())?);
        let (amount, redeem_script) = validate_address_format(
            &address.format(),
            &amount,
            &redeem_script,
            &script_pub_key
        )?;

        let out_point = OutPoint { reverse_transaction_id, index, amount, redeem_script, script_pub_key, address };
        let sequence = sequence.unwrap_or(ZcashTransactionInput::<N>::DEFAULT_SEQUENCE.to_vec());

        Ok(Self { out_point, script: Vec::new(), sequence, sig_hash_code, witnesses: Vec::new() })
    }

    /// Serialize the transaction input
    pub fn serialize(&self, raw: bool, hash_preimage: bool) -> Result<Vec<u8>, TransactionError> {
        let mut serialized_input: Vec<u8> = Vec::new();
        serialized_input.extend(&self.out_point.reverse_transaction_id);
        serialized_input.extend(&self.out_point.index.to_le_bytes());

        match raw {
            true => serialized_input.extend(vec![0x00]),
            false => {
                if self.script.len() == 0 {
                    let script_pub_key = &self.out_point.script_pub_key.clone();
                    serialized_input.extend(variable_length_integer(script_pub_key.len() as u64)?);
                    serialized_input.extend(script_pub_key);
                } else {
                    serialized_input.extend(variable_length_integer(self.script.len() as u64)?);
                    serialized_input.extend(&self.script);
                }
            }
        };

        if hash_preimage {
            serialized_input.extend(&self.out_point.amount.to_le_bytes());
        };

        serialized_input.extend(&self.sequence);
        Ok(serialized_input)
    }
}

impl <N: ZcashNetwork> ZcashTransactionOutput<N> {
    /// Create a new Zcash transaction output
    pub fn new(address: &str, amount: u64) -> Result<Self, TransactionError> {
        Ok(
            Self {
                amount,
                output_public_key: generate_script_pub_key::<N>(address)?,
                _network: PhantomData
            }
        )
    }

    /// Serialize the transaction output
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let mut serialized_output: Vec<u8> = Vec::new();
        serialized_output.extend(&self.amount.to_le_bytes());
        serialized_output.extend( variable_length_integer(self.output_public_key.len() as u64)?);
        serialized_output.extend(&self.output_public_key);
        Ok(serialized_output)
    }
}

fn blake2_256_hash(personalization: &str, message: Vec<u8>, consensus_id: Option<&str>) -> Hash {

    let personalization = match consensus_id {
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

/// Generate the script_pub_key of a corresponding address
pub fn generate_script_pub_key<N: ZcashNetwork>(address: &str) -> Result<Vec<u8>, TransactionError> {
    let address = ZcashAddress::<N>::from_str(address)?;
    let mut script: Vec<u8> = Vec::new();
    let format = address.format();
    match format {
        Format::P2PKH => {
            let address_bytes = &address.to_string().from_base58()?;
            let pub_key_hash = address_bytes[2..(address_bytes.len()-4)].to_vec();

            script.push(OPCodes::OP_DUP as u8);
            script.push(OPCodes::OP_HASH160 as u8);
            script.extend(variable_length_integer(pub_key_hash.len() as u64)?);
            script.extend(pub_key_hash);
            script.push(OPCodes::OP_EQUALVERIFY as u8);
            script.push(OPCodes::OP_CHECKSIG as u8);
        },
        _ => unreachable!(),
    }

    Ok(script)
}

/// Determine the address type (P2PKH, P2SH_P2PKH, etc.) with the given scripts
pub fn validate_address_format(
    address_format: &Format,
    amount: &Option<u64>,
    redeem_script: &Option<Vec<u8>>,
    script_pub_key: &Vec<u8>
) -> Result<(u64, Vec<u8>), TransactionError> {
    let op_dup = OPCodes::OP_DUP as u8;
    let op_hash160 = OPCodes::OP_HASH160 as u8;
    let op_checksig = OPCodes::OP_CHECKSIG as u8;

    if address_format == &Format::P2PKH
        && script_pub_key[0] != op_dup
        && script_pub_key[1] != op_hash160
        && script_pub_key[script_pub_key.len() - 1] != op_checksig
    {
        return Err(TransactionError::InvalidScriptPubKey("P2PKH".into()));
    }

    Ok((
        amount.unwrap_or(0),
        redeem_script.clone().unwrap_or(Vec::new())
    ))
}

/// Return the variable length integer of the size
/// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
pub fn variable_length_integer(size: u64) -> Result<Vec<u8>, TransactionError> {
    if size < 253 {
        Ok(vec![size as u8])
    } else if size <= 65535 { // u16::max_value()
        Ok([vec![0xfd], (size as u16).to_le_bytes().to_vec()].concat())
    } else if size <= 4294967295 { // u32::max_value()
        Ok([vec![0xfe], (size as u32).to_le_bytes().to_vec()].concat())
    } else {
        Ok([vec![0xff], size.to_le_bytes().to_vec()].concat())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mainnet;
    use crate::Testnet;

    pub struct Transaction {
        pub header: u32,
        pub version_group_id: u32,
        pub lock_time: u32,
        pub expiry_height: u32,
        pub value_balance: i64,
        pub inputs: [Input; 4],
        pub outputs: [Output; 8],
        pub expected_signed_transaction: &'static str,
    }

    #[derive(Clone)]
    pub struct Input {
        pub private_key: &'static str,
        pub address_format: Format,
        pub transaction_id: &'static str,
        pub index: u32,
        pub redeem_script: Option<&'static str>,
        pub script_pub_key: Option<&'static str>,
        pub utxo_amount: Option<u64>,
        pub sequence: Option<[u8; 4]>,
        pub sig_hash_code: SigHashCode,
    }

    #[derive(Clone)]
    pub struct Output {
        pub address: &'static str,
        pub amount: u64,
    }

    const INPUT_FILLER: Input = Input {
        private_key: "L32wMPwuyeRFjK6KfdL9xssik3BR4RwuTfDUPYrkyURSrfu9uwmv",
        address_format: Format::P2PKH,
        transaction_id: "",
        index: 0,
        redeem_script: Some(""),
        script_pub_key: None,
        utxo_amount: None,
        sequence: None,
        sig_hash_code: SigHashCode::SIGHASH_ALL,
    };

    const OUTPUT_FILLER: Output = Output { address: "", amount: 0 };

    fn test_transaction<N: ZcashNetwork>(
        header: u32,
        version_group_id: u32,
        lock_time: u32,
        expiry_height: u32,
        value_balance: i64,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        expected_signed_transaction: &str,
    ) {
        let mut input_vec: Vec<ZcashTransactionInput<N>> = Vec::new();
        for input in &inputs {
            let private_key = ZcashPrivateKey::from_str(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();
            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = match input.redeem_script {
                Some(script) => Some(hex::decode(script).unwrap()),
                None => None,
            };

            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());
            let transaction_input = ZcashTransactionInput::<N>::new(
                address,
                transaction_id,
                input.index,
                input.utxo_amount,
                redeem_script,
                script_pub_key,
                sequence,
                input.sig_hash_code,
            ).unwrap();

            input_vec.push(transaction_input);
        }

        let mut output_vec: Vec<ZcashTransactionOutput<N>> = Vec::new();
        for output in outputs {
            output_vec.push(ZcashTransactionOutput::<N>::new(output.address, output.amount).unwrap());
        }

        let mut transaction =
            ZcashTransaction::build_raw_transaction(
                header,
                version_group_id,
                input_vec,
                output_vec,
                lock_time,
                expiry_height,
                value_balance,
                None,
                None,
                None
            ).unwrap();

        println!("raw transaction: {:}", hex::encode(transaction.serialize_transaction(true).unwrap()));

        for (index, input) in inputs.iter().enumerate() {
            transaction
                .sign_raw_transaction(
                    ZcashPrivateKey::from_str(input.private_key).unwrap(),
                    index,
                )
                .unwrap();
        }

        let signed_transaction = hex::encode(transaction.serialize_transaction(false).unwrap());

        println!("signed transaction: {}", signed_transaction);

        assert_eq!(expected_signed_transaction, signed_transaction);
    }

    mod test_mainnet_transactions {
        use super::*;

        type N = Mainnet;

        /// Keys and addresses were generated randomly and test transactions were built using zcash-cli
        const TRANSACTIONS: [Transaction; 4] = [
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 0,
                value_balance: 0,
                inputs: [
                    Input {
                        private_key: "KwbK8JibyGAKz7h7uXAmW2hmM68SDGZenurVMKvUMoH5n97dEekL",
                        address_format: Format::P2PKH,
                        transaction_id: "1097b2e1ffbaf193ec0123c0d20b0e217f77250446485e3e9af906f314a01055",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(101000000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "t1S5TMtjLu73QwjMkYDwa67B39qqneqq4yY",
                        amount: 100000000
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                expected_signed_transaction: "0400008085202f89015510a014f306f99a3e5e48460425777f210e0bd2c02301ec93f1baffe1b29710000000006a47304402207c2e6d5ec25a8ab67229f23a581ee8898eb087c2aa6c8db8acf21c3b96bab5fb02202ff7689945891a20961de1b4e18b40995fe7f07cb6dd1c97607c65259adeb1bd012102a7b8361f36eee68b96cbc72bab73295494161b8e670a29c99819e2b793939d25ffffffff0100e1f505000000001976a91459fec7e62fcf3e580656bc1bc6c220dad37709ab88ac00000000000000000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 456789,
                expiry_height: 600000,
                value_balance: 0,
                inputs: [
                    Input {
                        private_key: "KyWLtuy5hiPejU1muc2ENTQ6U6WVueWErEYtye96oeB9QrPZMj1t",
                        address_format: Format::P2PKH,
                        transaction_id: "f234d95b8313c7f8534e3dd3cc0549b307759ec3909626920c129e493ac84f39",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(200010000),
                        sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "t1bq98GbMv8wbjkEQqQkMxiHi7Qefb67jXr",
                        amount: 50000000
                    },
                    Output {
                        address: "t1MkLsaPmTuc8XQjLENxppkCFUkCtTRCsZZ",
                        amount: 50000000
                    },
                    Output {
                        address: "t1KvUTiJ8LJeFygnzNFigUCpiUqak7Yzbqq",
                        amount: 50000000
                    },
                    Output {
                        address: "t1QNGuoLLkYXDfCFJUGGajQugMCUGRxbAvn",
                        amount: 50000000
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                expected_signed_transaction: "0400008085202f8901394fc83a499e120c92269690c39e7507b34905ccd33d4e53f8c713835bd934f2000000006a473044022053637ac8ece0fd2c5cd2fa2c6abb6fec36317a7e60be6c5215ff83ab903409a502206cdcb354b7bca6a4aed08fc6409a6e0000ba263c47f6bb22ab74ad2fe270250501210325c97e86e09f91a9894b856c9b9ca6d7ea90754d66acc95fb57b46117492d3bdfeffffff0480f0fa02000000001976a914c4fafe5725a6ec3d2218458c00da884cd9a0507c88ac80f0fa02000000001976a9142a80f5573b12de286ecbe0f8d46acb9c2334375588ac80f0fa02000000001976a914167b3376103f458ea847ec6f5e763b0de2808f3e88ac80f0fa02000000001976a914473ce0a50b7a876fcba71973b49770b79cfb10b188ac55f80600c02709000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 456789,
                expiry_height: 0,
                value_balance: 0,
                inputs: [
                    Input {
                        private_key: "KyXn7mdxMm4GC2BLPopZTjkSp17P86vvDh25enpDRcma6vUnicCk",
                        address_format: Format::P2PKH,
                        transaction_id: "ffb595919dd6a431bc74948317cd56be39802b6a2c9a9f0d08606c7b01edb250",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(500000000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    Input {
                        private_key: "KwY2f9ohrQoHv39dat6hdBnprxtD165dikuW21nExQVhY7KU2VHW",
                        address_format: Format::P2PKH,
                        transaction_id: "466351234fb03d3c09c501194f778342314307e923fc7cd6eec9e3fc581a9474",
                        index: 2,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(500000000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    Input {
                        private_key: "L1CTbTh1npyZLjVdpfc2uYwW4mwRD549KGAY8d3RP2Fbk38Kryh4",
                        address_format: Format::P2PKH,
                        transaction_id: "2ed71a12ed95aa64c1812c5bbaceddfc706054dc439d206b42c191a5f790305d",
                        index: 3,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(10000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "t1YEmnC2MMFnsAFQwiijeJYeEy4Hui8ZFju",
                        amount: 1000000000
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                expected_signed_transaction: "0400008085202f890350b2ed017b6c60080d9f9a2c6a2b8039be56cd17839474bc31a4d69d9195b5ff010000006b483045022100adcab54a2e437df28eebf4c19f33061467d951a035f12125d3ba16dc3a7ed21c02204a13ba64160a5a11fb22ada860202995df5f51f05eb882fc197109fba298b96e012103f632eeb38fa2fcc7af1881f1b6c1f4fe6155ee6267d92657d9a95fdbb15c010effffffff74941a58fce3c9eed67cfc23e90743314283774f1901c5093c3db04f23516346020000006b483045022100a14d25f96742b6a06f201db6811ed1bbbeab80be29ea45ad8e54ce583337056502200e04272216609ca7cf38729156c860e59a1e88632697456fb0639efebc6509bd0121026fba2e786f9351532a8f93de404d0c44b54e01a7f10bf1a61f734bc4249b58f9ffffffff5d3090f7a591c1426b209d43dc546070fcddceba5b2c81c164aa95ed121ad72e030000006a473044022005e9df51bedd7f95d567ef472040fb295f7dc7d742e1a894d48f67f5239fd860022076d170cb5be8435628c738f0beecbeb85fc6fb1f8f74d5dd18db0fdc584df6650121020621d94a64caf7183bef70f89cfca4cd3d30a76ce0335f7f10eb787e266bb2cdffffffff0100ca9a3b000000001976a9149d92a791abc62a9ca93ced9086c2129d31757ee088ac55f80600000000000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 584789,
                expiry_height: 710482,
                value_balance: 0,
                inputs: [
                    Input {
                        private_key: "KxN4JLuVGg7A64gCrKxg2aiH1vsq3QGUhgXnARrsiqQpWFFdv7bU",
                        address_format: Format::P2PKH,
                        transaction_id: "0f4b24007bdf5eb11c1e62f186ef3478d70e46453ba06ae290ea323959af380d",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(360100000), //3.601
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "t1JfgVaB5JXx7dQ8gvJzoQH6ng975V1B25G",
                        amount: 10000000
                    },
                    Output {
                        address: "t1MsywTe4TT3QtLjV6CwS1Y4Q1WSBE6vaPS",
                        amount: 20000000
                    },
                    Output {
                        address: "t1cx5apduMvoVGYxPkkM3ygsZv8uVHxdn7C",
                        amount: 30000000
                    },
                    Output {
                        address: "t1JMFpgce1Tex6jHMmJcUHVWZB57KGezWby",
                        amount: 40000000
                    },
                    Output {
                        address: "t1MPCPc6KGbC2shZauK1J7wAitkeLK7SVYU",
                        amount: 50000000
                    },
                    Output {
                        address: "t1g1VEHW9Z69acSHwxcr2tQgmUnV8kX5Kat",
                        amount: 60000000
                    },
                    Output {
                        address: "t1PqYvqKND2ex5rB1BaVQ1MzWumxV9qzhLz",
                        amount: 70000000
                    },
                    Output {
                        address: "t1JQKfrVZtFVBw6vQ1sSxCp7AbHjBfRrVVc",
                        amount: 80000000
                    }
                ],
                expected_signed_transaction: "0400008085202f89010d38af593932ea90e26aa03b45460ed77834ef86f1621e1cb15edf7b00244b0f010000006b4830450221008092fa7e36ee33d24e4325d94d2edc79094a2cc7ee9b5a9b927327eaedeba8b10220221452eab944f6c11ea7c3db4737acec9bc7db2a0bb0a3c90e2c96a5cae40bd00121026c6b54c8303dedb35591698afa9fbc5501763c5a18341d1e7c0a2b68148c69bcffffffff0880969800000000001976a91408b6e1325af5b5017f0dab34965540fac91d3b2788ac002d3101000000001976a9142bf2cfe165f273fbf3e323c4c694769ad24afc9388ac80c3c901000000001976a914d14312fbd36be1b32a1461634694cc7ebe81bb6288ac005a6202000000001976a914053acc6851cc71df9715c68b7ca93e1ad6007c5288ac80f0fa02000000001976a9142681247d3de732e1867edfc085cc4197334c785188ac00879303000000001976a914f2d0702165e099a7cde104b3e3a963b0f79c7b2e88ac801d2c04000000001976a914416d5a8d0daa988ebf0f415bc35a41d74751d95788ac00b4c404000000001976a91405cf42203276331ca0b5b121730c89273cb1e5fc88ac55ec080052d70a000000000000000000000000"
            },
        ];

        #[test]
        fn test_mainnet_transactions() {
            TRANSACTIONS.iter().for_each(|transaction| {
                let mut pruned_inputs = transaction.inputs.to_vec();
                pruned_inputs.retain(|input| input.transaction_id != "");

                let mut pruned_outputs = transaction.outputs.to_vec();
                pruned_outputs.retain(|output| output.address != "");

                test_transaction::<N>(
                    transaction.header,
                    transaction.version_group_id,
                    transaction.lock_time,
                    transaction.expiry_height,
                    transaction.value_balance,
                    pruned_inputs,
                    pruned_outputs,
                    transaction.expected_signed_transaction,
                );
            });
        }
    }

    mod test_testnet_transactions {
        use super::*;

        type N = Testnet;

        const TRANSACTIONS: [Transaction; 4] = [
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 307241,
                expiry_height: 307272,
                value_balance: 0,
                inputs: [
                    Input {
                        private_key: "cUacGttX6uipjEPinJv2BHuax2VNNpHGrf3psRABxtuAddpxLep7",
                        address_format: Format::P2PKH,
                        transaction_id: "d9042195d9a1b65b2f1f79d68ceb1a5ea6459c9651a6ad4dc1f465824785c6a8",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(50000000),
                        sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "tmMVUvhGDFmCAUsXdeGLhftcPJzB8LQ7VrV",
                        amount: 40000000
                    },
                    Output {
                        address: "tmHQEbDidJm3t6RDp4Y5F8inXd84CqHwTDA",
                        amount: 9999755
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                expected_signed_transaction: "0400008085202f8901a8c685478265f4c14dada651969c45a65e1aeb8cd6791f2f5bb6a1d9952104d9010000006b483045022100ef50a15eece0f43a0efd13a2c45aecf85e8e999858721150a70e75b106d80ea702202b3ff79fdcd2ff101dcacd74a7f6e3adb1250955f7a80962b259d1e17742f2f70121037e8e3a964e0f59c52633e25f9cec2fc8bb9af5b23eace85f6264f68b47db5cb6feffffff02005a6202000000001976a9148132712c3ff19f3a151234616777420a6d7ef22688ac8b959800000000001976a9145453e4698f02a38abdaa521cd1ff2dee6fac187188ac29b0040048b004000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 450000,
                expiry_height: 579945,
                value_balance: 0,
                inputs: [
                    Input {
                        private_key: "cVasUuNrNZCnfe4VAdVS2LpyxCh7UmFpdowUx1K9h5JigZxcpX4W",
                        address_format: Format::P2PKH,
                        transaction_id: "ce03f10f794d2db649a365b2bd460fcdf45288a7d36c13d0526457432ab82131",
                        index: 12,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(1000000000),
                        sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "tmTyLLYAaPpK2nsqKArgchdXVGJ4zsB6CQZ",
                        amount: 900000000,
                    },
                    Output {
                        address: "tmBmPifMLsmRkNyBg2u1FHFWMXquWqGpQ8G",
                        amount: 50000000
                    },
                    Output {
                        address: "tmDrbFH5RELCJnMTEaWMo9VF3YaBgqTEgX6",
                        amount: 49900000
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                expected_signed_transaction: "0400008085202f89013121b82a43576452d0136cd3a78852f4cd0f46bdb265a349b62d4d790ff103ce0c0000006a47304402201e563ac13e9ae03b0c0f19313dfc5ef32d633adc46d0e2ecad6185b46961e37902207d33d054cfaf1f25149298bb12f5f9dd063034415ec4ee0bad71437f846b04e00121029862bf5d37725419b03e9e3db90f60060de42d187c5ed28bdb41ed435742bd51feffffff0300e9a435000000001976a914c847ac8eafe8ecfac934a41c37b2720ab266b8b688ac80f0fa02000000001976a91416837e1ef0b93ef72d9a2cc235e4d342b476d1d788ace069f902000000001976a9142d6f726f415eaf3e8b609bb0cdc451d4777c800d88acd0dd060069d908000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 285895,
                value_balance: 0,
                inputs: [
                    Input {
                        private_key: "cQJJZoXt3fhmv7FVNqQX7H4kpVrihX2g6Mh5KpPreuT7XTGuUWiD",
                        address_format: Format::P2PKH,
                        transaction_id: "1ec22e34540e8748a369272d858421ff607c2b7991a88e154b352a9f7acd9431",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(100000000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "tmL1qkaq3yedV1kbGommnx7tVNXQVpq4cNy",
                        amount: 99000000
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                expected_signed_transaction: "0400008085202f89013194cd7a9f2a354b158ea891792b7c60ff2184852d2769a348870e54342ec21e000000006a47304402203b1f53d5f4c56e5120cd9574328f68c7403772db8eb26b75566a1499a8da1c5002205b22f8870c467d206494448f364b3f2f632e747563dbcc74ddcf27bb3c8033020121030cb32083e4b93572483ac4a3a39df5de63047973eb424b3f202bf0438e80b7bcffffffff01c09ee605000000001976a91471000dc3823178a6a14b0d41547f1a4163bb6fd488ac00000000c75c04000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 500000,
                expiry_height: 575098,
                value_balance: 0,
                inputs: [
                    Input {
                        private_key: "cNmWGcSzDEwWB9FJkvsP4rUzrFt6nNRBUdfV8Krv6hSeDnTSjwzx",
                        address_format: Format::P2PKH,
                        transaction_id: "77533bf33c0835d20820f46f3dd484feb7c813d33e87400ed3066b1dfbfa3442",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(100000000),
                        sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    Input {
                        private_key: "cMefZsn9zKu7XPW6sGk6jXicgKQmT9DUE4Hj3wKLKQRfadSdDcWr",
                        address_format: Format::P2PKH,
                        transaction_id: "e39029f7936131571772a60c5ba390f52449dd0665aa3c5f422747f813a7ea52",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(100000000),
                        sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER,
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "tmP9PseY1RvxiLompZ6mUSM9CymBpEbvU6J",
                        amount: 45000000
                    },
                    Output {
                        address: "tmT1UteSdKa1jXBpsd7GLoaBy4RpSsNgcuQ",
                        amount: 100000000
                    },
                    Output {
                        address: "tmE63tsYgu7Yv2AFMKWJJTW737adHpxCk4q",
                        amount: 23000000
                    },
                    Output {
                        address: "tmKDzQrKDbPGeET81pM3v5y6M7CiijyoeEo",
                        amount: 31000000
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                expected_signed_transaction: "0400008085202f89024234fafb1d6b06d30e40873ed313c8b7fe84d43d6ff42008d235083cf33b5377000000006a47304402204b631eb3a5f335b3de5693decc757164c711785d9e9260e997b290f6f2265f6402204bdb57d435d966645d42ae40ce58f88a28922063d365cf49b04ffafb959e338d012103d417fc48280160dbf89ea4e3c34b3d47c79bfc43cc211846c22b3538c267a082feffffff52eaa713f84727425f3caa6506dd4924f590a35b0ca6721757316193f72990e3010000006b483045022100f5b4368cbc84a548b48b15acc5589d93c9cc5032476b331f7fd14bf93c0176da02205b93f2439e5ca49e1a0af344d0654b0ec4b22783c31579bd52722a890a8b2ac401210335232f77fae42c4737ddd8d8c9df538767065aa17b9e6a388b6081d2893b9801feffffff0440a5ae02000000001976a914935628220a6e53fec7a6829a69b1139099a95ee688ac00e1f505000000001976a914bdb78536ed86bab756d96c227ff05a156d0994f188acc0f35e01000000001976a9142ffb196b33124bcbac37e85142e14db096202c4a88acc005d901000000001976a914685425f98a20f92e880b10de6e84416683a7010c88ac20a107007ac608000000000000000000000000"
            },
        ];

        #[test]
        fn test_testnet_transactions() {
            TRANSACTIONS.iter().for_each(|transaction| {
                let mut pruned_inputs = transaction.inputs.to_vec();
                pruned_inputs.retain(|input| input.transaction_id != "");

                let mut pruned_outputs = transaction.outputs.to_vec();
                pruned_outputs.retain(|output| output.address != "");

                test_transaction::<N>(
                    transaction.header,
                    transaction.version_group_id,
                    transaction.lock_time,
                    transaction.expiry_height,
                    transaction.value_balance,
                    pruned_inputs,
                    pruned_outputs,
                    transaction.expected_signed_transaction,
                );
            });
        }
    }
}