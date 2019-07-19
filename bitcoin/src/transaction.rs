use crate::address::{BitcoinAddress, Format};
use crate::private_key::BitcoinPrivateKey;
use byteorder::{LittleEndian, WriteBytesExt};
use std::str::FromStr;
use base58::{FromBase58};
use secp256k1::Secp256k1;
use sha2::{Digest, Sha256};
use wagu_model::{PrivateKey, AddressError};
use bech32::{Bech32,FromBase32};
use crate::witness_program::WitnessProgram;

/// Represents a Bitcoin transaction
pub struct BitcoinTransaction {
    /// Version number - 4 bytes
    pub version : u32,
    /// Optional 2 bytes to indicate segwit transactions
    pub segwit_flag : bool,
    /// Number of inputs - variable integer length
    pub input_count: Vec<u8>,
    /// Transaction inputs included in the transaction
    pub inputs: Vec<BitcoinTransactionInput>,
    /// Number of outputs - variable integer length
    pub output_count: Vec<u8>,
    /// Transaction outputs included in the transaction
    pub outputs: Vec<BitcoinTransactionOutput>,
    /// Lock time - 4 bytes
    pub lock_time: u32
}

/// Represents a Bitcoin transaction input
pub struct BitcoinTransactionInput {
    /// OutPoint - transaction id and index - 36 bytes
    pub out_point: OutPoint,
    /// Tx-in script - Variable size
    pub script: Option<Script>,
    /// Sequence number - 4 bytes (normally 0xFFFFFFFF, unless lock > 0)
    /// Also used in replace-by-fee - BIP 125.
    pub sequence: Vec<u8>,
    /// SIGHASH Code - 4 Bytes (used in signing raw transaction only)
    pub sig_hash_code: SigHashCode,
    /// Number of witnesses - variable integer length
    pub witness_count: Option<Vec<u8>>,
    /// Witnesses used in segwit transactions
    pub witnesses: Vec<BitcoinTransactionWitness>,
}

/// Represents a Bitcoin transaction output
pub struct BitcoinTransactionOutput {
    /// Transfer amount in Satoshi
    pub amount: u64,
    /// Output public key script
    pub output_public_key: Script
}

/// Represents a specific UTXO
pub struct OutPoint {
    /// Previous transaction hash (using Bitcoin RPC's reversed hash order) - 32 bytes
    pub reverse_transaction_id: Vec<u8>,
    /// Index of the transaction being used - 4 bytes
    pub index: u32,
    /// Amount associated with the UTXO - used for segwit transaction signatures
    pub amount: Option<u64>,
    /// Script public key asssociated with claiming this particular input UTXO
    pub script_pub_key: Option<Vec<u8>>,
    /// Optional redeem script - for segwit transactions
    pub redeem_script: Option<Vec<u8>>,
    /// Address of the outpoint
    pub address: BitcoinAddress
}

/// Represents a generic script (e.g. script_sig or script_pub_key)
pub struct Script {
    /// Length of the script - variable integer length
    pub script_length: Vec<u8>,
    /// Transaction input script - Variable size
    pub script: Vec<u8>
}

/// Represents a witness in a segwit transaction
pub struct BitcoinTransactionWitness {
    /// The witness in segwit transactions
    pub witness: Vec<u8>
}

/// Represents the signature hash opcode
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum SigHashCode {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 128,
}

/// Returns the value of the signature hash opcode
impl SigHashCode {
    fn value(&self) -> u32 {
        match *self {
            SigHashCode::SIGHASH_ALL => 1,
            SigHashCode::SIGHASH_NONE => 2,
            SigHashCode::SIGHASH_SINGLE => 3,
            SigHashCode::SIGHASH_ANYONECANPAY => 128
        }
    }
}

/// Represents the commonly used script opcodes
#[allow(non_camel_case_types)]
pub enum OPCodes {
    OP_DUP = 0x76,
    OP_HASH160 = 0xa9,
    OP_CHECKSIG = 0xac,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
}

impl BitcoinTransaction {
    /// Returns a raw unsigned bitcoin transaction
    pub fn build_raw_transaction(
        version: u32,
        raw_inputs: Vec<BitcoinTransactionInput>,
        outputs: Vec<BitcoinTransactionOutput>,
        lock_time: u32
    ) -> Self {
        let input_count = variable_integer_length(raw_inputs.len() as u64);
        let output_count = variable_integer_length(outputs.len() as u64);

        Self {
            version,
            segwit_flag: false,
            input_count,
            inputs: raw_inputs,
            output_count,
            outputs,
            lock_time
        }
    }

    /// Returns the transaction as a byte vector
    pub fn serialize_transaction(&mut self, raw: bool) -> Result<Vec<u8>, std::io::Error> {
        let mut serialized_transaction: Vec<u8> = Vec::new();

        let version_bytes = u32_to_bytes(self.version)?;
        serialized_transaction.extend(version_bytes);

        if self.segwit_flag {
            serialized_transaction.extend(vec![0x00, 0x01]);
        }

        serialized_transaction.extend(&self.input_count);

        let mut has_witness = false;
        for input in &self.inputs {
            if input.witness_count.is_some() && input.witnesses.len() > 0 {
                has_witness = true;
            }
            if input.out_point.address.format == Format::Bech32 {
                serialized_transaction.extend(input.serialize(true)?);
            } else {
                serialized_transaction.extend(input.serialize(raw)?);
            }
        }

        serialized_transaction.extend(&self.output_count);

        for output in  &self.outputs {
            serialized_transaction.extend(output.serialize());
        }

        if has_witness {
            for input in &self.inputs {
                if input.witness_count.is_some() && input.witnesses.len() > 0 {
                    serialized_transaction.extend(input.witness_count.clone().unwrap());
                    for witness in &input.witnesses {
                        serialized_transaction.extend(&witness.witness);
                    }
                } else {
                    serialized_transaction.extend(vec![0x00]);
                }
            }
        }

        let lock_time_bytes = u32_to_bytes(self.lock_time)?;
        serialized_transaction.extend(lock_time_bytes);
        Ok(serialized_transaction)
    }

    /// Signs the raw transaction, updates the transaction, and returns the signature
    pub fn sign_raw_transaction(&mut self,
                                private_key: BitcoinPrivateKey,
                                input_index: usize,
                                address_format: Format
    ) -> Result<Vec<u8>, std::io::Error> {
        let input = &self.inputs[input_index];
        let transaction_hash_preimage  = if input.out_point.address.format == Format::P2PKH {
            self.generate_p2pkh_hash_preimage(input_index, input.sig_hash_code.clone())?
        } else {
            self.generate_segwit_hash_preimage(input_index, input.sig_hash_code.clone())?
        };

        let transaction_hash = Sha256::digest(&Sha256::digest(&transaction_hash_preimage));
        let message = secp256k1::Message::from_slice(&transaction_hash).unwrap();
        let sign = Secp256k1::signing_only();
        let signing_key = private_key.secret_key;
        let mut signature =  sign.sign(&message, &signing_key).serialize_der(&sign).to_vec();
        let sig_hash_code_bytes = u32_to_bytes(input.sig_hash_code.value());
        signature.extend(vec![sig_hash_code_bytes?[0]]); // Add the SIG_HASH ALL TO THE END OF THE signature
        let signature_length = variable_integer_length(signature.len() as u64 );
        let public_key = private_key.to_public_key();
        let mut public_key_vec: Vec<u8> = Vec::new();

        if address_format == Format::P2PKH && !public_key.compressed {
            public_key_vec.extend(public_key.public_key.serialize_uncompressed().to_vec());
        } else {
            // Public Key must always be compressed for segwit- https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#restrictions-on-public-key-type
            public_key_vec.extend(public_key.public_key.serialize().to_vec());
        }

        let mut public_key_length: Vec<u8> = Vec::new();
        public_key_length.write_u8(public_key_vec.len() as u8).unwrap();

        if input.out_point.address.format == Format::P2PKH {
            let mut final_script = signature_length;
            final_script.extend(&signature);
            final_script.extend(public_key_length);
            final_script.extend(public_key_vec);

            self.inputs[input_index].create_script_sig(final_script);
        } else {
            self.segwit_flag = true;

            // Bech32 P2WPKH doesnt require an input script
            if input.out_point.address.format == Format::P2SH_P2WPKH {
                let input_script = input.out_point.redeem_script.clone().unwrap();
                let mut new_script = variable_integer_length(input_script.len() as u64);
                new_script.extend(input_script);
                self.inputs[input_index].create_script_sig(new_script);
            }

            let mut witness_sig = signature_length;
            let mut witness_public_key = public_key_length;

            witness_sig.extend(&signature);
            witness_public_key.extend(public_key_vec);

            let mut full_witness: Vec<BitcoinTransactionWitness> = vec![
                BitcoinTransactionWitness { witness: witness_sig },
                BitcoinTransactionWitness { witness: witness_public_key }];

            self.inputs[input_index].witnesses.append(&mut full_witness);
            self.inputs[input_index].witness_count = Some(variable_integer_length(self.inputs[input_index].witnesses.len() as u64));
        }

        Ok(signature)
    }

    /// Return the P2PKH hash preimage of the raw transaction
    pub fn generate_p2pkh_hash_preimage(&self, input_index: usize, sig_hash_code: SigHashCode) -> Result<Vec<u8>, std::io::Error> {
        let version_bytes = u32_to_bytes(self.version)?;
        let lock_time_bytes = u32_to_bytes(self.lock_time)?;
        let sig_hash_code_bytes = u32_to_bytes(sig_hash_code.value())?;
        let mut transaction_hash_preimage: Vec<u8> = Vec::new();

        transaction_hash_preimage.extend(version_bytes);
        transaction_hash_preimage.extend(&self.input_count);

        for index in 0..self.inputs.len() {
            let raw = index != input_index;
            transaction_hash_preimage.extend(&self.inputs[index].serialize(raw)?);
        }

        transaction_hash_preimage.extend(&self.output_count);
        for output in  &self.outputs {
            transaction_hash_preimage.extend(output.serialize());
        }

        transaction_hash_preimage.extend(lock_time_bytes);
        transaction_hash_preimage.extend(sig_hash_code_bytes);

        Ok(transaction_hash_preimage)
    }

    /// Return the segwit hash preimage of the raw transaction - https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
    pub fn generate_segwit_hash_preimage(&self, input_index: usize, sig_hash_code: SigHashCode) -> Result<Vec<u8>, std::io::Error>{
        let mut transaction_hash_preimage: Vec<u8> = Vec::new();
        let mut prev_outputs: Vec<u8> = Vec::new();
        let mut prev_sequences: Vec<u8> = Vec::new();
        let mut outputs: Vec<u8> = Vec::new();

        for input in &self.inputs {
            prev_outputs.extend(&input.out_point.reverse_transaction_id);
            prev_outputs.extend(u32_to_bytes(input.out_point.index)?);
            prev_sequences.extend(&input.sequence);
        }

        for output in &self.outputs {
            outputs.extend(&output.serialize());
        }

        let input = &self.inputs[input_index];
        let hash_prev_outputs = Sha256::digest(&Sha256::digest(&prev_outputs));
        let hash_sequence = Sha256::digest(&Sha256::digest(&prev_sequences));
        let hash_outputs = Sha256::digest(&Sha256::digest(&outputs));

        let version_bytes = u32_to_bytes(self.version)?;
        let mut total_utxo_amount: Vec<u8> = Vec::new();
        let mut script_code: Vec<u8> = Vec::new();
        let mut script = if input.out_point.address.format == Format::Bech32 {
            input.out_point.script_pub_key.clone().unwrap()
        } else {
            input.out_point.redeem_script.clone().unwrap()
        };
        total_utxo_amount.write_u64::<LittleEndian>(input.out_point.amount.unwrap())?;
        script = script[1..].to_vec();

        let op_dup: Vec<u8> = vec![OPCodes::OP_DUP as u8];
        let op_hash160: Vec<u8> = vec![OPCodes::OP_HASH160 as u8];
        let op_equal_verify: Vec<u8> = vec![OPCodes::OP_EQUALVERIFY as u8];
        let op_checksig: Vec<u8> = vec![OPCodes::OP_CHECKSIG as u8];

        script_code.extend(op_dup);
        script_code.extend(op_hash160);
        script_code.extend(script);
        script_code.extend(op_equal_verify);
        script_code.extend(op_checksig);

        let mut script_code_with_length = variable_integer_length(script_code.len() as u64);
        script_code_with_length.extend(&script_code);

        transaction_hash_preimage.extend(version_bytes);
        transaction_hash_preimage.extend(hash_prev_outputs);
        transaction_hash_preimage.extend(hash_sequence);
        transaction_hash_preimage.extend(&input.out_point.reverse_transaction_id);
        transaction_hash_preimage.extend(u32_to_bytes(input.out_point.index)?);
        transaction_hash_preimage.extend(&script_code_with_length);
        transaction_hash_preimage.extend(total_utxo_amount);
        transaction_hash_preimage.extend(&input.sequence);
        transaction_hash_preimage.extend(hash_outputs);
        transaction_hash_preimage.extend(u32_to_bytes(self.lock_time)?);
        transaction_hash_preimage.extend(u32_to_bytes(sig_hash_code.value())?);

        Ok(transaction_hash_preimage)
    }
}

impl BitcoinTransactionInput {
    const DEFAULT_SEQUENCE: [u8; 4] =  [0xff, 0xff, 0xff, 0xff];

    /// Create a new Bitcoin Transaction input without the script
    pub fn new(
        address: BitcoinAddress,
        transaction_id: Vec<u8>,
        index: u32,
        amount: Option<u64>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
        sequence: Option<Vec<u8>>,
        sig_hash_code: SigHashCode
    ) -> Result<Self,  &'static str> {
        if transaction_id.len() != 32 {
            return Err("invalid transaction id");
        }

        let sequence = match sequence {
            None => BitcoinTransactionInput::DEFAULT_SEQUENCE.to_vec(),
            Some(sequence) => sequence
        };

        // Bitcoin uses reverse hash order - https://bitcoin.org/en/developer-reference#hash-byte-order
        let mut reverse_transaction_id = transaction_id;
        reverse_transaction_id.reverse();

        let script_pub_key = match script_pub_key {
            None => {
                Some(generate_script_pub_key(&address.address).unwrap().script)
            }
            Some (script) => Some(script)
        };

        validate_address_format(address.format.clone(), redeem_script.clone(), script_pub_key.clone(), amount)?;
        let out_point = OutPoint { reverse_transaction_id, index, amount, redeem_script, script_pub_key, address };

        Ok(Self { out_point, script: None, sequence, sig_hash_code, witness_count: None,  witnesses: vec![] })
    }

    // Create a full script_sig using the given script
    pub fn create_script_sig(&mut self, script: Vec<u8>) {
        let script_size_bytes: u64 = script.len() as u64;
        let script_length = variable_integer_length(script_size_bytes);
        self.script = Some(Script { script_length, script });
    }

    // Serialize the transaction input
    pub fn serialize(&self, raw: bool) -> Result<Vec<u8>, std::io::Error> {
        let mut serialized_input: Vec<u8> = Vec::new();
        serialized_input.extend(&self.out_point.reverse_transaction_id);
        serialized_input.extend(u32_to_bytes(self.out_point.index)?);
        if raw {
            serialized_input.extend(vec![0x00]);
        } else {
            match &self.script {
                None => {
                    let script_pub_key = &self.out_point.script_pub_key.clone().unwrap();
                    let script_pub_key_length = variable_integer_length(script_pub_key.len() as u64);
                    serialized_input.extend(script_pub_key_length);
                    serialized_input.extend(script_pub_key);

                },
                Some(script) => {
                    serialized_input.extend(&script.script_length);
                    serialized_input.extend(&script.script);
                }
            }
        }
        serialized_input.extend(&self.sequence);
        Ok(serialized_input)
    }
}

impl BitcoinTransactionOutput {
    /// Create a new Bitcoin transaction output
    pub fn new(bitcoin_address: &str, amount: u64) -> Result<Self, AddressError> {
        let output_public_key = generate_script_pub_key(bitcoin_address)?;
        Ok(Self { amount, output_public_key })
    }

    // Serialize the transaction output
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_output: Vec<u8> = Vec::new();
        serialized_output.write_u64::<LittleEndian>(self.amount).unwrap();
        serialized_output.extend( &self.output_public_key.script_length);
        serialized_output.extend(&self.output_public_key.script);
        serialized_output
    }
}

/// Write a u32 into a 4 byte vector
pub fn u32_to_bytes(num: u32) -> Result<Vec<u8>, std::io::Error> {
    let mut num_vec: Vec<u8> = Vec::new();
    num_vec.write_u32::<LittleEndian>(num)?;
    Ok(num_vec)
}

/// Derive the public key hash or script hash from the spending address
pub fn address_to_pub_key_or_script_hash(address: String) -> Vec<u8> {
    let mut pub_key_or_script_hash = address.from_base58().unwrap();
    pub_key_or_script_hash = pub_key_or_script_hash[1..(pub_key_or_script_hash.len()-4)].to_vec();
    pub_key_or_script_hash

}

/// Generate the script_pub_key of a corresponding address
pub fn generate_script_pub_key(bitcoin_address: &str) -> Result<Script, AddressError> {
    let bitcoin_address = BitcoinAddress::from_str(bitcoin_address)?;
    let mut script: Vec<u8> = Vec::new();
    let format = bitcoin_address.format;
    match format {
        Format::P2PKH => {
            let op_dup: Vec<u8> = vec![OPCodes::OP_DUP as u8];
            let op_hash160: Vec<u8> = vec![OPCodes::OP_HASH160 as u8];
            let pub_key_hash = address_to_pub_key_or_script_hash(bitcoin_address.address);
            let bytes_to_push: Vec<u8> = variable_integer_length(pub_key_hash.len() as u64);
            let op_equal_verify: Vec<u8> = vec![OPCodes::OP_EQUALVERIFY as u8];
            let op_checksig: Vec<u8> = vec![OPCodes::OP_CHECKSIG as u8];

            script.extend(op_dup);
            script.extend(op_hash160);
            script.extend(bytes_to_push);
            script.extend(pub_key_hash);
            script.extend(op_equal_verify);
            script.extend(op_checksig);
        },
        Format::P2SH_P2WPKH => {
            let op_hash160: Vec<u8> = vec![OPCodes::OP_HASH160 as u8];
            let script_hash = address_to_pub_key_or_script_hash(bitcoin_address.address);
            let bytes_to_push: Vec<u8> = variable_integer_length(script_hash.len() as u64);
            let op_equal: Vec<u8> = vec![OPCodes::OP_EQUAL as u8];

            script.extend(op_hash160);
            script.extend(bytes_to_push);
            script.extend(script_hash);
            script.extend(op_equal);
        },
        Format::Bech32 => { // Bech 32 implementation for P2SH_P2WPKH and P2SH_P2WSH
            let bech32 = Bech32::from_str(&bitcoin_address.address).unwrap();
            let (v, program) = bech32.data().split_at(1);
            let mut version_u8 =  v[0].to_u8();
            let program_u8 = Vec::from_base32(program).unwrap();
            let bytes_to_push: Vec<u8> = variable_integer_length(program_u8.len() as u64);
            version_u8 = WitnessProgram::convert_version(version_u8);

            script.push(version_u8);
            script.extend(bytes_to_push);
            script.extend(program_u8);
        }
    }
    let script_length = variable_integer_length(script.len() as u64);

    Ok(Script { script_length, script })
}

/// Determine the address type (P2PKH, P2SH_P2PKH, etc.) with the given scripts
pub fn validate_address_format (address_format: Format, redeem_script: Option<Vec<u8>>, script_pub_key: Option<Vec<u8>>, amount: Option<u64>) -> Result<bool,  &'static str> {
    let op_dup = OPCodes::OP_DUP as u8;
    let op_hash160 = OPCodes::OP_HASH160 as u8;
    let op_checksig = OPCodes::OP_CHECKSIG as u8;
    let op_equal = OPCodes::OP_EQUAL as u8;

    if (amount.is_none() || redeem_script.is_none()) && address_format == Format::P2SH_P2WPKH {
        return Err("insufficient information to craft P2SH_P2WPKH transaction input");
    } else if amount.is_none() && address_format == Format::Bech32 {
        return Err("insufficient information to craft Bech32 transaction input");
    } else if redeem_script.is_none() && amount.is_none() {
        Ok(address_format == Format::P2PKH)
    } else if redeem_script.is_none() && amount.is_some() {
        Ok(address_format == Format::Bech32)
    } else {
        let script_pub_key = script_pub_key.unwrap();
        if script_pub_key[0] == op_dup && script_pub_key[1] == op_hash160 && script_pub_key[script_pub_key.len() -1] == op_checksig {
            Ok(address_format == Format::P2PKH)
        } else if script_pub_key[0] == op_hash160 &&
            script_pub_key[script_pub_key.len() -1] == op_equal
        {
            Ok(address_format == Format::P2SH_P2WPKH || address_format == Format::Bech32)
        } else {
            Ok(address_format == Format::P2SH_P2WPKH || address_format == Format::Bech32) // UNIMPLEMENTED - P2SH/P2WSH SPENDING
        }
    }
}

/// Return Bitcoin variable length integer of the size
/// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
pub fn variable_integer_length (size: u64) -> Vec<u8> {
    let mut v8: Vec<u8> = Vec::new();
    if size < 253 {
        vec![size as u8]
    } else if size <= 65535 { // u16::max_value()
        let mut result: Vec<u8> = vec![0xfd];
        v8.write_u16::<LittleEndian>(size as u16).unwrap();
        result.append(&mut v8);
        result
    } else if size <= 4294967295 { // u32::max_value()
        let mut result: Vec<u8> = vec![0xfe];
        v8.write_u32::<LittleEndian>(size as u32).unwrap();
        result.append(&mut v8);
        result
    } else {
        let mut result: Vec<u8> = vec![0xff];
        v8.write_u64::<LittleEndian>(size).unwrap();
        result.append(&mut v8);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wagu_model::crypto::hash160;

    #[derive(Clone)]
    pub struct Input {
        pub private_key: &'static str,
        pub address_format: Format,
        pub transaction_id: &'static str,
        pub index: u32,
        pub redeem_script: Option<&'static str>,
        pub script_pub_key: Option<&'static str>,
        pub utxo_amount: Option<u64>,
        pub sequence: Option<[u8;4]>,
        pub sig_hash_code: SigHashCode
    }

    #[derive(Clone)]
    pub struct Output {
        pub address: &'static str,
        pub amount: u64
    }

    const INPUT_FILLER: Input =
        Input {
            private_key: "L5QDKPT7t5S4biznTohoGqRmeHSzQrZzqHq9rfMJijuUtsvZksbj",
            address_format: Format::P2PKH,
            transaction_id: "",
            index: 0,
            redeem_script: Some(""),
            script_pub_key: None,
            utxo_amount: None,
            sequence: None,
            sig_hash_code: SigHashCode::SIGHASH_ALL
        };

    const OUTPUT_FILLER: Output = Output { address: "", amount: 0 };

    fn test_transaction(
        version: u32,
        lock_time: u32,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        expected_signed_transaction: &str
    ) {
        let mut input_vec: Vec<BitcoinTransactionInput> = Vec::new();
        for input in &inputs {
            let private_key = BitcoinPrivateKey::from_wif(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();
            let transaction_id = hex::decode(input.transaction_id).unwrap();

            let redeem_script = match input.redeem_script {
                None => {
                    if input.address_format == Format::P2SH_P2WPKH {
                        let mut redeem_script: Vec<u8> = vec![0x00, 0x14];
                        redeem_script.extend(&hash160(&private_key.to_public_key().public_key.serialize()));
                        Some(redeem_script)
                    } else {
                        None
                    }
                },
                Some(redeem_script) => Some(hex::decode(redeem_script).unwrap())
            };
            let script_pub_key = match input.script_pub_key {
                None => None,
                Some (script) => Some(hex::decode(script).unwrap())
            };

            let sequence = match input.sequence {
                None => None,
                Some(seq) => Some(seq.to_vec())
            };

            let transaction_input = BitcoinTransactionInput::new(
                address,
                transaction_id, input.index,
                input.utxo_amount,
                redeem_script,
                script_pub_key,
                sequence,
                input.sig_hash_code)
                .unwrap();
            input_vec.push(transaction_input);
        }

        let mut output_vec: Vec<BitcoinTransactionOutput> = Vec::new();
        for output in outputs {
            let transaction_output = BitcoinTransactionOutput::new(output.address, output.amount).unwrap();
            output_vec.push(transaction_output);
        }

        let mut transaction = BitcoinTransaction::build_raw_transaction(version, input_vec, output_vec, lock_time);
        for (index, input) in inputs.iter().enumerate() {
            let private_key = BitcoinPrivateKey::from_wif(input.private_key).unwrap();
            transaction.sign_raw_transaction(private_key, index, input.address_format.clone()).unwrap();
        }

        let signed_transaction = hex::encode(transaction.serialize_transaction(false).unwrap());
        assert_eq!(expected_signed_transaction, signed_transaction);
    }

    mod test_valid_transactions {
        use super::*;

        // version, lock time, inputs, outputs, expected_signed_transaction
        const TRANSACTIONS: [(
            u32,
            u32,
            [Input; 4],
            [Output; 4],
            &str
        ); 10] = [
            ( // p2pkh to p2pkh - based on https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/test/integration/transactions.js
              1,
              0,
              [
                  Input {
                      private_key: "L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy",
                      address_format: Format::P2PKH,
                      transaction_id: "61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d",
                      index: 0,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: None,
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP",
                      amount: 12000
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "01000000019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d561000000006b48304502210088828c0bdfcdca68d8ae0caeb6ec62cd3fd5f9b2191848edae33feb533df35d302202e0beadd35e17e7f83a733f5277028a9b453d525553e3f5d2d7a7aa8010a81d60121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff01e02e0000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac00000000"
            ),
            ( // p2sh_p2wpkh to p2pkh - based on https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
              1,
              1170,
              [
                  Input {
                      private_key: "5Kbxro1cmUF9mTJ8fDrTfNB6URTBsFMUG52jzzumP2p9C94uKCh",
                      address_format: Format::P2SH_P2WPKH,
                      transaction_id: "77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb",
                      index: 1,
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
              [
                  Output {
                      address: "1Fyxts6r24DpEieygQiNnWxUdb18ANa5p7",
                      amount: 199996600
                  },
                  Output {
                      address: "1Q5YjKVj5yQWHBBsyEBamkfph3cA6G9KK8",
                      amount: 800000000,
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
            ),
            ( // p2sh_p2wsh to p2pkh
              2,
              0,
              [
                  Input {
                      private_key: "cNdMBCLMUt7jK8LynAWz7rAC8VTMMcZLozDzwg8e4aTWGRcQ4exR", // Testnet address
                      address_format: Format::P2SH_P2WPKH,
                      transaction_id: "80d9a1dc460da39c0fbbc0415c7cebf305cea2aa2d1de1a64d0bf4e4e541e513",
                      index: 1,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: Some(50000),
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "1CUQeVjoMynT4dpgcv6g5A57rBXZ7sdL7w",
                      amount: 20000
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "0200000000010113e541e5e4f40b4da6e11d2daaa2ce05f3eb7c5c41c0bb0f9ca30d46dca1d9800100000017160014e709f020a951e483eb6628e0ee9abce30da49ffbffffffff01204e0000000000001976a9147dd85a8a421b256394532b7a2aaeb00347080c7888ac0247304402202178e5eb537b086efdef5fb6ee0e1848168a853187b7b9db9de299b5afe7ef0f02205ecfb092874babd3dac021c46854a3c43962c156770d3f420d00b09c1c2be13c012103fae6ce0d2a2920e7fbae4f32ace11c6fa9470115887171d0f98ef40d03a4ab4000000000"
            ),
            ( //p2sh_p2wpkh to segwit
              2,
              140,
              [
                  Input {
                      private_key: "KwtetKxofS1Lhp7idNJzb5B5WninBRfELdwkjvTMZZGME4G72kMz",
                      address_format: Format::P2SH_P2WPKH,
                      transaction_id: "375e1622b2690e395df21b33192bad06d2706c139692d43ea84d38df3d183313",
                      index: 0,
                      redeem_script: Some("0014b93f973eb2bf0b614bddc0f47286788c98c535b4"), // Manually specify redeem_script
                      script_pub_key: None,
                      utxo_amount: Some(1000000000),
                      sequence: Some([0xfe, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "3H3Kc7aSPP4THLX68k4mQMyf1gvL6AtmDm",
                      amount: 100000000
                  },
                  Output {
                      address: "3MSu6Ak7L6RY5HdghczUcXzGaVVCusAeYj",
                      amount: 899990000,
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "020000000001011333183ddf384da83ed49296136c70d206ad2b19331bf25d390e69b222165e370000000017160014b93f973eb2bf0b614bddc0f47286788c98c535b4feffffff0200e1f5050000000017a914a860f76561c85551594c18eecceffaee8c4822d787f0c1a4350000000017a914d8b6fcc85a383261df05423ddf068a8987bf0287870247304402206214bf6096f0050f8442be6107448f89983a7399974f7160ba02e80f96383a3f02207b2a169fed3f48433850f39599396f8c8237260a57462795a83b85cceff5b1aa012102e1a2ba641bbad8399bf6e16a7824faf9175d246aef205599364cc5b4ad64962f8c000000"
            ),
            ( // p2pkh and p2sh_p2wpkh to p2pkh - based on https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/test/integration/transactions.js
              1,
              0,
              [
                  Input {
                      private_key: "L1Knwj9W3qK3qMKdTvmg3VfzUs3ij2LETTFhxza9LfD5dngnoLG1",
                      address_format: Format::P2PKH,
                      transaction_id: "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
                      index: 6,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: None,
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  Input {
                      private_key: "KwcN2pT3wnRAurhy7qMczzbkpY5nXMW2ubh696UBc1bcwctTx26z",
                      address_format: Format::P2PKH,
                      transaction_id: "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
                      index: 0,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: None,
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb",
                      amount: 180000
                  },
                  Output {
                      address: "1JtK9CQw1syfWj1WtFMWomrYdV3W2tWBF9",
                      amount: 170000
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "01000000024c94e48a870b85f41228d33cf25213dfcc8dd796e7211ed6b1f9a014809dbbb5060000006a473044022041450c258ce7cac7da97316bf2ea1ce66d88967c4df94f3e91f4c2a30f5d08cb02203674d516e6bb2b0afd084c3551614bd9cec3c2945231245e891b145f2d6951f0012103e05ce435e462ec503143305feb6c00e06a3ad52fbf939e85c65f3a765bb7baacffffffff3077d9de049574c3af9bc9c09a7c9db80f2d94caaf63988c9166249b955e867d000000006b483045022100aeb5f1332c79c446d3f906e4499b2e678500580a3f90329edf1ba502eec9402e022072c8b863f8c8d6c26f4c691ac9a6610aa4200edc697306648ee844cfbc089d7a012103df7940ee7cddd2f97763f67e1fb13488da3fbdd7f9c68ec5ef0864074745a289ffffffff0220bf0200000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac10980200000000001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac00000000"
            ),
            ( // p2sh_p2wsh to multiple address types
              2,
              0,
              [
                  Input {
                      private_key: "Kxxkik2L9KgrGgvdkEvYSkgAxaY4qPGfvxe1M1KBVBB7Ls3xDD8o",
                      address_format: Format::P2SH_P2WPKH,
                      transaction_id: "7c95424e4c86467eaea85b878985fa77d191bad2b9c5cac5a0cb98f760616afa",
                      index: 55,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: Some(2000000),
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "3DTGFEmobt8BaJpfPe62HvCQKp2iGsnYqD",
                      amount: 30000
                  },
                  Output {
                      address: "1NxCpkhj6n8orGdhPpxCD3B52WvoR4CS7S",
                      amount: 2000000
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "02000000000101fa6a6160f798cba0c5cac5b9d2ba91d177fa8589875ba8ae7e46864c4e42957c37000000171600143d295b6276ff8e4579f3350873db3e839e230f41ffffffff02307500000000000017a9148107a4409368488413295580eb88cbf7609cce658780841e00000000001976a914f0cb63944bcbbeb75c26492196939ae419c515a988ac024730440220243435ca67a713f6715d14d761b5ab073e88b30559a02f8b1add1aee8082f1c902207dfea838a2e815132999035245d9ebf51b4c740cbe4d95c609c7012ba9beb86301210324804353b8e10ce351d073da432fb046a4d13edf22052577a6e09cf9a5090cda00000000"
            ),
            ( // p2sh_p2wsh and p2pkh to multiple address types
              2,
              0,
              [
                  Input {
                      private_key: "L3EEWFaodvuDcH7yeTtugQDvNxnBs8Fkzerqf8tgmHYKQ4QkQJDE", // Testnet address
                      address_format: Format::P2PKH,
                      transaction_id: "6b88c087247aa2f07ee1c5956b8e1a9f4c7f892a70e324f1bb3d161e05ca107b",
                      index: 0,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: None,
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  Input {
                      private_key: "KzZtscUzkZS38CYqYfRZ8pUKfUr1JnAnwJLK25S8a6Pj6QgPYJkq", // Testnet address
                      address_format: Format::P2SH_P2WPKH,
                      transaction_id: "93ca92c0653260994680a4caa40cfc7b0aac02a077c4f022b007813d6416c70d",
                      index: 1,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: Some(100000),
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "36NCSwdvrL7XpiRSsfYWY99azC4xWgtL3X",
                      amount: 50000
                  },
                  Output {
                      address: "17rB37JzbUVmFuKMx8fexrHjdWBtDurpuL",
                      amount: 123456
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "020000000001027b10ca051e163dbbf124e3702a897f4c9f1a8e6b95c5e17ef0a27a2487c0886b000000006b483045022100b15c1d8e7de7c1d77612f80ab49c48c3d0c23467a0becaa86fcd98009d2dff6002200f3b2341a591889f38e629dc4b938faf9165aecedc4e3be768b13ef491cbb37001210264174f4ff6006a98be258fe1c371b635b097b000ce714c6a2842d5c269dbf2e9ffffffff0dc716643d8107b022f0c477a002ac0a7bfc0ca4caa4804699603265c092ca9301000000171600142b654d833c287e239f73ba8165bbadf4dee3c00effffffff0250c300000000000017a914334982bfd308f92f8ea5d22e9f7ee52f2265543b8740e20100000000001976a9144b1d83c75928642a41f2945c8a3be48550822a9a88ac0002483045022100a37e7aeb82332d5dc65d1582bb917acbf2d56a90f5a792a932cfec3c09f7a534022033baa11aa0f3ad4ba9723c703e65dce724ccb79c00838e09b96892087e43f1c8012102d9c6aaa344ee7cc41466e4705780020deb70720bef8ddb9b4e83e75df02e1d8600000000"
            ),
            ( // p2pkh to bech32
              2,
              0,
              [
                  Input {
                      private_key: "5JsX1A2JNjqVmLFUUhUJuDsVjFH2yfoVdV5qtFQpWhLkYzamKKy",
                      address_format: Format::P2PKH,
                      transaction_id: "bda2ebcbf0bd6bc4ee1c330a64a9ff95e839cc2d25c593a01e704996bc1e869c",
                      index: 0,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: None,
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                      amount: 1234
                  },
                  Output {
                      address: "bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9",
                      amount: 111
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "02000000019c861ebc9649701ea093c5252dcc39e895ffa9640a331ceec46bbdf0cbeba2bd000000008a473044022077be9faa83fc2289bb59eb7538c3801f513d3640466a48cea9845f3b26f14cd802207b80fda8836610c487e8b59105e682d1c438f98f6324d1ea74cdec5d2d74ef04014104cc58298806e4e233ad1acb81feeb90368e05ad79a1d4b3698156dc4766ca077f39fbb47f52cbd5282c15a8a9fb08401e678acb9ef2fd28e043164723e9f29bb2ffffffff02d204000000000000160014e8df018c7e326cc253faac7e46cdc51e68542c426f00000000000000220020c7a1f1a4d6b4c1802a59631966a18359de779e8a6a65973735a3ccdfdabc407d00000000"
            ),
            ( // p2sh-p2wpkh to bech32
              2,
              0,
              [
                  Input {
                      private_key: "KzZtscUzkZS38CYqYfRZ8pUKfUr1JnAnwJLK25S8a6Pj6QgPYJkq",
                      address_format: Format::P2SH_P2WPKH,
                      transaction_id: "1a2290470e0aa7549ab1e04b2453274374149ffee517a57715e5206e4142c233",
                      index: 1,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: Some(1500000),
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", // witness version 1
                      amount: 100000000
                  },
                  Output {
                      address: "bc1qquxqz4f7wzen367stgwt25tf640gp4vud5vez0",
                      amount: 42500001
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "0200000000010133c242416e20e51577a517e5fe9f1474432753244be0b19a54a70a0e4790221a01000000171600142b654d833c287e239f73ba8165bbadf4dee3c00effffffff0200e1f505000000002a5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6a17f880200000000160014070c01553e70b338ebd05a1cb55169d55e80d59c02483045022100b5cf710307329d8634842c1894057ef243e172284e0908b215479e3b1889f62302205dfdd0287899e3034c95526bcfb1f437a0ca66de42a63c3c36aabb5b893459fb012102d9c6aaa344ee7cc41466e4705780020deb70720bef8ddb9b4e83e75df02e1d8600000000"
            ),
            ( // p2pkh and bech32(p2wpkh) to multiple address types
              1,
              0,
              [
                  Input {
                      private_key: "L1X6apYnZ39CLFJFX6Ny7oriHX3nmeBcjkobeYgmk6arbyZfouJu",
                      address_format: Format::P2PKH,
                      transaction_id: "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff",
                      index: 0,
                      redeem_script: None,
                      script_pub_key: Some("76a9148631bf621f7c6671f8d2d646327b636cbbe79f8c88ac"), // Manually specify script_pub_key
                      utxo_amount: None,
                      sequence: Some([0xee, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  Input {
                      private_key: "5JZGuGYM4vfKvpxaJg5g5D3uvVYVQ74UUdueCVvWCNacrAkkvGi",
                      address_format: Format::Bech32,
                      transaction_id: "8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef",
                      index: 1,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: Some(600000000),
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
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
                  OUTPUT_FILLER
              ],
              "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000006b4830450221009eed10e4b7cc9eb23efc36dc9b0907d0b4dd224ae5d0ee9c92d7912c9a9cde7e02203ede96d667901abfb9f3997aba8e08c6b9de218db920916203f2632c713cd99c012103f4edae249cb015280d48cae959d1823440eeab74f9fc9752a8a18cba76c892b6eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff030a0000000000000016001443b957dcac4c405e77dffce035152e8154fcce4763c55400000000001976a9146504e4b146b24898cf7881b0bdcd059dc35dd5a888aca71d8c000000000017a91463c110106d813c69514b3d97e1a1e6c94ad1b56a870002483045022100cfff608b18a97cc46cf8d22e97e78b22343cfcc19028918a5cd06fc9031f532302201b877de8872619a832387d7d0e15482521e449ce0d4daeb2d080995317883cd60121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635700000000"
            )
        ];

        #[test]
        fn test_transactions() {
            TRANSACTIONS.iter()
                .for_each(|(
                               version,
                               lock_time,
                               inputs,
                               outputs,
                               expected_signed_transaction
                           )| {
                    let mut pruned_inputs = inputs.to_vec();
                    pruned_inputs.retain(|input| input.transaction_id != "");

                    let mut pruned_outputs = outputs.to_vec();
                    pruned_outputs.retain(|output| output.address != "");

                    test_transaction(*version, *lock_time, pruned_inputs, pruned_outputs, expected_signed_transaction);
                });
        }
    }

    mod test_invalid_transactions {
        use super::*;

        const INVALID_INPUTS: [Input; 8] = [
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: Format::P2SH_P2WPKH,
                transaction_id: "61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d",
                index: 0,
                redeem_script: None,
                script_pub_key: None,
                utxo_amount: None,
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sig_hash_code: SigHashCode::SIGHASH_ALL
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: Format::P2PKH,
                transaction_id: "7dabce",
                index: 0,
                redeem_script: None,
                script_pub_key: None,
                utxo_amount: Some(10000),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sig_hash_code: SigHashCode::SIGHASH_ALL
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: Format::P2SH_P2WPKH,
                transaction_id: "7dabce",
                index: 0,
                redeem_script: Some("00142b6e15d83c28acd7e2373ba81bb4adf4dee3c01a"),
                script_pub_key: None,
                utxo_amount: Some(10000),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sig_hash_code: SigHashCode::SIGHASH_ALL
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: Format::P2SH_P2WPKH,
                transaction_id: "7dabce588a8a57786790",
                index: 0,
                redeem_script: Some("00142b6e15d83c28acd7e2373ba81bb4adf4dee3c01a"),
                script_pub_key: None,
                utxo_amount: Some(10000),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sig_hash_code: SigHashCode::SIGHASH_ALL
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: Format::P2SH_P2WPKH,
                transaction_id: "7dabce588a8a57786790d27810514f5ffccff4148a8105894da57c985d02cdbb7dabce",
                index: 0,
                redeem_script: Some("00142b6e15d83c28acd7e2373ba81bb4adf4dee3c01a"),
                script_pub_key: None,
                utxo_amount: Some(10000),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sig_hash_code: SigHashCode::SIGHASH_ALL
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: Format::Bech32,
                transaction_id: "61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d",
                index: 0,
                redeem_script: None,
                script_pub_key: None,
                utxo_amount: None,
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sig_hash_code: SigHashCode::SIGHASH_ALL
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: Format::Bech32,
                transaction_id: "61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d",
                index: 0,
                redeem_script: None,
                script_pub_key: None,
                utxo_amount: None,
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sig_hash_code: SigHashCode::SIGHASH_ALL
            },
            INPUT_FILLER
        ];

        const INVALID_OUTPUTS: [Output; 5] = [
            Output {
                address: "ABCD",
                amount: 100
            },
            Output {
                address: "INVALID ADDRESS",
                amount: 12345
            },
            Output {
                address: "0xE345828db876E265Dc2cea04c6b16F62021841A1",
                amount: 100000
            },
            Output {
                address: "1PhyG9uGuEAne9BUjtDkBr8pcPGHtdZ",
                amount: 5
            },
            OUTPUT_FILLER
        ];

        #[test]
        fn test_invalid_inputs() {

            // Not enough information to craft a bitcoin transaction input

            for input in INVALID_INPUTS.iter() {
                let transaction_id = hex::decode(input.transaction_id).unwrap();

                let redeem_script = match input.redeem_script {
                    None => None,
                    Some(redeem_script) => Some(hex::decode(redeem_script).unwrap())
                };
                let script_pub_key = match input.script_pub_key {
                    None => None,
                    Some (script) => Some(hex::decode(script).unwrap())
                };

                let sequence = match input.sequence {
                    None => None,
                    Some(seq) => Some(seq.to_vec())
                };

                let private_key = BitcoinPrivateKey::from_wif(input.private_key).unwrap();
                let address = private_key.to_address(&input.address_format).unwrap();
                let invalid_input = BitcoinTransactionInput::new(
                    address,
                    transaction_id,
                    input.index,
                    input.utxo_amount,
                    redeem_script,
                    script_pub_key,
                    sequence,
                    input.sig_hash_code
                );
                assert!(invalid_input.is_err());
            }
        }

        #[test]
        fn test_invalid_outputs() {

            // Invalid output address

            for output in INVALID_OUTPUTS.iter() {
                let invalid_output = BitcoinTransactionOutput::new(
                    output.address,
                    output.amount
                );
                assert!(invalid_output.is_err());
            }
        }
    }

    mod test_real_mainnet_transactions {
        use super::*;

        const REAL_TRANSACTIONS: [(
            u32,
            u32,
            [Input; 4],
            [Output; 4],
            &str
        ); 5] = [
            ( // Transaction 1 -> Segwit P2SH_P2WPKH to P2PKH and Bech32(P2WPKH) (60805eb82c53d9c53900ad6d1c423ffc2235caa0c266625afd9cf03e856bf92c)
              1,
              0,
              [
                  Input {
                      private_key: "L1fUQgwdWcqGUAr3kFznuAP36Vw3oFeGHH29XRYMwxN1HpSw5yBm",
                      address_format: Format::P2SH_P2WPKH,
                      transaction_id: "a5766fafb27aba97e7aeb3e71be79806dd23f03bbd1b61135bf5792159f42ab6",
                      index: 0,
                      redeem_script: Some("0014b5ccbe3c5a285af4afada113a8619827fb30b2ee"),
                      script_pub_key: None,
                      utxo_amount: Some(80000),
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "176DPNootfp2bSiE7KQUZp1VZj5EyGQeCt",
                      amount: 35000
                  },
                  Output {
                      address: "bc1qcsjz44ce84j3650qfu9k87tyd3z8h4qyxz470n",
                      amount: 35000
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "01000000000101b62af4592179f55b13611bbd3bf023dd0698e71be7b3aee797ba7ab2af6f76a50000000017160014b5ccbe3c5a285af4afada113a8619827fb30b2eeffffffff02b8880000000000001976a91442cd2c7460acc561c96b11c4aa96d0346b84db7f88acb888000000000000160014c4242ad7193d651d51e04f0b63f9646c447bd404024730440220449ca32ff3f8da3c17c1813dac91010cb1fea7a77b2f63065184b8318e1b9ed70220315da34cfeae62c26557c40f5ac5cde46b2801349e6677fc96597b4bfee04b0b012102973e9145ca85357b06de3009a12db171d70bae8a648dc8188e49723a2a46459100000000"
            ),
            ( // Transaction 2 -> P2PKH to P2SH_P2WPKH and P2PKH uncompressed (76ef90fa70e4c10adc358432a979683a2cf1855ff545f88c5022dea8863ed5ab)
              1,
              0,
              [
                  Input {
                      private_key: "KzZQ4ZzAecDmeDqxEJqSKpCfpPCa1x74ouyBhXUgMV2UdqNcaJiJ",
                      address_format: Format::P2PKH,
                      transaction_id: "60805eb82c53d9c53900ad6d1c423ffc2235caa0c266625afd9cf03e856bf92c",
                      index: 0,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: None,
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "3QDTHVyuJrHixUhhsdZXQ7M8P9MQngmw1P",
                      amount: 12000
                  },
                  Output {
                      address: "1C5RdoaGMVyQy8qjk96NsL4dW79aVPYrCK",
                      amount: 12000
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "01000000012cf96b853ef09cfd5a6266c2a0ca3522fc3f421c6dad0039c5d9532cb85e8060000000006a473044022079471aadca4be014260a4788e7dc7d7168712c8f21c536f326caccb843569ab802206c7b464e3fbe0518f147ee7c5fa39c05e04e7ed17fbe464a2773b179fe0ef35401210384faa5d9710f727523906f6d2fe781b40cf58a3139d02eeaad293dd03be7b69cffffffff02e02e00000000000017a914f7146aaa6f24a1012528c1d27cfe49d256d5a70187e02e0000000000001976a914797f9c80ef57ba7f30b31598383683923a5a7a7c88ac00000000"
            ),
            ( // Transaction 3 -> Bech32 (P2WPKH) to P2SH_P2WPKH (32464234781c37831398b5d2f1e1766f8dbb55ac3b41ed047e365c07e9b03429)
              1,
              0,
              [
                  Input {
                      private_key: "L5HiUByNV6D4anzT5aMhheZpG9oKdcvoPXjWJopEPiEzFisNTM7X",
                      address_format: Format::Bech32,
                      transaction_id: "60805eb82c53d9c53900ad6d1c423ffc2235caa0c266625afd9cf03e856bf92c",
                      index: 1,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: Some(35000),
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "3QDTHVyuJrHixUhhsdZXQ7M8P9MQngmw1P",
                      amount: 25000
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "010000000001012cf96b853ef09cfd5a6266c2a0ca3522fc3f421c6dad0039c5d9532cb85e80600100000000ffffffff01a86100000000000017a914f7146aaa6f24a1012528c1d27cfe49d256d5a701870247304402206af8b1cad8d8138631f2b2b08535643afb0c9597e1dd9b8daa4a565be274c96902203844c6af50658fb244370afaaffdb6f6e85ca681b80cd094bfd4f3eeae4febf0012103dcf5a50ac66bde7fe9f01c4710fb5d438d51f1da1ce138863d34fee6499f328900000000"
            ),
            ( // Transaction 4 -> Segwit P2SH_P2WPKH to Bech32(P2WPKH) and itself (6a06bd83718f24dd1883332939e59fdd26b95d8a328eac37a45b7c489618eac8)
              1,
              0,
              [
                  Input {
                      private_key: "L5TmwLMEyEqMAYj1qd7Fx9YRhNJTCvNn4ofr98ErbgHA99GjLBXC",
                      address_format: Format::P2SH_P2WPKH,
                      transaction_id: "32464234781c37831398b5d2f1e1766f8dbb55ac3b41ed047e365c07e9b03429",
                      index: 0,
                      redeem_script: Some("0014354816a98500d7df9201d46e008c203dd5143b92"),
                      script_pub_key: None,
                      utxo_amount: Some(25000),
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  Input {
                      private_key: "L5TmwLMEyEqMAYj1qd7Fx9YRhNJTCvNn4ofr98ErbgHA99GjLBXC",
                      address_format: Format::P2SH_P2WPKH,
                      transaction_id: "76ef90fa70e4c10adc358432a979683a2cf1855ff545f88c5022dea8863ed5ab",
                      index: 0,
                      redeem_script: Some("0014354816a98500d7df9201d46e008c203dd5143b92"),
                      script_pub_key: None,
                      utxo_amount: Some(12000),
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER,
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "bc1qzkuhp5jxuvwx90eg65wkxuw6y2pfe740yw6h5s",
                      amount: 12000
                  },
                  Output {
                      address: "3QDTHVyuJrHixUhhsdZXQ7M8P9MQngmw1P",
                      amount: 15000
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "010000000001022934b0e9075c367e04ed413bac55bb8d6f76e1f1d2b5981383371c78344246320000000017160014354816a98500d7df9201d46e008c203dd5143b92ffffffffabd53e86a8de22508cf845f55f85f12c3a6879a9328435dc0ac1e470fa90ef760000000017160014354816a98500d7df9201d46e008c203dd5143b92ffffffff02e02e00000000000016001415b970d246e31c62bf28d51d6371da22829cfaaf983a00000000000017a914f7146aaa6f24a1012528c1d27cfe49d256d5a7018702483045022100988bc569371f74d6e49f20ae05ab06abfbe7ba92bbc177b61e38c0c9f430646702207a874da47387b6cfc066c26c24c99ccb75dac6772a0f94b7327703bdb156c4c8012103f850b5fa8fe53be8675dd3045ed89c8a4235155b484d88eb62d0afed7cb9ef050247304402204296465f1f95480f058ccebd70a0f80b9f092021a15793c954f39373e1e6500102206ca2d3f6cb68d1a9fde36ed6ded6509e2284c6afe860abf7f49c3ae18944ffdf012103f850b5fa8fe53be8675dd3045ed89c8a4235155b484d88eb62d0afed7cb9ef0500000000"
            ),
            ( // Transaction 5 -> P2SH_P2WPKH, P2PKH uncompressed, and Bech32(P2WPKH) to Bech32(P2WPKH) (b2eb46fe6f8075caf013cd8e947f3b9dc06a416896d28aef450c9ec8d310361f)
              1,
              0,
              [
                  Input {
                      private_key: "L5TmwLMEyEqMAYj1qd7Fx9YRhNJTCvNn4ofr98ErbgHA99GjLBXC",
                      address_format: Format::P2SH_P2WPKH,
                      transaction_id: "6a06bd83718f24dd1883332939e59fdd26b95d8a328eac37a45b7c489618eac8",
                      index: 1,
                      redeem_script: Some("0014354816a98500d7df9201d46e008c203dd5143b92"),
                      script_pub_key: None,
                      utxo_amount: Some(15000),
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  Input {
                      private_key: "5KRoKpnWWav74XDgz28opnJUsBozUg8STwEQPq354yUa3MiXySn",
                      address_format: Format::P2PKH,
                      transaction_id: "76ef90fa70e4c10adc358432a979683a2cf1855ff545f88c5022dea8863ed5ab",
                      index: 1,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: None,
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  Input {
                      private_key: "Kzs2rY8y9brmULJ3VK9gZHiZAhNJ2ttjn7ZuyJbG52pToZfCpQDr",
                      address_format: Format::Bech32,
                      transaction_id: "6a06bd83718f24dd1883332939e59fdd26b95d8a328eac37a45b7c489618eac8",
                      index: 0,
                      redeem_script: None,
                      script_pub_key: None,
                      utxo_amount: Some(12000),
                      sequence: Some([0xff, 0xff, 0xff, 0xff]),
                      sig_hash_code: SigHashCode::SIGHASH_ALL
                  },
                  INPUT_FILLER
              ],
              [
                  Output {
                      address: "bc1qmj865gnmg3hv7eh74qmvu5fcde43ecd7haa5hy",
                      amount: 30000
                  },
                  OUTPUT_FILLER,
                  OUTPUT_FILLER,
                  OUTPUT_FILLER
              ],
              "01000000000103c8ea1896487c5ba437ac8e328a5db926dd9fe53929338318dd248f7183bd066a0100000017160014354816a98500d7df9201d46e008c203dd5143b92ffffffffabd53e86a8de22508cf845f55f85f12c3a6879a9328435dc0ac1e470fa90ef76010000008b4830450221008bf28b9f9e2c6d7d0ef9705b7fd914e7693b2f4f3584deff6dfa9dc83fc9f73402201cdbf5cd78bf04ccedfa11f17cff3728965dd328d30fad4f91ba2be57fb2ccab014104db232c08ac5f0332d317e6cd805f3e29e98b93fc9ca74831a6c5d27a0368cdb0862d536a445250a8de9d92cf1d450c7dc9b8efd6ca2ff0865d553f85f1bd346fffffffffc8ea1896487c5ba437ac8e328a5db926dd9fe53929338318dd248f7183bd066a0000000000ffffffff013075000000000000160014dc8faa227b446ecf66fea836ce51386e6b1ce1be02483045022100c77d6548c8f068d7088d1a5eab91be1f4bd394fdd7e7334699ccb1533af2c6300220621399e24b9f84bb580fab62ced44b979f0b5a06a1c429ffe4f8c2ae27f740fb012103f850b5fa8fe53be8675dd3045ed89c8a4235155b484d88eb62d0afed7cb9ef05000247304402205b3676bb82313d8ed25dec2efc30aa24076b4a5c0dc0e2b2953507a8135a470102207cad2e535a5cac8b947c9d37aeb9162ec745c61b7133eafba790442faa2a19000121030f36fbc8825fcdc2b79e5764b6bb70c2038bf4dba63dbf71483320e4d7f63a0500000000"
            )
        ];

        #[test]
        fn test_real_transactions() {
            REAL_TRANSACTIONS.iter()
                .for_each(|(
                               version,
                               lock_time,
                               inputs,
                               outputs,
                               expected_signed_transaction
                           )| {
                    let mut pruned_inputs = inputs.to_vec();
                    pruned_inputs.retain(|input| input.transaction_id != "");

                    let mut pruned_outputs = outputs.to_vec();
                    pruned_outputs.retain(|output| output.address != "");

                    test_transaction(*version, *lock_time, pruned_inputs, pruned_outputs, expected_signed_transaction);
                });
        }
    }
}