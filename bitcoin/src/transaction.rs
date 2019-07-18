use crate::address::{BitcoinAddress, Format};
use crate::private_key::BitcoinPrivateKey;
use byteorder::{LittleEndian, WriteBytesExt};
use std::str::FromStr;
use base58::{FromBase58};
use secp256k1::Secp256k1;
use sha2::{Digest, Sha256};
use wagu_model::{PrivateKey, AddressError};

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
    /// Type of address the outpoint is associated with
    pub address_type: Format
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
            serialized_transaction.extend(input.serialize(raw)?);
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
                                input_index: usize
    ) -> Result<Vec<u8>, std::io::Error> {
        let input = &self.inputs[input_index];

        let transaction_hash_preimage  = if input.out_point.address_type == Format::P2PKH {
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

        // Public Key must always be compressed - https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#restrictions-on-public-key-type
        let public_key = private_key.to_public_key().public_key.serialize().to_vec();
        let mut public_key_length: Vec<u8> = Vec::new();
        public_key_length.write_u8(public_key.len() as u8).unwrap();

        if input.out_point.address_type == Format::P2PKH {
            let mut final_script = signature_length;
            final_script.extend(&signature);
            final_script.extend(public_key_length);
            final_script.extend(public_key);

            self.inputs[input_index].create_script_sig(final_script);
        } else if input.out_point.address_type == Format::P2SH_P2WPKH {
            self.segwit_flag = true;

            let input_script = input.out_point.redeem_script.clone().unwrap();
            let mut new_script = variable_integer_length(input_script.len() as u64);
            new_script.extend(input_script);

            let mut witness_sig = signature_length;
            let mut witness_public_key = public_key_length;

            witness_sig.extend(&signature);
            witness_public_key.extend(public_key);

            let mut full_witness: Vec<BitcoinTransactionWitness> = vec![
                BitcoinTransactionWitness { witness: witness_sig },
                BitcoinTransactionWitness { witness: witness_public_key }];

            self.inputs[input_index].create_script_sig(new_script);
            self.inputs[input_index].witnesses.append(&mut full_witness);
            self.inputs[input_index].witness_count = Some(variable_integer_length(self.inputs[input_index].witnesses.len() as u64));
        }
//        else if input.out_point.address_type == Format::Bech32 {  // Spend from Bech32
//
//        }

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
        let input = &self.inputs[input_index];
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

        let hash_prev_outputs = Sha256::digest(&Sha256::digest(&prev_outputs));
        let hash_sequence = Sha256::digest(&Sha256::digest(&prev_sequences));
        let hash_outputs = Sha256::digest(&Sha256::digest(&outputs));
        let version_bytes = u32_to_bytes(self.version)?;
        let mut total_utxo_amount: Vec<u8> = Vec::new();
        let mut script_code: Vec<u8> = Vec::new();
        let mut redeem_script = input.out_point.redeem_script.clone().unwrap();
        total_utxo_amount.write_u64::<LittleEndian>(input.out_point.amount.unwrap())?;
        redeem_script = redeem_script[1..].to_vec();

        let op_dup: Vec<u8> = vec![OPCodes::OP_DUP as u8];
        let op_hash160: Vec<u8> = vec![OPCodes::OP_HASH160 as u8];
        let op_equal_verify: Vec<u8> = vec![OPCodes::OP_EQUALVERIFY as u8];
        let op_checksig: Vec<u8> = vec![OPCodes::OP_CHECKSIG as u8];

        script_code.extend(op_dup);
        script_code.extend(op_hash160);
        script_code.extend(redeem_script);
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
    /// Create a new Bitcoin Transaction input without the script
    pub fn new(
        transaction_id: Vec<u8>,
        index: u32, amount: Option<u64>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
        sequence: Option<Vec<u8>>,
        sig_hash_code: SigHashCode
    ) -> Result<Self,  &'static str> {
        if transaction_id.len() != 32 {
            return Err("invalid transaction id");
        }

        if amount.is_none() && redeem_script.is_none() && script_pub_key.is_none() {
            return Err("insufficient information to craft transaction input");
        }

        let default_sequence_number: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        let sequence = match sequence {
            None => default_sequence_number,
            Some(sequence) => sequence
        };

        // Bitcoin uses reverse hash order - https://bitcoin.org/en/developer-reference#hash-byte-order
        let mut reverse_transaction_id = transaction_id;
        reverse_transaction_id.reverse();

        let address_type: Format = find_address_type(redeem_script.clone(), script_pub_key.clone())?;
        let out_point = OutPoint { reverse_transaction_id, index, amount, redeem_script, script_pub_key, address_type };

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

    let bitcoin_address = bitcoin_address;
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
//            Format::Bech32 => { // Bech 32 implementation for P2SH_P2WPKH and P2SH_P2WSH
//
//                // Add witness program here for script_pub_key
//            }
    }
    let script_length = variable_integer_length(script.len() as u64);

    Ok(Script { script_length, script })
}

// Determine the address type (P2PKH, P2SH_P2PKH, etc.) with the given scripts
pub fn find_address_type (redeem_script: Option<Vec<u8>>, script_pub_key: Option<Vec<u8>>) -> Result<Format,  &'static str> {
    let op_dup = OPCodes::OP_DUP as u8;
    let op_hash160 = OPCodes::OP_HASH160 as u8;
    let op_checksig = OPCodes::OP_CHECKSIG as u8;
    let op_equal = OPCodes::OP_EQUAL as u8;

    if script_pub_key.is_none() && redeem_script.is_none() {
        Err("redeem script and script_pub_key are both None")
    } else if redeem_script.is_none() {
        Ok(Format::P2PKH)
    } else if script_pub_key.is_some() {
        let script_pub_key = script_pub_key.unwrap();
        if script_pub_key[0] == op_dup && script_pub_key[1] == op_hash160 && script_pub_key[script_pub_key.len() -1] == op_checksig {
            Ok(Format::P2PKH)
        } else if script_pub_key[0] == op_hash160 &&
            script_pub_key[script_pub_key.len() -1] == op_equal
        {
            Ok(Format::P2SH_P2WPKH)
        } else {
            Ok(Format::P2SH_P2WPKH) // UNIMPLEMENTED - wallet/address formats: Bech32 and P2SH
        }
    } else {
        Ok(Format::P2SH_P2WPKH) // UNIMPLEMENTED - wallet/address formats: Bech32 and P2SH
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
            private_key: "",
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
            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = match input.redeem_script {
                None => None,
                Some(redeem_script) => Some(hex::decode(redeem_script).unwrap())
            };
            let script_pub_key = match input.script_pub_key {
                None => {
                    let private_key = BitcoinPrivateKey::from_wif(input.private_key).unwrap();
                    let address = private_key.to_address(&input.address_format);
                    Some(generate_script_pub_key(&address.unwrap().to_string()).unwrap().script)
                }
                Some (script) => Some(hex::decode(script).unwrap())
            };

            let sequence = match input.sequence {
                None => None,
                Some(seq) => Some(seq.to_vec())
            };

            let transaction_input = BitcoinTransactionInput::new(transaction_id, input.index, input.utxo_amount, redeem_script, script_pub_key, sequence, input.sig_hash_code).unwrap();
            input_vec.push(transaction_input);
        }

        let mut output_vec: Vec<BitcoinTransactionOutput> = Vec::new();
        for output in outputs {
            let transaction_output = BitcoinTransactionOutput::new(output.address, output.amount).unwrap();
            output_vec.push(transaction_output);
        }

        let mut transaction = BitcoinTransaction::build_raw_transaction(version, input_vec, output_vec, lock_time);
        for index in 0..inputs.len() {
            let private_key = BitcoinPrivateKey::from_wif(inputs[index].private_key).unwrap();
            transaction.sign_raw_transaction(private_key, index).unwrap();
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
        ); 7] = [
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
                      redeem_script: Some("001479091972186c449eb1ded22b78e40d009bdf0089"),
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
                      redeem_script: Some("0014e709f020a951e483eb6628e0ee9abce30da49ffb"),
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
                      redeem_script: Some("0014b93f973eb2bf0b614bddc0f47286788c98c535b4"),
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
                      redeem_script: Some("00143d295b6276ff8e4579f3350873db3e839e230f41"),
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
                      redeem_script: Some("00142b654d833c287e239f73ba8165bbadf4dee3c00e"),
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
}