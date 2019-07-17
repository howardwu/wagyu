use crate::address::{BitcoinAddress, Format};
use crate::private_key::BitcoinPrivateKey;
use byteorder::{LittleEndian, WriteBytesExt};
use std::str::FromStr;
use base58::{FromBase58};
use secp256k1::Secp256k1;
use sha2::{Digest, Sha256};
use wagu_model::{PrivateKey, crypto::{checksum, hash160}};

/// Represents a raw Bitcoin transaction
pub struct BitcoinTransaction {
    // Version number - 4 bytes
    pub version : u32,
    // Optional 2 bytes to indicate segwit transactions
    pub segwit_flag : bool,
    // Variable integer length input size
    pub input_count: Vec<u8>,
    pub inputs: Vec<BitcoinTransactionInput>,
    pub output_count: Vec<u8>,
    pub outputs: Vec<BitcoinTransactionOutput>,
    // Lock time - 4 bytes
    pub lock_time: u32
}

pub struct BitcoinTransactionInput {
    // OutPoint - transaction id and index - 36 bytes
    pub out_point: OutPoint,
    // Tx-in script - Variable size
    pub script: Option<Script>,
    // Sequence number - 4 bytes (normally 0xFFFFFFFF, unless lock > 0)
    // Also used in replace-by-fee - BIP 125.
    pub sequence: Vec<u8>,
    // SIGHASH Code - 4 Bytes (used in signing raw transaction only)
    pub sig_hash_code: SigHashCode,
    pub witness_count: Option<Vec<u8>>,
    pub witnesses: Vec<BitcoinTransactionWitness>,
}

pub struct BitcoinTransactionOutput {
    // Transfer value in Satoshis
    pub value: u64,
    // Output public key script
    pub script_public_key: Script
}

pub struct OutPoint {
    // Previous transaction hash (using Bitcoin RPC's reversed hash order) - 32 bytes
    pub reverse_transaction_id: Vec<u8>,
    // Index of the transaction being used - 4 bytes
    pub index: u32,
    pub amount: Option<u64>,
    // Script pub key asssociated with claiming this particular input UTXO
    pub script_pub_key: Option<Vec<u8>>,
    // Optional redeem script for scriptsig's
    pub redeem_script: Option<Vec<u8>>,
    // Type of address the outpoint is associated with
    pub address_type: Format
}

pub struct Script {
    // Length of the script - 1 to 9 bytes
    pub script_length: Vec<u8>,
    // Transaction input script - Variable size
    pub script: Vec<u8>
}

pub struct BitcoinTransactionWitness {
    // The witness in segwit transactions
    pub witness: Vec<u8>
}

#[derive(Clone)]
#[allow(non_camel_case_types)]
pub enum SigHashCode {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
}

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

#[allow(non_camel_case_types)]
pub enum OPCodes {
    OP_DUP = 0x76,
    OP_HASH160 = 0xa9,
    OP_CHECKSIG = 0xac,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
}

impl BitcoinTransaction {
    // Build the base unsigned transaction
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

    // Serialize a transaction into a byte vector
    pub fn serialize_transaction(&mut self, raw: bool) -> Vec<u8> {
        let mut serialized_transaction: Vec<u8> = Vec::new();

        let version_bytes = u32_to_bytes(self.version);
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
            let serialized_input = input.serialize(raw);
            serialized_transaction.extend(serialized_input);
        }

        serialized_transaction.extend(&self.output_count);

        for output in  &self.outputs {
            let serialized_output = output.serialize();
            serialized_transaction.extend(serialized_output);
        }

        for input in &self.inputs {
            if has_witness {
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

        let lock_time_bytes = u32_to_bytes(self.lock_time);
        serialized_transaction.extend(lock_time_bytes);
        serialized_transaction
    }

    // Sign a raw transaction and fill the script_sig field of the transaction input
    pub fn sign_raw_transaction(&mut self,
                                private_key: BitcoinPrivateKey,
                                input_index: usize
    ) -> Vec<u8> {
        let input = &self.inputs[input_index];

        let transaction_hash_preimage  = if input.out_point.address_type == Format::P2PKH {
            self.generate_p2pkh_hash_preimage(input_index, input.sig_hash_code.clone())
        } else { // segwit transaction - new digest: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
            self.generate_segwit_hash_preimage(input_index, input.sig_hash_code.clone())
        };


        let transaction_hash = Sha256::digest(&Sha256::digest(&transaction_hash_preimage));
        let message = secp256k1::Message::from_slice(&transaction_hash).unwrap();

        let sign = Secp256k1::signing_only();
        let signing_key = private_key.secret_key;
        let signature_bytes =  sign.sign(&message, &signing_key).serialize_der(&sign);

        let mut signature = signature_bytes.to_vec();

        let sig_hash_code_bytes = u32_to_bytes(input.sig_hash_code.value());
        signature.extend(vec![sig_hash_code_bytes[0]]); // Add the SIG_HASH ALL TO THE END OF THE signature

        let signature_length = variable_integer_length(signature.len() as u64 );

        let pub_key: Vec<u8> = hex::decode(private_key.to_public_key().public_key.to_string()).unwrap();

        let pub_key_length: Vec<u8> = if pub_key.len() == 33 {
            vec![0x21] // Size 33 compressed pub key
        } else {
            vec![0x41] // Size 65 uncompressed pub key
        };

        if input.out_point.address_type == Format::P2PKH {
            let mut final_script = signature_length;
            final_script.extend(&signature);
            //update input scriptsigs

            final_script.extend(pub_key_length);
            final_script.extend(pub_key);

            self.inputs[input_index].create_script_sig(final_script);
        } else if self.inputs[input_index].out_point.address_type == Format::P2SH_P2WPKH {
            // Add witness and update scriptsig
            self.segwit_flag = true;

            // INCLUDES LENGTH OF SCRIPTSIG IN THE NEW SCRIPTSIG
            // ref: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
            let new_script_option = self.inputs[input_index].out_point.redeem_script.clone();
            let temp_new_script = new_script_option.unwrap();
            let mut new_script = variable_integer_length(temp_new_script.len() as u64);
            new_script.extend(temp_new_script);

            self.inputs[input_index].create_script_sig(new_script);

            // Add the witness
            let mut witness_sig = signature_length;
            witness_sig.extend(&signature);
            let mut witness_pub_key = pub_key_length;
            witness_pub_key.extend(pub_key);

            let mut new_vec: Vec<BitcoinTransactionWitness> = vec![
                BitcoinTransactionWitness { witness: witness_sig },
                BitcoinTransactionWitness { witness: witness_pub_key }];

            self.inputs[input_index].witnesses.append(&mut new_vec);
            self.inputs[input_index].witness_count = Some(variable_integer_length(self.inputs[input_index].witnesses.len() as u64));
        }
//        else if self.inputs[input_index].out_point.address_type == Format::Bech32 {  // Spend from Bech32
//
//        }

        signature
    }

    pub fn generate_p2pkh_hash_preimage(&self, input_index: usize, sig_hash_code: SigHashCode) -> Vec<u8> {
        let mut transaction_hash_preimage: Vec<u8> = Vec::new();

        let version_bytes = u32_to_bytes(self.version);
        transaction_hash_preimage.extend(version_bytes);
        transaction_hash_preimage.extend(&self.input_count);

        for index in 0..self.inputs.len() {
            let input = &self.inputs[index];
            if index == input_index {
                let serialized_input = input.serialize(false);
                transaction_hash_preimage.extend(serialized_input);
            } else {
                let serialized_input = input.serialize(true);
                transaction_hash_preimage.extend(serialized_input);
            }
        }

        transaction_hash_preimage.extend(&self.output_count);
        for output in  &self.outputs {
            let serialized_output = output.serialize();
            transaction_hash_preimage.extend(serialized_output);
        }

        let lock_time_bytes = u32_to_bytes(self.lock_time);
        transaction_hash_preimage.extend(lock_time_bytes);
        let sig_hash_code_bytes = u32_to_bytes(sig_hash_code.value());
        transaction_hash_preimage.extend(sig_hash_code_bytes);

        transaction_hash_preimage
    }

    // Generate a hash preimage based on https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
    pub fn generate_segwit_hash_preimage(&self, input_index: usize, sig_hash_code: SigHashCode) -> Vec<u8>{
        let mut transaction_hash_preimage: Vec<u8> = Vec::new();
        let input = &self.inputs[input_index];
        let mut prev_outputs: Vec<u8> = Vec::new();
        let mut prev_sequences: Vec<u8> = Vec::new();
        let mut outputs: Vec<u8> = Vec::new();

        for input in &self.inputs {
            prev_outputs.extend(&input.out_point.reverse_transaction_id);
            prev_outputs.extend(u32_to_bytes(input.out_point.index));
            prev_sequences.extend(&input.sequence);
        }

        for output in &self.outputs {
            outputs.extend(&output.serialize());
        }

        let hash_prev_outputs = Sha256::digest(&Sha256::digest(&prev_outputs));
        let hash_sequence = Sha256::digest(&Sha256::digest(&prev_sequences));
        let hash_outputs = Sha256::digest(&Sha256::digest(&outputs));

        let version_bytes = u32_to_bytes(self.version);
        transaction_hash_preimage.extend(version_bytes);
        transaction_hash_preimage.extend(hash_prev_outputs);
        transaction_hash_preimage.extend(hash_sequence);

        transaction_hash_preimage.extend(&input.out_point.reverse_transaction_id);
        transaction_hash_preimage.extend(u32_to_bytes(input.out_point.index));

        let mut script_code: Vec<u8> = Vec::new();
        let mut redeem_script = input.out_point.redeem_script.clone().unwrap();
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
        transaction_hash_preimage.extend(&script_code_with_length);

        let mut total_utxo_amount: Vec<u8> = Vec::new();
        total_utxo_amount.write_u64::<LittleEndian>(input.out_point.amount.unwrap()).unwrap();
        transaction_hash_preimage.extend(total_utxo_amount);
        transaction_hash_preimage.extend(&input.sequence);
        transaction_hash_preimage.extend(hash_outputs);

        transaction_hash_preimage.extend(u32_to_bytes(self.lock_time));
        transaction_hash_preimage.extend(u32_to_bytes(sig_hash_code.value()));

        transaction_hash_preimage
    }
}

pub fn u32_to_bytes(num: u32) -> Vec<u8> {
    let mut num_vec: Vec<u8> = Vec::new();
    num_vec.write_u32::<LittleEndian>(num).unwrap();
    num_vec
}

pub fn address_to_pub_key_or_script_hash(address: String) -> Vec<u8> {
    let mut pub_key_or_script_hash = address.from_base58().unwrap();
    pub_key_or_script_hash = pub_key_or_script_hash[1..(pub_key_or_script_hash.len()-4)].to_vec();
    pub_key_or_script_hash

}

pub fn generate_script_pub_key(bitcoin_address: &str) -> Result<Script,  &'static str> {
    let bitcoin_address = BitcoinAddress::from_str(bitcoin_address);
    if bitcoin_address.is_err() {
        return Err("invalid/unsupported bitcoin address")
    }
    let bitcoin_address = bitcoin_address.unwrap();

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
    let script_size_bytes: u64 = script.len() as u64;
    let script_length = variable_integer_length(script_size_bytes);

    Ok(Script { script_length, script })
}

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
            Ok(Format::P2SH_P2WPKH) // UNIMPLEMENTED Bech32 and P2SH integration
        }
    } else {
        Ok(Format::P2SH_P2WPKH) // UNIMPLEMENTED - other wallet/address formats
    }
}

// Convert input size to Bitcoin variable length integer format
// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
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

impl BitcoinTransactionInput {
    // Create a new Bitcoin Transaction input without the script_sig
    pub fn new(transaction_id: Vec<u8>, index: u32, amount: Option<u64>, redeem_script: Option<Vec<u8>>, script_pub_key: Option<Vec<u8>>, seq: Option<Vec<u8>>, sig_hash_code: SigHashCode, ) -> Result<Self,  &'static str> {

        if amount.is_none() && redeem_script.is_none() && script_pub_key.is_none() {
            return Err("insufficient information to craft transaction input");
        }

        let default_sequence_number: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];

        let sequence = match seq {
            None => default_sequence_number,
            Some(seq) => seq
        };

        let mut reverse_transaction_id = transaction_id; // Bitcoin uses reverse hash order - https://bitcoin.org/en/developer-reference#hash-byte-order
        reverse_transaction_id.reverse();


        let address_type: Format = find_address_type(redeem_script.clone(), script_pub_key.clone()).unwrap();
        let out_point = OutPoint { reverse_transaction_id, index, amount, redeem_script, script_pub_key, address_type };
        let script = None;

        Ok(Self { out_point, script, sequence, sig_hash_code, witness_count: None,  witnesses: vec![] })
    }

    pub fn create_script_sig(&mut self, script: Vec<u8>) {
        let script_size_bytes: u64 = script.len() as u64;
        let script_length = variable_integer_length(script_size_bytes);
        self.script = Some(Script { script_length, script });
    }

    pub fn serialize(&self, raw: bool) -> Vec<u8> {
        let mut serialized_input: Vec<u8> = Vec::new();
        serialized_input.extend(&self.out_point.reverse_transaction_id);
        serialized_input.extend(u32_to_bytes(self.out_point.index));
        match &self.script {
            None => {
                if raw { // For raw transaction signing
                    serialized_input.extend(vec![0x00]);
                } else {
                    let script_pub_key = &self.out_point.script_pub_key.clone().unwrap();
                    let script_pub_key_length = variable_integer_length(script_pub_key.len() as u64);
                    serialized_input.extend(script_pub_key_length);
                    serialized_input.extend(script_pub_key);
                }
            },
            Some(script) => {
                if raw { // For raw transaction signing
                    serialized_input.extend(vec![0x00]);
                } else {
                    serialized_input.extend(&script.script_length);
                    serialized_input.extend(&script.script);
                }
            }
        }
        serialized_input.extend(&self.sequence);
        serialized_input
    }
}

impl BitcoinTransactionOutput {
    pub fn new(value: u64, bitcoin_address: &str) -> Self {
        let script_public_key = generate_script_pub_key(bitcoin_address).unwrap();
        Self { value, script_public_key }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut value_vec: Vec<u8> = Vec::new();
        value_vec.write_u64::<LittleEndian>(self.value).unwrap();

        let mut serialized_output = value_vec;
        serialized_output.extend( &self.script_public_key.script_length);
        serialized_output.extend(&self.script_public_key.script);
        serialized_output
    }
}
