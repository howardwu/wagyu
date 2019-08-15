use crate::address::{MoneroAddress, Format};
use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;
use crate::one_time_key::OneTimeKey;
use wagyu_model::{PrivateKey, TransactionError, Transaction};

use base58_monero as base58;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use tiny_keccak::keccak256;

///// Fields needed to input a Monero transaction to script
//pub struct ScriptInput<N: MoneroNetwork> {
//    prev: hash,
//    prevout: usize,
//    sigset: Vec<Signature>,
//}

///// Fields need to input a Monero tranasction to script hash
//pub struct ScriptHashInput {
//    prev: hash,
//    prevout: usize,
//    txout_to_script: script,
//    sigset: Vec<Signature>,
//}


/// Fields needed to input a Monero transaction to one time key
pub struct KeyInput {
    key_offsets: Vec<u64>,
    key_image: [u8; 32],
}

/// Represents a Monero transaction input
pub struct MoneroTransactionInput {
    /// block height of where the coinbase transaction is included
    height: usize,
    /// a one time key input
    to_key: KeyInput,
//    /// Input from script input
//    to_script: ScriptInput<N>,
//    /// Input from script hash input
//    to_script_hash: ScriptHashInput<N>,
}

///// Fields needed to output a Monero transaction to script
//pub struct ScriptOutput<N: MoneroNetwork> {
//    keys: Vec<MoneroPublicKey<N>>,
//    script: Vec<u8>,
//}
//
///// Fields needed to output a Monero transaction to script hash
//pub struct ScriptHashOutput<N: MoneroNetwork> {
//    hash: hash
//}

/// Fields needed to output a Monero transaction to one time key
pub struct KeyOutput<N: MoneroNetwork> {
    amount: u64,
    key: OneTimeKey<N>,
}

/// Represents a Monero transaction output
pub struct MoneroTransactionOutput<N: MoneroNetwork> {
    /// output to one-time public key
    to_key: KeyOutput<N>,
//    /// Output to script
//    to_script: ScriptOutput<N>,
//    /// Output to script hash
//    to_script_hash: ScriptHashOutput<N>
}

/// Represents a Monero transaction prefix
pub struct MoneroTransactionPrefix<N: MoneroNetwork> {
    /// transaction format version 0 = miner, 1 = RctFull, 2 = RctSimple
    version: u64,
    /// unix unlock time (or block), used as a limitation like: spend this tx not early then block/time
    unlock_time: u64,
    /// extra field: transaction public key or additional public keys
    extra: Vec<u8>,
    /// transaction inputs
    inputs: Vec<MoneroTransactionInput>,
    /// transaction outputs
    outputs: Vec<MoneroTransactionOutput<N>>,
}

/// Represents a Monero transaction
pub struct MoneroTransaction<N: MoneroNetwork> {
    /// transaction prefix
    prefix: MoneroTransactionPrefix<N>,
//    /// Count signatures always the same as inputs count
//    signatures: Vec<Signature>,
//    /// Ring confidential transactions signatures
//    rct_signatures: Vec<RctSignature>,
//    set_hash_valid: bool,
//    set_blob_size_valid: bool,
//    pruned: bool,
//    unprunable_size: u8,
//    prefix_size: u8,
}

//impl <N: MoneroNetwork> Transaction for MoneroTransaction<N> {
//    type Address = MoneroAddress<N>;
//    type Format = Format;
//    type PrivateKey = MoneroPrivateKey<N>;
//    type PublicKey = MoneroPublicKey<N>;
//}

/// Represents a source entry used to construct a Monero transaction
pub struct TxSourceEntry {
    /// index + key + optional ringct commitment
    outputs: Vec<(u64, [u8; 32])>,
    /// index in outputs vector of real output_entry
    real_output: u64,
    /// incoming real tx public key
    real_out_tx_key: [u8; 32],
    /// incoming real tx additiona public keys
    real_out_additional_keys: Vec<[u8; 32]>,
    /// index in transaction outputs vector
    real_output_in_tx_index: u64,
    /// money
    amount: u64,
    /// true if output is rct
    rct: bool,
    //// ringct amount mask
//    mask: RctMask,
//    /// multisig info
//    multisig_kLRki: MultisigKLRki,
}

/// Represents a destination entry use to construct a Monero transaction
#[derive(Clone)]
pub struct TxDestinationEntry<N: MoneroNetwork> {
    /// I have no idea
    original: String,
    /// money
    amount: u64,
    /// destination address
    address: MoneroAddress<N>,
    is_subaddress: bool,
    is_integrated: bool,
}

/// The key image of a public key included in a ring signature
pub struct KeyImage {
    ephemeral_secret_key: [u8; 32],
    ephemeral_public_key: [u8; 32],
    image: [u8; 32]
}


impl<N: MoneroNetwork> MoneroTransaction<N> {
    /// Returns the number of standard addresses and subaddresses respectively
    fn classify_addresses(
        destinations: &Vec<TxDestinationEntry<N>>,
        change_address: &MoneroAddress<N>,
    ) -> (u8, u8) {
        let mut num_stdaddresses: u8 = 0;
        let mut num_subaddresses: u8 = 0;
        let mut single_dest_subaddress: MoneroAddress<N>;
        let mut unique_dst_addresses: Vec<MoneroAddress<N>> = Vec::new();
        for dst_entr in destinations.iter() {
            if change_address == &dst_entr.address {
                continue;
            }
            let num_of_occurrences = unique_dst_addresses.iter().filter(|&address| *address == dst_entr.address);
            if num_of_occurrences.count() == 0 {
                unique_dst_addresses.push(dst_entr.address.clone());
                match Format::from_address(&base58::decode(&dst_entr.address.to_string()).unwrap()).unwrap() {
                    Format::Subaddress(_, _) => {
                        num_subaddresses += 1;
//                        single_dest_subaddress = dst_entr.address;
                    }
                    _ => num_stdaddresses += 1
                }
            }
        }
        println!("destinations include {:?} standard addresses and {:?} subaddresses", num_stdaddresses, num_subaddresses);

//        single_dest_subaddress
        (num_stdaddresses, num_subaddresses)
    }

//    /// Returns keccak256 hash of serialized transaction prefix
//    fn get_transaction_prefix_hash(transaction: &MoneroTransaction<N>) -> [u8; 32] {
//        let mut prefix: Vec<u8> = Vec::new();
//        Self::serialize_transaction(transaction, &mut prefix, true);
//
//        keccak256(prefix.as_slice())
//    }
//
//    /// Returns keccak256 hash of transaction
//    fn get_transaction_hash(transaction: &MoneroTransaction<N>) -> [u8; 32] {
//        let mut tx: Vec<u8> = Vec::new();
//        Self::serialize_transaction(transaction, &mut tx, false);
//
//        keccak256(tx.as_slice())
//    }

//    /// Returns a serialized transaction or transaction prefix
//    fn serialize_transaction(transaction: &MoneroTransaction<N>, serialized: &mut Vec<u8>, header_only: bool) {
//        let transaction_prefix = &transaction.prefix;
//
//        //TODO: if possible, initialize vector of exact length based off header
//        serialized.extend(Self::encode_varint(transaction_prefix.version));
//        serialized.extend(Self::encode_varint(transaction_prefix.unlock_time));
//        serialized.extend(Self::encode_varint(transaction_prefix.inputs.len() as u64));
//
//        transaction_prefix.inputs.iter().for_each(|&input| {
//            let offsets = input.to_key.key_offsets;
//
//            serialized.extend(Self::encode_varint("02" as u64));
//            serialized.extend(Self::encode_varint(&offsets.len() as u64));
//
//            offsets.iter().for_each(|&key_offset| {
//                serialized.extend(key_offset);
//            });
//        });
//
//        serialized.extend(transaction_prefix.outputs.len() as u64);
//
//        transaction_prefix.outputs.iter().for_each(|&output| {
//            serialized.extend(&output.to_key.amount);
//            serialized.extend(Self::encode_varint("02" as u64));
//            serialized.extend_from_slice(&output.to_key.key.to_transaction_prefix_public_key());
//        });
//
//        serialized.extend(Self::encode_varint(transaction_prefix.extra.len() / 2 as u64));
//        serialized.extend(&transaction_prefix.extra);
//
////        uncomment after implementing signatures
////        if !header_only {
////            if transaction_prefix.inputs.len() != transaction.signatures.len() {
////                return Err(TransactionError::MoneroTransactionError);
////            }
////            transaction.signatures.iter.for_each(|&signature_row| {
////                signature_row.iter().for_each(|&signature_row_column| {
////                    serialized.extend(&signature_row_column);
////                });
////            });
////        }
//    }

    /// Encodes the index to conform to Monero consensus
    pub fn encode_varint(index: u64) -> Vec<u8> {
        // used here: https://github.com/monero-project/monero/blob/50d48d611867ffcd41037e2ab4fec2526c08a7f5/src/crypto/crypto.cpp#L195
        // impl here: https://github.com/monero-project/monero/blob/50d48d611867ffcd41037e2ab4fec2526c08a7f5/src/common/varint.h#L69
        let mut res: Vec<u8> = vec![];
        let mut n = index;
        loop {
            let bits = (n & 0b0111_1111) as u8;
            n = n >> 7;
            res.push(bits);
            if n == 0u64 {
                break;
            }
        }
        let mut encoded_bytes = vec![];
        match res.split_last() {
            Some((last, arr)) => {
                let _a: Vec<_> = arr
                    .iter()
                    .map(|bits| encoded_bytes.push(*bits | 0b1000_0000))
                    .collect();
                encoded_bytes.push(*last);
            }
            None => encoded_bytes.push(0x00),
        }

        encoded_bytes
    }

    /// Returns scalar base multiplication of public and secret key then multiplies result by cofactor
    pub fn generate_key_derivation(public: &[u8; 32], secret_key: &[u8; 32], dest: &mut Vec<u8>) {
        // r * A
        let r = Scalar::from_bits(*secret_key);
        let A = CompressedEdwardsY::from_slice(public)
            .decompress()
            .unwrap(); //TODO: remove unwraps

        let mut rA: EdwardsPoint = r * A;
        rA = rA.mul_by_cofactor(); //https://github.com/monero-project/monero/blob/50d48d611867ffcd41037e2ab4fec2526c08a7f5/src/crypto/crypto.cpp#L182

        dest.clear();
        dest.extend(rA.compress().to_bytes().to_vec());
    }

    /// Returns keccak256 hash of key derivation extended by output index as a scalar
    pub fn derivation_to_scalar(derivation: &Vec<u8>, output_index: u64) -> Scalar {
        // H_s(derivation || output_index)
        let mut derivation = derivation.clone();
        derivation.extend(&MoneroTransaction::<N>::encode_varint(output_index));

        Scalar::from_bytes_mod_order(keccak256(&derivation))
    }

    /// Returns a public key from key derivation, output index, and public spend key
    fn derive_public_key(derivation: &Vec<u8>, output_index: u64, public_spend_key: &[u8; 32]) -> [u8; 32] {
        let mut derivation = derivation.clone();
        let public_point = CompressedEdwardsY::from_slice(public_spend_key)
            .decompress()
            .unwrap();
        let derivation_at_index = &Self::derivation_to_scalar(&derivation, output_index) * &ED25519_BASEPOINT_TABLE;

        (public_point + derivation_at_index).compress().to_bytes()
    }

    /// Returns a secret key from key derivation, output index, and private spend key
    fn derive_secret_key(derivation: &Vec<u8>, output_index: u64, private_spend_key: &[u8; 32]) -> [u8; 32] {
        let mut derivation = derivation.clone();
        let secret = Scalar::from_bits(*private_spend_key);
        let derivation_at_index = Self::derivation_to_scalar(&derivation, output_index);

        (derivation_at_index + secret).to_bytes()
    }

    /// Returns keccack256 hash of key multiplied by cofactor as uncompressed Edwards point
    fn hash_to_ec(key: &[u8; 32]) -> EdwardsPoint {
        let hashed_key_point = CompressedEdwardsY::from_slice(&keccak256(key))
            .decompress()
            .unwrap();

        hashed_key_point.mul_by_cofactor()
    }

    /// Returns a public key image given ephemeral public and secret key
    fn generate_key_image(public_key: &[u8; 32], secret_key: &[u8; 32]) -> [u8; 32] {
        let secret_key_scalar = Scalar::from_bits(*secret_key);
        let image = Self::hash_to_ec(public_key) * secret_key_scalar;

        image.compress().to_bytes()
    }

    /// Returns help to generate the key image for the given source entry index
    fn generate_keys_and_key_image(
        sender_account_keys: &MoneroPrivateKey<N>,
        transaction_public_key: &[u8; 32],
        transaction_output_index: u64
    ) -> KeyImage {
        let mut recv_derivation = Vec::<u8>::new();
        Self::generate_key_derivation(transaction_public_key, &sender_account_keys.to_private_view_key(), &mut recv_derivation);
        let ephemeral_public_key = Self::derive_public_key(
            &recv_derivation,
            transaction_output_index,
            &sender_account_keys.to_public_key().to_public_spend_key().unwrap());
        let ephemeral_secret_key = Self::derive_secret_key(
            &recv_derivation,
            transaction_output_index,
            &sender_account_keys.to_private_spend_key());
        let image = Self::generate_key_image(&ephemeral_public_key, &ephemeral_secret_key);

        KeyImage {ephemeral_secret_key, ephemeral_public_key, image}
    }
    
    /// Returns a Monero transaction from given arguments
    pub fn construct_tx(
        sender_account_keys: MoneroPrivateKey<N>,
        sources: Vec<TxSourceEntry>,
        destinations: Vec<TxDestinationEntry<N>>,
        change_address: MoneroAddress<N>,
        extra: Vec<u8>,
        unlock_time: u64,
    ) -> Result<Self, TransactionError> {
        let mut subaddresses: HashMap<[u8; 32], (u8, u8)> = HashMap::new();
        subaddresses.insert(sender_account_keys.to_public_key().to_public_spend_key().unwrap(), (0, 0));

        // TODO: generate new secret key instead of just random bytes here
        let mut tx_key = [0u8; 32];
        thread_rng().fill(&mut tx_key[..]);

        let mut additional_tx_keys: Vec<[u8; 32]> = Vec::new();

        let mut destinations_copy: Vec<TxDestinationEntry<N>> = destinations.clone();

        Self::construct_tx_and_get_tx_key(
            sender_account_keys,
            subaddresses,
            sources,
            &destinations_copy,
            &change_address,
            extra,
            unlock_time,
            tx_key,
            &mut additional_tx_keys,
            false,
            0,
            false,
        )
    }

    /// Returns a Monero transaction and transaction key from given arguments
    pub fn construct_tx_and_get_tx_key(
        sender_account_keys: MoneroPrivateKey<N>,
        subaddresses: HashMap<[u8; 32], (u8, u8)>,
        sources: Vec<TxSourceEntry>,
        destinations: &Vec<TxDestinationEntry<N>>,
        change_address: &MoneroAddress<N>,
        extra: Vec<u8>,
        unlock_time: u64,
        tx_key: [u8; 32],
        additional_tx_keys: &mut Vec<[u8; 32]>,
        rct: bool,
        rct_config: u8,
        multisig_out: bool,
    ) -> Result<Self, TransactionError> {
        // figure out if we need to make additional tx pubkeys
        let (num_stdaddresses, num_subaddresses) = Self::classify_addresses(destinations, change_address);
        let need_additional_tx_keys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);

        if need_additional_tx_keys {
            additional_tx_keys.clear();
            for dest in destinations.iter() {
                // TODO: generate new secret key instead of just random bytes here
                let mut random_bytes = [0u8; 32];
                thread_rng().fill(&mut random_bytes[..]);
                additional_tx_keys.push(random_bytes);
            }
        }

        Self::construct_tx_with_tx_key(
            sender_account_keys,
            subaddresses,
            sources,
            destinations,
            change_address,
            extra,
            unlock_time,
            tx_key,
            additional_tx_keys,
            rct,
            rct_config,
            multisig_out
        )
    }

    /// Returns a Monero transaction given a transaction key and arguments
    pub fn construct_tx_with_tx_key(
        sender_account_keys: MoneroPrivateKey<N>,
        subaddresses: HashMap<[u8; 32], (u8, u8)>,
        sources: Vec<TxSourceEntry>,
        destinations: &Vec<TxDestinationEntry<N>>,
        change_address: &MoneroAddress<N>,
        extra: Vec<u8>,
        unlock_time: u64,
        tx_key: [u8; 32],
        additional_tx_keys: &mut Vec<[u8; 32]>,
        rct: bool,
        rct_config: u8,
        multisig_out: bool,
    ) -> Result<Self, TransactionError> {
        // line 205 - 209 - if no tx sources, output error
        if sources.is_empty() {
            return Err(TransactionError::MoneroTransactionError); //TODO: return proper errors
        }

        // line 219 - if rct is true, set tx.version to 2, else 1
        let version = match rct {
            true => 2,
            false => 1,
        };

        // line 222 - set tx.extra

        // line 225 - 266 if we have a stealth payment id, find it and encrypt it with the tx key now
        let mut add_dummy_payment_id = false;
        if extra.len() != 0 {
            add_dummy_payment_id = true;
            // weird nonce stuff, will come back to

            // line 268 - 270 if we don't add one if we've got more than the usual 1 destination plus change
            if destinations.len() > 2 {
                add_dummy_payment_id = false;
            }

            // line 272 - 292 add a dummy short payment id
            if add_dummy_payment_id {

            }
        }


        // line 308 - set up data structures to parse tx inputs, store tx images, track summary of money in, generate tx outputs
        let mut in_contexts: Vec<([u8; 32], [u8; 32])> = Vec::new();
        let mut summary_inputs_money = 0u64;

        sources.iter().for_each(|source_entry| {
            if source_entry.real_output >= source_entry.outputs.len() as u64 {
                println!("real output index out of range");
            }

            summary_inputs_money += source_entry.amount;

            // line 320 - 329 - generate key image key_derivation recv_derivation
            let key_image = Self::generate_keys_and_key_image(&sender_account_keys, &source_entry.real_out_tx_key, source_entry.real_output_in_tx_index);

            // line 331 - 340 - check that derived key is equal with real output key (if non-multisig)

            // line 342 - 345 - put key image into tx input

            // line 347 - 349 - fill outputs array and use relative offsets
        });


        // line 355 - 358 - shuffle outputs

        // line 360 - 373 - sort ins by their key image

        // line 375 - 379 - figure out if we need to make additional tx pubkeys

        // line 381 - 391 - if this is a single-destination transfer to a subaddress, set tx pubkey to R=s*D

        // line 395 - 400 - we don’t need to include additional tx keys if
        //    - all destinations are standard addresses
        //    - there’s only one destination which is a subaddress

        // line 402 - 424 - set up data structures to parse tx outputs, and track summary of money out

        // line 426 remove additional pub key field from tx extra

        // line 428 - 435 - add additional public keys

        // line 440 - 445 - check summary of money out is not greater than money in

        // line 447 - 454 - check for watch only wallet

        // line 456 - 491 - rct_full_tx_type = 1

        // line 491 - 552 - rct_simple_tx_type = 2

        // line 554 - 576 - mixRing indexing

        // line 579 - 580 - calculate fee (amounts in - amounts out) - verified that this was positive above

        // line 582 - 589 - zero out all amounts to mask rct outputs, real amounts are now encrypted

        // line 591 - 598 - generate transaction Rct signatures

        // line 600 - 602 - check and assert tx size, then create transaction

        return Err(TransactionError::MoneroTransactionError);
    }
}
