use crate::address::{MoneroAddress, Format};
use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;
use crate::one_time_key::OneTimeKey;
use wagyu_model::{PublicKeyError, PrivateKey, TransactionError, Transaction};

use base58_monero as base58;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::{json, Result as SerdeResult};
use std::collections::HashMap;
use tiny_keccak::keccak256;

//#[link(name="serial_bridge_index.cpp", kind="static")]
//    extern "C" {
//    fn decode_address(args_string: &String);
//
//    fn send_step1__prepare_params_for_get_decoys(args_string: &String);
//
//    fn send_step2__try_create_transaction(args_string: &String);
//}

/// Represents a Monero transaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl <N: MoneroNetwork> Transaction for MoneroTransaction<N> {
    type Address = MoneroAddress<N>;
    type Format = Format;
    type PrivateKey = MoneroPrivateKey<N>;
    type PublicKey = MoneroPublicKey<N>;
}

/// Represents a Monero transaction input
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MoneroTransactionInput {
    amount: u64,
    offsets: Vec<u64>,
    image: [u8; 32],
}

/// Represents a Monero transaction output
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MoneroTransactionOutput<N: MoneroNetwork> {
    amount: u64,
    key: OneTimeKey<N>,
}

/// Represents a Monero transaction prefix
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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


/// Represents a source entry used to construct a Monero transaction
pub struct TxSourceEntry {
    /// index + key + optional ringct commitment
    outputs: Vec<(u64, [u8; 32])>,
    /// index in outputs vector of real output_entry
    real_output: u64,
    /// incoming real tx public key
    real_out_tx_key: [u8; 32],
    /// incoming real tx additional public keys
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

/// Represents a secret and public keypair for a transaction
#[derive(Clone, Copy)]
pub struct TransactionKeypair {
    secret_key: [u8; 32],
    public_key: [u8; 32],
}

impl TransactionKeypair {

    /// Returns a new random keypair
    pub fn new() -> Self {
        let mut secret_key = [0u8; 32];
        thread_rng().fill(&mut secret_key[..]);

        Self::from_secret_key(&secret_key)
    }

    /// Returns a keypair from a secret key
    pub fn from_secret_key(secret_key: &[u8; 32]) -> Self {
        let secret_key_scalar = Scalar::from_bits(*secret_key);

        let public_key = (&secret_key_scalar * &ED25519_BASEPOINT_TABLE).compress().to_bytes();

        TransactionKeypair{ secret_key: *secret_key, public_key }
    }

//    /// Returns a public key given a secret key
//    fn from_secret_to_public(secret_key: &[u8; 32]) -> [u8; 32] {
//        let secret_key_scalar = Scalar::from_bits(*secret_key);
//
//        (&secret_key_scalar * &ED25519_BASEPOINT_TABLE).compress().to_bytes()
//    }

    pub fn to_secret_key(self) -> [u8; 32] {
        self.secret_key
    }

    pub fn to_public_key(self) -> [u8; 32] {
        self.public_key
    }
}

impl<N: MoneroNetwork> MoneroTransaction<N> {
    /// Returns the number of standard addresses and subaddresses respectively
    fn classify_addresses(
        destinations: &Vec<TxDestinationEntry<N>>,
        change_address: &MoneroAddress<N>,
    ) -> Result<(u8, u8), TransactionError> {
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
                match Format::from_address(&base58::decode(&dst_entr.address.to_string())?)? {
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
        Ok((num_stdaddresses, num_subaddresses))
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
    pub fn generate_key_derivation(public: &[u8; 32], secret_key: &[u8; 32], dest: &mut Vec<u8>) -> Result<(), TransactionError>{
        // r * A
        let r = Scalar::from_bits(*secret_key);
        let A = &match CompressedEdwardsY::from_slice(public).decompress() {
            Some(point) => point,
            None => return Err(TransactionError::EdwardsPointError(*public)),
        };

        let mut rA: EdwardsPoint = r * A;
        rA = rA.mul_by_cofactor(); //https://github.com/monero-project/monero/blob/50d48d611867ffcd41037e2ab4fec2526c08a7f5/src/crypto/crypto.cpp#L182

        dest.clear();
        dest.extend(rA.compress().to_bytes().to_vec());

        Ok(())
    }

    /// Returns keccak256 hash of key derivation extended by output index as a scalar
    pub fn derivation_to_scalar(derivation: &Vec<u8>, output_index: u64) -> Scalar {
        // H_s(derivation || output_index)
        let mut derivation = derivation.clone();
        derivation.extend(&MoneroTransaction::<N>::encode_varint(output_index));

        Scalar::from_bytes_mod_order(keccak256(&derivation))
    }

    /// Returns a public key from key derivation, output index, and public spend key
    fn derive_public_key(derivation: &Vec<u8>, output_index: u64, public_spend_key: &[u8; 32]) -> Result<[u8; 32], TransactionError> {
        let mut derivation = derivation.clone();
        let public_point = &match CompressedEdwardsY::from_slice(public_spend_key).decompress() {
            Some(point) => point,
            None => return Err(TransactionError::EdwardsPointError(*public_spend_key)),
        };
        let derivation_at_index = &Self::derivation_to_scalar(&derivation, output_index) * &ED25519_BASEPOINT_TABLE;

        Ok((public_point + derivation_at_index).compress().to_bytes())
    }

    /// Returns a secret key from key derivation, output index, and private spend key
    fn derive_secret_key(derivation: &Vec<u8>, output_index: u64, private_spend_key: &[u8; 32]) -> [u8; 32] {
        let mut derivation = derivation.clone();
        let secret = Scalar::from_bits(*private_spend_key);
        let derivation_at_index = Self::derivation_to_scalar(&derivation, output_index);

        (derivation_at_index + secret).to_bytes()
    }

    /// Returns keccack256 hash of key multiplied by cofactor as uncompressed Edwards point
    fn hash_to_ec(key: &[u8; 32]) -> Result<EdwardsPoint, TransactionError> {
        let hashed_key = keccak256(key);
        let hashed_key_point = &match CompressedEdwardsY::from_slice(&hashed_key).decompress() {
            Some(point) => point,
            None => return Err(TransactionError::EdwardsPointError(hashed_key)),
        };

        Ok(hashed_key_point.mul_by_cofactor())
    }

    /// Returns a public key image given ephemeral public and secret key
    fn generate_key_image(public_key: &[u8; 32], secret_key: &[u8; 32]) -> Result<[u8; 32], TransactionError> {
        let secret_key_scalar = Scalar::from_bits(*secret_key);
        let image = Self::hash_to_ec(public_key)? * secret_key_scalar;

        Ok(image.compress().to_bytes())
    }

    /// Returns help to generate the key image for the given source entry index
    fn generate_keys_and_key_image(
        sender_account_keys: &MoneroPrivateKey<N>,
        transaction_public_key: &[u8; 32],
        transaction_output_index: u64
    ) -> Result<KeyImage, TransactionError> {
        let public_spend_key: [u8; 32] = match sender_account_keys.to_public_key().to_public_spend_key() {
            Some(key) => key,
            None => return Err(TransactionError::PublicKeyError(PublicKeyError::NoSpendingKey)),
        };
        let private_spend_key = sender_account_keys.to_private_spend_key();
        let private_view_key = sender_account_keys.to_private_view_key();
        let mut recv_derivation = Vec::<u8>::new();

        if Self::generate_key_derivation(transaction_public_key, &private_view_key, &mut recv_derivation
        ).is_err() {
            return Err(TransactionError::KeyImageError)
        }

        let ephemeral_public_key = Self::derive_public_key(&recv_derivation, transaction_output_index, &public_spend_key)?;
        let ephemeral_secret_key = Self::derive_secret_key(&recv_derivation, transaction_output_index, &private_spend_key);

        let image = Self::generate_key_image(&ephemeral_public_key, &ephemeral_secret_key)?;

        Ok(KeyImage {ephemeral_secret_key, ephemeral_public_key, image})
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
        let public_spend_key: [u8; 32] = match sender_account_keys.to_public_key().to_public_spend_key() {
            Some(key) => key,
            None => return Err(TransactionError::PublicKeyError(PublicKeyError::NoSpendingKey)),
        };
        subaddresses.insert(public_spend_key, (0, 0));

        let tx_key = TransactionKeypair::new();

        let mut additional_tx_keys = Vec::<(TransactionKeypair)>::new();

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
        tx_key: TransactionKeypair,
        additional_tx_keys: &mut Vec<TransactionKeypair>,
        rct: bool,
        rct_config: u8,
        multisig_out: bool,
    ) -> Result<Self, TransactionError> {
        // figure out if we need to make additional tx pubkeys
        let (num_stdaddresses, num_subaddresses) = Self::classify_addresses(destinations, change_address)?;
        let need_additional_tx_keys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);

        if need_additional_tx_keys {
            additional_tx_keys.clear();
            for dest in destinations.iter() {
                let random_tx_key = TransactionKeypair::new();
                additional_tx_keys.push(random_tx_key);
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
        tx_key: TransactionKeypair,
        additional_tx_keys: &mut Vec<TransactionKeypair>,
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
        let mut transaction_extra = Vec::<u8>::new();
        transaction_extra.extend_from_slice(&tx_key.to_public_key());

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
        let mut transaction_inputs = Vec::<MoneroTransactionInput>::new();

        for (_, source_entry) in sources.iter().enumerate() { //we use enumerate instead of for_each because for_each must return () so we would not be able to use ? on Result<>
            if source_entry.real_output >= source_entry.outputs.len() as u64 {
                println!("real output index out of range");
                return Err(TransactionError::MoneroTransactionError); //TODO: return proper errors
            }

            summary_inputs_money += source_entry.amount;

            // line 320 - 329 - generate key image key_derivation recv_derivation
            let key_image = Self::generate_keys_and_key_image(
                &sender_account_keys,
                &source_entry.real_out_tx_key,
                source_entry.real_output_in_tx_index
            )?;
            in_contexts.push((key_image.ephemeral_secret_key, key_image.ephemeral_public_key));

            // line 331 - 340 - check that derived key is equal with real output key (if non-multisig)
            if key_image.ephemeral_public_key != source_entry.outputs[source_entry.real_output as usize].1 {
                println!("ephemeral public key is not equal to real output key");
                return Err(TransactionError::MoneroTransactionError); //TODO: return proper errors
            }


            // line 342 - 345 - put key image into tx input
            let mut offsets = Vec::<u64>::new();

            // line 347 - 349 - fill outputs array and use relative offsets
            source_entry.outputs.iter().for_each(|output| {
                offsets.push(output.0)
            });

            let input = MoneroTransactionInput{
                amount: source_entry.amount,
                offsets,
                image: key_image.image
            };

            transaction_inputs.push(input);
        }


        // line 355 - 358 - shuffle outputs

        // line 360 - 373 - sort ins by their key image

        // line 375 - 379 - figure out if we need to make additional tx pubkeys

        // line 381 - 391 - if this is a single-destination transfer to a subaddress, set tx pubkey to R=s*D

        // line 395 - 400 - we don’t need to include additional tx keys if
        //    - all destinations are standard addresses
        //    - there’s only one destination which is a subaddress

        // line 402 - 424 - set up data structures to parse tx outputs, and track summary of money out
        let mut transaction_outputs = Vec::<MoneroTransactionOutput<N>>::new();
        let mut summary_outputs_money = 0u64;
//        let tx_secret_key = tx_key.to_secret_key();
        for (i, destination) in destinations.iter().enumerate() {
            if destination.amount != 0u64 {
                println!("destinations must be equal to zero");
                return Err(TransactionError::MoneroTransactionError); //TODO: return proper errors
            }

            let public_keys = destination.address.to_public_key()?;
            let out_ephemeral = OneTimeKey::new(&public_keys, &tx_key.to_secret_key(), i as u64)?;

            let output = MoneroTransactionOutput {
                amount: destination.amount,
                key: out_ephemeral
            };

            transaction_outputs.push(output);
            summary_outputs_money += destination.amount;
        }


        // line 426 remove additional pub key field from tx extra

        // line 428 - 435 - add additional public keys

        // line 440 - 445 - check summary of money out is not greater than money in
        if summary_outputs_money > summary_inputs_money {
            println!("{:?} less than outputs money {:?}", summary_inputs_money, summary_outputs_money);
        }

        // line 447 - 454 - check for watch only wallet

        // line 456 - 491 - rct_full_tx_type = 1
        // line 460 generate transaction prefix hash
        // line 464 for every transaction source (row)
        // line 468 create vector of public keys
        // line 470 for every transaction source output (column)
        // line 472 add public key to vector
        // line 478 create ring signature on vector and add to transaction signatures

        // line 491 - 552 - rct_simple_tx_type = 2
        //

        // line 554 - 576 - mixRing indexing

        // line 579 - 580 - calculate fee (amounts in - amounts out) - verified that this was positive above

        // line 582 - 589 - zero out all amounts to mask rct outputs, real amounts are now encrypted

        // line 591 - 598 - generate transaction Rct signatures

        // line 600 - 602 - check and assert tx size, then create transaction

        return Err(TransactionError::MoneroTransactionError);
    }

    // Call into mymonero-core-cpp library json interface functions to send transaction
    // https://github.com/mymonero/mymonero-core-cpp/blob/master/src/serial_bridge_index.cpp

    pub fn call_step1(
        sending_amount: u64,
        is_sweeping: bool,
        priority: u32,
        fee_per_b: u64,
        fee_mask: u64,
        fork_version: u8,
        unspent_outs: Vec<UnspentOutput>,
        payment_id_string: Option<String>,
        passedIn_attemptAt_fee: Option<String>
    ) -> Result<Step1Result, TransactionError> {

        // Do preprocessing checks here

        let args_string = json!({
            "sending_amount": sending_amount.to_string(),
            "is_sweeping": is_sweeping.to_string(),
            "priority": priority.to_string(),
            "fee_per_b": fee_per_b.to_string(),
            "fee_mask": fee_mask.to_string(),
            "fork_version": fork_version.to_string(),
            "unspent_outs": unspent_outs,
//            "payment_id_string": payment_id_string_unwrapped
//            "passedIn_attemptAt_fee": passedIn_attemptAt_fee_unwrapped
        });
        println!("{}", args_string.to_string());

//        unsafe {
//            send_step1__prepare_params_for_get_decoys(args_string);
//        }

        // Do postprocessing and return Step1Result
        Err(TransactionError::MoneroTransactionError)
    }
//
//    pub fn call_step2(
//        from_address_string: String,
//        sec_viewKey_string: String,
//        to_address_string: String,
//        final_total_wo_fee: u64,
//        change_amount: u64,
//        fee_amount: u64,
//        priority: u32,
//        fee_per_b: u64,
//        fee_mask: u64,
//        fork_version: u8,
//        using_outs: Vec<UnspentOutput>,
//        mix_outs: Vec<MixAmountAndOuts>,
//        unlock_time: u64,
//        nettype_string: String,
//        payment_id_string: Option<String>
//    ) -> bool {
//
//    }
}

pub struct Step1Result {
    mixin: u32,
    using_fee: u64,
    change_amount: u64,
    using_outs: Vec<UnspentOutput>,
    final_total_wo_fee: u64,
}

// Structs mirrored from https://github.com/mymonero/mymonero-core-cpp
#[derive(Serialize, Deserialize)]
pub struct UnspentOutput {
    amount: u64,
    public_key: String,
    rct: Option<String>,
    global_index: u64,
    index: u64,
    tx_pub_key: String
}

#[derive(Serialize, Deserialize)]
pub struct MixAmountAndOuts {
    amount: u64,
    outputs: Vec<MixOut>,
}

#[derive(Serialize, Deserialize)]
pub struct MixOut {
    global_index: u64,
    public_key: [u8; 32],
    rct: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::{
        Mainnet,
    };
    use super::*;

    type N = Mainnet;


    #[link(name="serial_bridge_index.cpp", kind="static")]
    extern "C" {
        fn decode_address(args_string: &String);
//
//        fn send_step1__prepare_params_for_get_decoys(args_string: &String);
//
//        fn send_step2__try_create_transaction(args_string: &String);
    }

    #[test]
    fn test_create_transaction() {
            let address = "43tXwm6UNNvSyMdHU4Jfeg4GRgU7KEVAfHo3B5RrXYMjZMRaowr68y12HSo14wv2qcYqqpG1U5AHrJtBdFHKPDEA9UxK6Hy";
            unsafe {
                decode_address(&String::from(address));
//                send_step1__prepare_params_for_get_decoys()
            }
    }

    // https://github.com/mymonero/mymonero-core-cpp/blob/20b6cbabf230ae4ebe01d05c859aad397741cf8f/test/test_all.cpp#L347
    #[test]
    fn test_bridge_transfers_send_amount() {
        let unspent_outs_string = "[{\"amount\":3000000000,\"public_key\":\"41be1978f58cabf69a9bed5b6cb3c8d588621ef9b67602328da42a213ee42271\",\"index\":1,\"global_index\":7611174,\"rct\":\"86a2c9f1f8e66848cd99bfda7a14d4ac6c3525d06947e21e4e55fe42a368507eb5b234ccdd70beca8b1fc8de4f2ceb1374e0f1fd8810849e7f11316c2cc063060008ffa5ac9827b776993468df21af8c963d12148622354f950cbe1369a92a0c\",\"tx_id\":5334971,\"tx_hash\":\"9d37c7fdeab91abfd1e7e120f5c49eac17b7ac04a97a0c93b51c172115df21ea\",\"tx_pub_key\":\"bd703d7f37995cc7071fb4d2929594b5e2a4c27d2b7c68a9064500ca7bc638b8\"}]";
//        let mix_outs_string = "[{\"amount\":\"0\",\"outputs\":[{\"global_index\":\"7453099\",\"public_key\":\"31f3a7fec0f6f09067e826b6c2904fd4b1684d7893dcf08c5b5d22e317e148bb\",\"rct\":\"ea6bcb193a25ce2787dd6abaaeef1ee0c924b323c6a5873db1406261e86145fc\"},{\"global_index\":\"7500097\",\"public_key\":\"f9d923500671da05a1bf44b932b872f0c4a3c88e6b3d4bf774c8be915e25f42b\",\"rct\":\"dcae4267a6c382bcd71fd1af4d2cbceb3749d576d7a3acc473dd579ea9231a52\"},{\"global_index\":\"7548483\",\"public_key\":\"839cbbb73685654b93e824c4843e745e8d5f7742e83494932307bf300641c480\",\"rct\":\"aa99d492f1d6f1b20dcd95b8fff8f67a219043d0d94b4551759016b4888573e7\"},{\"global_index\":\"7554755\",\"public_key\":\"b8860f0697988c8cefd7b4285fbb8bec463f136c2b9a9cadb3e57cebee10717f\",\"rct\":\"327f9b07bee9c4c25b5a990123cd2444228e5704ebe32016cd632866710279b5\"},{\"global_index\":\"7561477\",\"public_key\":\"561d734cb90bc4a64d49d37f85ea85575243e2ed749a3d6dcb4d27aa6bec6e88\",\"rct\":\"b5393e038df95b94bfda62b44a29141cac9e356127270af97193460d51949841\"},{\"global_index\":\"7567062\",\"public_key\":\"db1024ef67e7e73608ef8afab62f49e2402c8da3dc3197008e3ba720ad3c94a8\",\"rct\":\"1fedf95621881b77f823a70aa83ece26aef62974976d2b8cd87ed4862a4ec92c\"},{\"global_index\":\"7567508\",\"public_key\":\"6283f3cd2f050bba90276443fe04f6076ad2ad46a515bf07b84d424a3ba43d27\",\"rct\":\"10e16bb8a8b7b0c8a4b193467b010976b962809c9f3e6c047335dba09daa351f\"},{\"global_index\":\"7568716\",\"public_key\":\"7a7deb4eef81c1f5ce9cbd0552891cb19f1014a03a5863d549630824c7c7c0d3\",\"rct\":\"735d059dc3526334ac705ddc44c4316bb8805d2426dcea9544cde50cf6c7a850\"},{\"global_index\":\"7571196\",\"public_key\":\"535208e354cae530ed7ce752935e555d630cf2edd7f91525024ed9c332b2a347\",\"rct\":\"c3cf838faa14e993536c5581ca582fb0d96b70f713cf88f7f15c89336e5853ec\"},{\"global_index\":\"7571333\",\"public_key\":\"e73f27b7eb001aa7eac13df82814cda65b42ceeb6ef36227c25d5cbf82f6a5e4\",\"rct\":\"5f45f33c6800cdae202b37abe6d87b53d6873e7b30f3527161f44fa8db3104b6\"},{\"global_index\":\"7571335\",\"public_key\":\"fce982dbz8e7a6b71a1e632c7de8c5cbf54e8bacdfbf250f1ffc2a8d2f7055ce3\",\"rct\":\"407bdcc48e70eb3ef2cc22cefee6c6b5a3c59fd17bde12fda5f1a44a0fb39d14\"}]}]";

        let unspent_outs: Vec<UnspentOutput> = serde_json::from_str(unspent_outs_string).unwrap();
        let sending_amount= 200000000u64;
        let is_sweeping= false;
        let priority= 1u32;
        let fee_per_b = 24658u64;
        let fee_mask = 10000u64;
        let fork_version = 10u8;
        let payment_id_string: Option<String> = Some("d2f602b240fbe624".into());
        let passedIn_attemptAt_fee: Option<String> = None;

        let step1_result = MoneroTransaction::<N>::call_step1(
            sending_amount,
            is_sweeping,
            priority,
            fee_per_b,
            fee_mask,
            fork_version,
            unspent_outs,
            payment_id_string,
            passedIn_attemptAt_fee,
        ).unwrap();
    }
}
