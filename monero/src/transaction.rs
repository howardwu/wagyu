use crate::address::{MoneroAddress, Format};
use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;
use crate::one_time_key::OneTimeKey;
use wagyu_model::{PrivateKey, TransactionError, Transaction};

use rand::{thread_rng, Rng};
use std::collections::HashMap;
use serde_json::value::Value::Null;
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
pub struct KeyInput<N: MoneroNetwork> {
    key_offsets: Vec<u64>,
    key_image: [u8; 32],
}

/// Represents a Monero transaction input
pub struct MoneroTransactionInput<N: MoneroNetwork> {
    /// block height of where the coinbase transaction is included
    height: usize,
    /// a one time key input
    to_key: KeyInput<N>,
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
    key: OneTimeKey<N>
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
    inputs: Vec<MoneroTransactionInput<N>>,
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

impl <N: MoneroNetwork> Transaction for MoneroTransaction<N> {
    type Address = MoneroAddress<N>;
    type Format = Format;
    type PrivateKey = MoneroPrivateKey<N>;
    type PublicKey = MoneroPublicKey<N>;
}

/// Represents a source entry used to construct a Monero transaction
pub struct TxSourceEntry {
    /// index + key + optional ringct commitment
    outputs: Vec<(u64, CtKey)>,
    /// index in outputs vector of real output_entry
    real_output: usize,
    /// incoming real tx public key
    real_out_tx_key: [u8; 32],
    /// incoming real tx additiona public keys
    real_out_additional_keys: Vec<[u8; 32]>,
    /// index in transaction outputs vector
    real_output_in_tx_index: usize,
    /// money
    amount: u64,
    /// true if output is rct
    rct: bool,
    /// ringct amount mask
    mask: RctMask,
    /// multisig info
    multisig_kLRki: MultisigKLRki,
}

/// Represents a destination entry use to construct a Monero transaction
pub struct TxDestinationEntry<N> {
    /// I have no idea
    original: String,
    /// money
    amount: u64,
    /// destination address
    address: MoneroAddress<N>,
    is_subaddress: bool,
    is_integrated: bool
}


impl <N: MoneroNetwork> MoneroTransaction<N> {
    /// Returns the number of standard addresses and subaddresses respectively
    fn classify_addresses(
        destinations: Vec<TxDestinationEntry<N>>,
        change_address: MoneroAddress<N>,
    ) -> (u8, u8) {
        let mut num_stdaddresses: u8 = 0;
        let mut num_subaddresses: u8 = 0;
        let mut single_dest_subaddress: MoneroAddress<N>;
        let mut unique_dst_addresses : Vec<MoneroAddress<N>> = Vec::new();
        for dst_entr in destinations.iter() {
            if change_address == dst_entr.address {
                continue;
            }
            let num_of_occurrences = unique_dst_addresses.iter().filter(|&address| *address == dst_entr.address);
            if num_of_occurrences.count() == 0 {
                unique_dst_addresses.push(dst_entr.address);
                match Format::from_address(dst_entr.address) {
                    Format::Subaddress() => {
                        num_subaddresses += 1;
//                        single_dest_subaddress = dst_entr.address;
                    },
                    _ => num_stdaddresses += 1
                }
            }
        }
        println!("destinations include {:?} standard addresses and {:?} subaddresses", num_stdaddresses, num_subaddresses);

//        single_dest_subaddress
        (num_stdaddresses, num_subaddresses)
    }

    /// Returns keccak256 hash of serialized transaction prefix
    fn get_transaction_prefix_hash(transaction: &MoneroTransaction<N>) -> [u8; 32] {
        let mut prefix: Vec<u8> = Vec::new();
        Self::serialize_transaction(transaction, &mut prefix, true);

        keccak256(prefix.as_slice())
    }

    /// Returns keccak256 hash of transaction
    fn get_transaction_hash(transaction: &MoneroTransaction<N>) -> [u8; 32] {
        let mut tx: Vec<u8> = Vec::new();
        Self::serialize_transaction(transaction, &mut tx, false);

        keccak256(tx.as_slice())
    }

    /// Returns a serialized transaction or transaction prefix
    fn serialize_transaction(transaction: &MoneroTransaction<N>, serialized: &mut Vec<u8>, header_only: bool) {
        let transaction_prefix = &transaction.prefix;

        //TODO: if possible, initialize vector of exact length based off header
        serialized.extend(OneTimeKey::encode_varint(transaction_prefix.version));
        serialized.extend(OneTimeKey::encode_varint(transaction_prefix.unlock_time));
        serialized.extend(OneTimeKey::encode_varint(transaction_prefix.inputs.len() as u64));

        transaction_prefix.inputs.iter().for_each(|&input| {
            let offsets = input.to_key.key_offsets;

            serialized.extend(OneTimeKey::encode_varint("02" as u64));
            serialized.extend(&offsets.len() as u64);

            offsets.iter().for_each(|&key_offset| {
                serialized.extend(key_offset);
            });
        });

        serialized.extend(transaction_prefix.outputs.len() as u64);

        transaction_prefix.outputs.iter().for_each(|&output| {
            serialized.extend(&output.amount);
            serialized.extend("02" as u64);
            serialized.extend_from_slice(&output.to_key.key.to_transaction_prefix_public_key());
        });

        serialized.extend((transaction_prefix.extra.len() / 2) as u64);
        serialized.extend(&transaction_prefix.extra);

//        uncomment after implementing signatures
//        if !header_only {
//            if transaction_prefix.inputs.len() != transaction.signatures.len() {
//                return Err(TransactionError::MoneroTransactionError);
//            }
//            transaction.signatures.iter.for_each(|&signature_row| {
//                signature_row.iter().for_each(|&signature_row_column| {
//                    serialized.extend(&signature_row_column);
//                });
//            });
//        }
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

        construct_tx_and_get_tx_key(
            sender_account_keys,
            subaddresses,
            sources,
            &destinations_copy,
            &change_address,
            extra,
            unlock_time,
            tx_key,
            &additional_tx_keys,
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
        let (num_stdaddresses, num_subaddresses) = classify_addresses(destinations, change_address);
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

        construct_tx_with_tx_key(
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
        if sources.is_empty() {
            return TransactionError::MoneroTransactionError; //TODO: return proper errors
        }

    }
}
