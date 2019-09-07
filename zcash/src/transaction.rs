use crate::address::{Format, ZcashAddress};
use crate::extended_private_key::ZcashExtendedPrivateKey;
use crate::network::ZcashNetwork;
use crate::private_key::{SaplingOutgoingViewingKey, ZcashPrivateKey};
use crate::public_key::ZcashPublicKey;

use base58::FromBase58;
use blake2b_simd::{Hash, Params};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use secp256k1;
use serde::Serialize;
use std::{fmt, marker::PhantomData, str::FromStr};
use wagyu_model::{ExtendedPrivateKey, PrivateKey, Transaction, TransactionError};

// librustzcash crates
use bellman::groth16::{Parameters, PreparedVerifyingKey, Proof};
use ff::{Field, PrimeField, PrimeFieldRepr};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use zcash_primitives::{
    jubjub::{edwards, fs::Fs},
    keys::{ExpandedSpendingKey, FullViewingKey, OutgoingViewingKey},
    merkle_tree::CommitmentTreeWitness,
    note_encryption::{try_sapling_note_decryption, Memo, SaplingNoteEncryption},
    primitives::{Diversifier, Note, PaymentAddress},
    redjubjub::{PrivateKey as jubjubPrivateKey, PublicKey as jubjubPublicKey, Signature as jubjubSignature},
    sapling::{spend_sig, Node},
    transaction::components::Amount,
    JUBJUB,
};
use zcash_proofs::sapling::{SaplingProvingContext, SaplingVerificationContext};

const GROTH_PROOF_SIZE: usize = 48 // π_A
    + 96 // π_B
    + 48; // π_C

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
#[derive(Clone)]
pub struct ZcashTransaction<N: ZcashNetwork> {
    /// Transactions header - overwintered flag and transaction version (04000080 for sapling)
    pub header: u32,
    /// Version group ID (0x892F2085 for sapling)
    pub version_group_id: u32,
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
    pub shielded_spends: Vec<SaplingSpend<N>>,
    /// Transaction shielded outputs
    pub shielded_outputs: Vec<SaplingOutput<N>>,
    /// Transaction join splits
    pub join_splits: Vec<JoinSplit>,
    /// Binding Signature
    pub binding_sig: Option<Vec<u8>>,
    /// Anchor
    pub anchor: Option<Fr>,
}

/// Represents a Zcash transaction input
#[derive(Debug, Clone)]
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
}

/// Represents a Zcash transaction output
#[derive(Debug, Clone)]
pub struct ZcashTransactionOutput<N: ZcashNetwork> {
    /// Transfer amount in Satoshi
    pub amount: u64,
    /// Output public key script
    pub output_public_key: Vec<u8>,
    /// PhantomData
    _network: PhantomData<N>,
}

/// Represents a specific UTXO
#[derive(Debug, Clone)]
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
#[derive(Clone)]
pub struct SaplingSpend<N: ZcashNetwork> {
    /// Sapling extended secret key
    pub extended_spend_key: ZcashExtendedPrivateKey<N>,
    /// Sapling address diversifier
    pub diversifier: [u8; 11],
    /// Sapling Spend note
    pub note: Note<Bls12>,
    /// Alpha randomness
    pub alpha: Fs,
    /// Anchor
    pub anchor: Fr,
    /// Commitment witness
    pub witness: CommitmentTreeWitness<Node>,
    /// SpendDescription
    pub spend_description: Option<SpendDescription>,
}

/// Represents a Zcash transaction Shielded Spend Description
#[derive(Debug, Clone)]
pub struct SpendDescription {
    /// Value commitment for the spend note
    pub cv: [u8; 32],
    /// Root of the sapling note commitment tree
    pub anchor: [u8; 32],
    /// Nullifier of the spend note
    pub nullifier: [u8; 32],
    /// Randomized public key for spend_auth_sig
    pub rk: [u8; 32],
    /// Zero knowledge proof used for the output circuit
    pub zk_proof: Vec<u8>,
    /// Signature authorizing the spend
    pub spend_auth_sig: Option<Vec<u8>>,
}

/// Represents a Zcash transaction Shielded Output
#[derive(Debug, Clone)]
pub struct SaplingOutput<N: ZcashNetwork> {
    /// Sapling address
    pub address: ZcashAddress<N>,
    /// outgoing view key
    pub ovk: SaplingOutgoingViewingKey,
    /// Sapling output address
    pub to: PaymentAddress<Bls12>,
    /// Sapling output note
    pub note: Note<Bls12>,
    /// Optional memo
    pub memo: Memo,
    /// OutputDescription
    pub output_description: Option<OutputDescription>,
}

/// Represents a Zcash transaction Shielded Output Description
#[derive(Debug, Clone)]
pub struct OutputDescription {
    /// Value commitment for the output note
    pub cv: [u8; 32],
    /// Commitment for the output note
    pub cmu: [u8; 32],
    /// Jubjub public Key
    pub ephemeral_key: [u8; 32],
    /// Ciphertext for the encrypted output note
    pub enc_ciphertext: Vec<u8>,
    /// Ciphertext for the encrypted output note
    pub out_ciphertext: Vec<u8>,
    /// Zero knowledge proof used for the output circuit
    pub zk_proof: Vec<u8>,
}

/// Represents a Zcash transaction Join Split
#[derive(Debug, Clone)]
pub struct JoinSplit {}

impl<N: ZcashNetwork> Transaction for ZcashTransaction<N> {
    type Address = ZcashAddress<N>;
    type Format = Format;
    type PrivateKey = ZcashPrivateKey<N>;
    type PublicKey = ZcashPublicKey<N>;
}

impl<N: ZcashNetwork> ZcashTransaction<N> {
    /// Returns a raw unsigned zcash transaction
    pub fn build_raw_transaction(
        header: u32,
        version_group_id: u32,
        lock_time: u32,
        expiry_height: u32,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            header,
            version_group_id,
            inputs: vec![],
            outputs: vec![],
            lock_time,
            expiry_height,
            value_balance: 0,
            shielded_spends: vec![],
            shielded_outputs: vec![],
            join_splits: vec![],
            binding_sig: None,
            anchor: None,
        })
    }

    /// Add a transparent input to the transaction
    pub fn add_transparent_input(
        &mut self,
        address: ZcashAddress<N>,
        transaction_id: Vec<u8>,
        index: u32,
        amount: Option<u64>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
        sequence: Option<Vec<u8>>,
        sig_hash_code: SigHashCode,
    ) -> Result<(), TransactionError> {
        let input = ZcashTransactionInput::<N>::new(
            address,
            transaction_id,
            index,
            amount,
            redeem_script,
            script_pub_key,
            sequence,
            sig_hash_code,
        )?;

        self.inputs.push(input);
        Ok(())
    }

    /// Add a transparent output to the transaction
    pub fn add_transparent_output(&mut self, address: &str, amount: u64) -> Result<(), TransactionError> {
        let output = ZcashTransactionOutput::<N>::new(address, amount)?;
        self.outputs.push(output);

        Ok(())
    }

    /// Add a sapling shielded spend to the transaction
    pub fn add_sapling_spend(
        &mut self,
        extended_secret_key: &str,
        cmu: &[u8; 32],
        epk: &[u8; 32],
        enc_ciphertext: &str,
        input_anchor: Fr,
        witness: CommitmentTreeWitness<Node>,
    ) -> Result<(), TransactionError> {
        // Verify all anchors are the same
        match &self.anchor {
            None => self.anchor = Some(input_anchor),
            Some(anchor) => {
                if anchor != &input_anchor {
                    return Err(TransactionError::ConflictingWitnessAnchors());
                }
            }
        };

        let sapling_spend =
            SaplingSpend::<N>::new(extended_secret_key, cmu, epk, enc_ciphertext, input_anchor, witness)?;

        self.value_balance += sapling_spend.note.value as i64;
        self.shielded_spends.push(sapling_spend);
        Ok(())
    }

    /// Add a sapling shielded output to the transaction
    pub fn add_sapling_output(
        &mut self,
        ovk: SaplingOutgoingViewingKey,
        address: &str,
        amount: u64,
    ) -> Result<(()), TransactionError> {
        let shielded_output = SaplingOutput::<N>::new(ovk, address, amount)?;
        self.value_balance -= shielded_output.note.value as i64;
        self.shielded_outputs.push(shielded_output);
        Ok(())
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

        for output in &self.outputs {
            serialized_transaction.extend(output.serialize()?);
        }

        serialized_transaction.extend(&self.lock_time.to_le_bytes());
        serialized_transaction.extend(&self.expiry_height.to_le_bytes());
        serialized_transaction.extend(&self.value_balance.to_le_bytes());

        match &self.shielded_spends.len() {
            0 => serialized_transaction.push(0u8),
            _ => {
                serialized_transaction.extend(variable_length_integer(self.shielded_spends.len() as u64)?);

                for spend in &self.shielded_spends {
                    match &spend.spend_description {
                        Some(description) => serialized_transaction.extend(description.serialize(false)?),
                        None => {}
                    }
                }
            }
        };

        match &self.shielded_outputs.len() {
            0 => serialized_transaction.push(0u8),
            _ => {
                serialized_transaction.extend(variable_length_integer(self.shielded_outputs.len() as u64)?);

                for output in &self.shielded_outputs {
                    match &output.output_description {
                        Some(description) => serialized_transaction.extend(description.serialize()?),
                        None => {}
                    }
                }
            }
        };

        match &self.join_splits.len() {
            0 => serialized_transaction.push(0u8),
            _ => unimplemented!(),
        };

        if let Some(binding_sig) = &self.binding_sig {
            serialized_transaction.extend(binding_sig);
        };

        Ok(serialized_transaction)
    }

    /// Signs the raw transaction, updates the transaction, and returns the signature - P2SH unimplemented
    pub fn sign_raw_transaction(
        &mut self,
        private_key: <Self as Transaction>::PrivateKey,
        input_index: usize,
    ) -> Result<Vec<u8>, TransactionError> {
        let input = &self.inputs[input_index];
        let transaction_hash = match input.out_point.address.format() {
            Format::P2PKH => self.generate_sighash(Some(input_index), input.sig_hash_code)?,
            _ => unimplemented!(),
        };

        let message = secp256k1::Message::from_slice(&transaction_hash.as_bytes())?;
        let spending_key = &private_key;
        let mut signature = match spending_key {
            ZcashPrivateKey::<N>::P2PKH(p2pkh_spending_key) => secp256k1::Secp256k1::signing_only()
                .sign(&message, &p2pkh_spending_key.to_secp256k1_secret_key())
                .serialize_der()
                .to_vec(),
            _ => unimplemented!(),
        };

        signature.push((input.sig_hash_code as u32).to_le_bytes()[0]);
        let signature = [variable_length_integer(signature.len() as u64)?, signature].concat();

        let viewing_key = private_key.to_public_key();
        let viewing_key_bytes = match viewing_key {
            ZcashPublicKey::<N>::P2PKH(p2pkh_view_key) => match p2pkh_view_key.is_compressed() {
                true => p2pkh_view_key.to_secp256k1_public_key().serialize().to_vec(),
                false => p2pkh_view_key
                    .to_secp256k1_public_key()
                    .serialize_uncompressed()
                    .to_vec(),
            },
            _ => unimplemented!(),
        };

        let public_key: Vec<u8> = [vec![viewing_key_bytes.len() as u8], viewing_key_bytes].concat();

        match input.out_point.address.format() {
            Format::P2PKH => self.inputs[input_index].script = [signature.clone(), public_key].concat(),
            _ => unimplemented!(),
        };

        Ok(signature)
    }

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
        match &self.shielded_spends.len() {
            0 => {},
            _ => {
                for spend in &mut self.shielded_spends {
                    spend.create_sapling_spend_description(proving_ctx, spend_params, spend_vk)?;
                }
            }
        };

        match &self.shielded_outputs.len() {
            0 => {},
            _ => {
                for output in &mut self.shielded_outputs {
                    output.create_sapling_output_description(proving_ctx, verifying_ctx, output_params, output_vk)?;
                }
            }
        };

        let mut sighash = [0u8; 32];
        sighash.copy_from_slice(self.generate_sighash(None, SigHashCode::SIGHASH_ALL)?.as_bytes());

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
        for spend in &mut self.shielded_spends {
            match &mut spend.spend_description {
                Some(spend_description) => {
                    let spending_key = spend.extended_spend_key.to_extended_spending_key().expsk.to_bytes();
                    let ask = ExpandedSpendingKey::<Bls12>::read(&spending_key[..])?.ask;

                    let sig = spend_sig(
                        jubjubPrivateKey(ask),
                        spend.alpha,
                        &sighash,
                        &mut StdRng::from_entropy(),
                        &JUBJUB,
                    );

                    let mut spend_auth_sig = [0u8; 64];
                    sig.write(&mut spend_auth_sig[..]).unwrap();

                    let check_sig = jubjubSignature::read(&spend_auth_sig[..])?;

                    spend_description.spend_auth_sig = Some(spend_auth_sig.to_vec());

                    let public_key = jubjubPublicKey::<Bls12>::read(&spend_description.rk[..], &JUBJUB)?;

                    let mut f = FrRepr::default();
                    f.read_le(&spend_description.anchor[..]).unwrap();
                    let anchor_fr = Fr::from_repr(f).unwrap();

                    let value_commitment = edwards::Point::<Bls12, _>::read(&spend_description.cv[..], &JUBJUB)?;
                    let proof = Proof::<Bls12>::read(&spend_description.zk_proof[..])?;

                    // Verify the spend description
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
                        false => return Err(TransactionError::InvalidSpendDescription()),
                    };
                }
                None => return Err(TransactionError::MissingSpendDescription()),
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
        let sig = proving_ctx.binding_sig(Amount::from_i64(self.value_balance)?, &sighash, &JUBJUB)?;
        sig.write(&mut binding_sig[..])?;
        self.binding_sig = Some(binding_sig.to_vec());

        match verifying_ctx.final_check(Amount::from_i64(self.value_balance)?, &sighash, sig, &JUBJUB) {
            true => Ok(()),
            false => Err(TransactionError::InvalidBindingSig()),
        }
    }

    /// Generate the sighash
    /// https://github.com/zcash/zips/blob/master/zip-0243.rs
    pub fn generate_sighash(
        &self,
        input_index: Option<usize>,
        sig_hash_code: SigHashCode,
    ) -> Result<Hash, TransactionError> {
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

        let hash_shielded_spends = match &self.shielded_spends.len() {
            0 => [0u8; 32].to_vec(),
            _ => {
                let mut spend_descriptions: Vec<u8> = Vec::new();
                for spend in &self.shielded_spends {
                    match &spend.spend_description {
                        Some(description) => spend_descriptions.extend(description.serialize(true)?),
                        None => {}
                    }
                }

                blake2_256_hash("ZcashSSpendsHash", spend_descriptions, None)
                    .as_bytes()
                    .to_vec()
            }
        };

        let hash_shielded_outputs = match &self.shielded_outputs.len() {
            0 => [0u8; 32].to_vec(),
            _ => {
                let mut output_descriptions: Vec<u8> = Vec::new();
                for output in &self.shielded_outputs {
                    match &output.output_description {
                        Some(description) => output_descriptions.extend(description.serialize()?),
                        None => {}
                    }
                }

                blake2_256_hash("ZcashSOutputHash", output_descriptions, None)
                    .as_bytes()
                    .to_vec()
            }
        };

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

        if let Some(index) = input_index {
            transaction_hash_preimage.extend(&self.inputs[index].serialize(false, true)?);
        };

        let transaction_hash = blake2_256_hash("ZcashSigHash", transaction_hash_preimage, Some("sapling"));

        Ok(transaction_hash)
    }
}

impl<N: ZcashNetwork> ZcashTransactionInput<N> {
    const DEFAULT_SEQUENCE: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

    /// Create a new Zcash Transaction input without the script
    pub fn new(
        address: ZcashAddress<N>,
        transaction_id: Vec<u8>,
        index: u32,
        amount: Option<u64>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
        sequence: Option<Vec<u8>>,
        sig_hash_code: SigHashCode,
    ) -> Result<Self, TransactionError> {
        if transaction_id.len() != 32 {
            return Err(TransactionError::InvalidTransactionId(transaction_id.len()));
        }

        // Reverse hash order - https://bitcoin.org/en/developer-reference#hash-byte-order
        let mut reverse_transaction_id = transaction_id;
        reverse_transaction_id.reverse();

        let script_pub_key = script_pub_key.unwrap_or(generate_script_pub_key::<N>(&address.to_string())?);
        let (amount, redeem_script) =
            validate_address_format(&address.format(), &amount, &redeem_script, &script_pub_key)?;

        let out_point = OutPoint {
            reverse_transaction_id,
            index,
            amount,
            redeem_script,
            script_pub_key,
            address,
        };
        let sequence = sequence.unwrap_or(ZcashTransactionInput::<N>::DEFAULT_SEQUENCE.to_vec());

        Ok(Self {
            out_point,
            script: Vec::new(),
            sequence,
            sig_hash_code,
        })
    }

    /// Serialize the transaction input
    pub fn serialize(&self, raw: bool, hash_preimage: bool) -> Result<Vec<u8>, TransactionError> {
        let mut serialized_input: Vec<u8> = Vec::new();
        serialized_input.extend(&self.out_point.reverse_transaction_id);
        serialized_input.extend(&self.out_point.index.to_le_bytes());

        match (raw, self.script.len()) {
            (true, _) => serialized_input.extend(vec![0x00]),
            (false, 0) => {
                let script_pub_key = &self.out_point.script_pub_key.clone();
                serialized_input.extend(variable_length_integer(script_pub_key.len() as u64)?);
                serialized_input.extend(script_pub_key);
            }
            (false, _) => {
                serialized_input.extend(variable_length_integer(self.script.len() as u64)?);
                serialized_input.extend(&self.script);
            }
        };

        if hash_preimage {
            serialized_input.extend(&self.out_point.amount.to_le_bytes());
        };

        serialized_input.extend(&self.sequence);
        Ok(serialized_input)
    }
}

impl<N: ZcashNetwork> ZcashTransactionOutput<N> {
    /// Create a new Zcash transaction output
    pub fn new(address: &str, amount: u64) -> Result<Self, TransactionError> {
        Ok(Self {
            amount,
            output_public_key: generate_script_pub_key::<N>(address)?,
            _network: PhantomData,
        })
    }

    /// Serialize the transaction output
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let mut serialized_output: Vec<u8> = Vec::new();
        serialized_output.extend(&self.amount.to_le_bytes());
        serialized_output.extend(variable_length_integer(self.output_public_key.len() as u64)?);
        serialized_output.extend(&self.output_public_key);
        Ok(serialized_output)
    }
}

impl<N: ZcashNetwork> SaplingSpend<N> {
    pub fn new(
        extended_key: &str,
        cmu: &[u8; 32],
        epk: &[u8; 32],
        enc_ciphertext: &str,
        anchor: Fr,
        witness: CommitmentTreeWitness<Node>,
    ) -> Result<Self, TransactionError> {
        let extended_spend_key = ZcashExtendedPrivateKey::<N>::from_str(extended_key)?;
        //        let ivk = extended_spend_key.to_extended_public_key().to_extended_full_viewing_key().fvk.vk.ivk(); // Incompatible implementations of Fs

        let full_viewing_key = extended_spend_key
            .to_extended_public_key()
            .to_extended_full_viewing_key()
            .fvk
            .to_bytes();
        let ivk = FullViewingKey::<Bls12>::read(&full_viewing_key[..], &JUBJUB)?
            .vk
            .ivk();

        let mut f = FrRepr::default();
        f.read_le(&cmu[..]).unwrap();
        let cmu = Fr::from_repr(f).unwrap();

        let enc_ciphertext_vec = hex::decode(enc_ciphertext)?;

        let epk = edwards::Point::<Bls12, _>::read(&epk[..], &JUBJUB)?
            .as_prime_order(&JUBJUB)
            .unwrap();
        let (note, payment_address, _memo) =
            match try_sapling_note_decryption(&ivk.into(), &epk, &cmu, &enc_ciphertext_vec) {
                None => return Err(TransactionError::FailedNoteDecryption(enc_ciphertext.into())),
                Some((note, payment_address, memo)) => (note, payment_address, memo),
            };

        let alpha = Fs::random(&mut StdRng::from_entropy());

        Ok(SaplingSpend {
            extended_spend_key,
            diversifier: payment_address.diversifier().0,
            note,
            alpha,
            anchor,
            witness,
            spend_description: None,
        })
    }

    /// Create Sapling Spend Description
    pub fn create_sapling_spend_description(
        &mut self,
        proving_ctx: &mut SaplingProvingContext,
        spend_params: &Parameters<Bls12>,
        spend_vk: &PreparedVerifyingKey<Bls12>,
    ) -> Result<(), TransactionError> {
        // Incompatible implementation types for proof generation key - requires byte conversion
        let spending_key = self.extended_spend_key.to_extended_spending_key().expsk.to_bytes();
        let proof_generation_key = ExpandedSpendingKey::<Bls12>::read(&spending_key[..])?
            .proof_generation_key(&JUBJUB);

        let nf = &self.note.nf(
            &proof_generation_key.to_viewing_key(&JUBJUB),
            self.witness.position,
            &JUBJUB,
        );

        let (proof, value_commitment, public_key) = proving_ctx
            .spend_proof(
                proof_generation_key,
                Diversifier(self.diversifier),
                self.note.r,
                self.alpha,
                self.note.value,
                self.anchor,
                self.witness.clone(),
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
        self.anchor.into_repr().write_le(&mut anchor[..])?;
        nullifier.copy_from_slice(nf);
        public_key.write(&mut rk[..])?;
        proof.write(&mut zk_proof[..])?;

        let spend_description = SpendDescription {
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
}

impl SpendDescription {
    /// Serialize the Sapling output description
    pub fn serialize(&self, sighash: bool) -> Result<Vec<u8>, TransactionError> {
        let mut serialized_output: Vec<u8> = Vec::new();
        serialized_output.extend(&self.cv);
        serialized_output.extend(&self.anchor);
        serialized_output.extend(&self.nullifier);
        serialized_output.extend(&self.rk);
        serialized_output.extend(&self.zk_proof);

        match (&self.spend_auth_sig, sighash) {
            (Some(spend_auth_sig), false) => serialized_output.extend(spend_auth_sig),
            (_, _) => {}
        };

        Ok(serialized_output)
    }
}

impl<N: ZcashNetwork> SaplingOutput<N> {
    pub fn new(ovk: SaplingOutgoingViewingKey, address: &str, value: u64) -> Result<Self, TransactionError> {
        let diversifier = ZcashAddress::<N>::get_diversifier(&address)?;
        let pk_d = ZcashAddress::<N>::get_pk_d(&address)?;

        let pk_d = edwards::Point::<Bls12, _>::read(&pk_d[..], &JUBJUB)?.as_prime_order(&JUBJUB);

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
                    value,
                    r: Fs::random(&mut StdRng::from_entropy()),
                };

                Ok(Self {
                    address: ZcashAddress::<N>::from_str(&address)?,
                    ovk,
                    to,
                    note,
                    memo: Memo::default(),
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
        let ovk = OutgoingViewingKey(self.ovk.0);
        let enc = SaplingNoteEncryption::new(
            ovk,
            self.note.clone(),
            self.to.clone(),
            self.memo.clone(),
            &mut StdRng::from_entropy(),
        );

        let (proof, value_commitment) = proving_ctx.output_proof(
            enc.esk().clone(),
            self.to.clone(),
            self.note.r,
            self.note.value,
            &output_params,
            &JUBJUB,
        );

        // Generate the ciphertexts

        let cm = self.note.cm(&JUBJUB);
        let enc_ciphertext = enc.encrypt_note_plaintext();
        let out_ciphertext = enc.encrypt_outgoing_plaintext(&value_commitment, &cm);

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
        enc.epk().write(&mut ephemeral_key[..])?;
        proof.write(&mut zk_proof[..])?;

        // Verify the output description
        match verifying_ctx.check_output(
            value_commitment,
            cm,
            enc.epk().clone().into(),
            proof,
            output_vk,
            &JUBJUB,
        ) {
            true => {}
            false => return Err(TransactionError::InvalidOutputDescription(self.address.to_string())),
        };

        let output_description = OutputDescription {
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
}

impl OutputDescription {
    /// Serialize the Sapling output description
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let mut serialized_output: Vec<u8> = Vec::new();
        serialized_output.extend(&self.cv);
        serialized_output.extend(&self.cmu);
        serialized_output.extend(&self.ephemeral_key);
        serialized_output.extend(&self.enc_ciphertext);
        serialized_output.extend(&self.out_ciphertext);
        serialized_output.extend(&self.zk_proof);
        Ok(serialized_output)
    }
}

/// Return the Blake256 hash given a personalization and optional zcash version name
fn blake2_256_hash(personalization: &str, message: Vec<u8>, version_name: Option<&str>) -> Hash {
    let personalization = match version_name {
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
            let pub_key_hash = address_bytes[2..(address_bytes.len() - 4)].to_vec();

            script.push(OPCodes::OP_DUP as u8);
            script.push(OPCodes::OP_HASH160 as u8);
            script.extend(variable_length_integer(pub_key_hash.len() as u64)?);
            script.extend(pub_key_hash);
            script.push(OPCodes::OP_EQUALVERIFY as u8);
            script.push(OPCodes::OP_CHECKSIG as u8);
        }
        _ => unreachable!(),
    }

    Ok(script)
}

/// Validate the address format with the given scripts
/// (P2SH currently unsupported)
pub fn validate_address_format(
    address_format: &Format,
    amount: &Option<u64>,
    redeem_script: &Option<Vec<u8>>,
    script_pub_key: &Vec<u8>,
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

    Ok((amount.unwrap_or(0), redeem_script.clone().unwrap_or(Vec::new())))
}

/// Return the variable length integer of the size (compactSize uint)
/// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
pub fn variable_length_integer(size: u64) -> Result<Vec<u8>, TransactionError> {
    if size < 253 {
        Ok(vec![size as u8])
    } else if size <= 65535 {
        // u16::max_value()
        Ok([vec![0xfd], (size as u16).to_le_bytes().to_vec()].concat())
    } else if size <= 4294967295 {
        // u32::max_value()
        Ok([vec![0xfe], (size as u32).to_le_bytes().to_vec()].concat())
    } else {
        Ok([vec![0xff], size.to_le_bytes().to_vec()].concat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::librustzcash::zip32::prf_expand;
    use crate::private_key::SaplingSpendingKey;
    use crate::{Mainnet, Testnet};

    use bellman::groth16::PreparedVerifyingKey;
    use rand::Rng;
    use std::path::Path;
    use zcash_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
    use zcash_proofs::load_parameters;

    pub struct Transaction {
        pub header: u32,
        pub version_group_id: u32,
        pub lock_time: u32,
        pub expiry_height: u32,
        pub inputs: [Input; 4],
        pub outputs: [Output; 8],
        pub sapling_inputs: [SaplingInput; 4],
        pub sapling_outputs: [Output; 4],
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
    pub struct SaplingInput {
        pub extended_secret_key: &'static str,
        pub cmu: &'static str,
        pub epk: &'static str,
        pub enc_ciphertext: &'static str,
        pub anchor: Option<&'static str>,
        pub witness: Option<&'static str>,
    }

    #[derive(Clone)]
    pub struct Output {
        pub address: &'static str,
        pub amount: u64,
    }

    const SAPLING_INPUT_FILLER: SaplingInput = SaplingInput {
        extended_secret_key: "",
        cmu: "",
        epk: "",
        enc_ciphertext: "",
        anchor: None,
        witness: None,
    };

    const INPUT_FILLER: Input = Input {
        private_key: "",
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

    fn test_sapling_transaction<N: ZcashNetwork>(
        header: u32,
        version_group_id: u32,
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

        let mut transaction =
            ZcashTransaction::<N>::build_raw_transaction(header, version_group_id, lock_time, expiry_height).unwrap();

        // Add transparent inputs

        for input in &inputs {
            let private_key = ZcashPrivateKey::from_str(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();

            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = input.redeem_script.map(|script| hex::decode(script).unwrap());
            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());

            transaction
                .add_transparent_input(
                    address,
                    transaction_id,
                    input.index,
                    input.utxo_amount,
                    redeem_script,
                    script_pub_key,
                    sequence,
                    input.sig_hash_code,
                )
                .unwrap();
        }

        // Add transparent outputs

        for output in outputs {
            transaction.add_transparent_output(output.address, output.amount).unwrap();
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
                    let witness = CommitmentTreeWitness::<Node>::from_slice(&witness_vec[..]).unwrap();

                    let mut f = FrRepr::default();
                    f.read_le(&hex::decode(input.anchor.unwrap()).unwrap()[..]).unwrap();
                    let anchor = Fr::from_repr(f).unwrap();

                    (witness, anchor)
                }
                None => {
                    // Generate note witness for testing purposes only.
                    // Real transactions require a stateful client to fetch witnesses/anchors from sapling tree state.
                    let extended_spend_key = ZcashExtendedPrivateKey::<N>::from_str(input.extended_secret_key).unwrap();
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

            transaction
                .add_sapling_spend(
                    input.extended_secret_key,
                    &cmu,
                    &epk,
                    input.enc_ciphertext,
                    anchor,
                    witness,
                )
                .unwrap();

            let extended_spend_key = ZcashExtendedPrivateKey::<N>::from_str(input.extended_secret_key).unwrap();
            sapling_spend_key = Some(extended_spend_key.to_extended_spending_key().expsk);
        }

        // Select Output Viewing Key

        let ovk = match &sapling_spend_key {
            // Generate a common ovk from HD seed
            // (optionally pass in a seed for wallet management purposes)
            None => {
                let rng = &mut StdRng::from_entropy();
                let seed: [u8; 32] = rng.gen();
                let hash = blake2_256_hash("ZcTaddrToSapling", seed.to_vec(), None);
                let mut ovk = [0u8; 32];
                ovk.copy_from_slice(&prf_expand(hash.as_bytes(), &[0x01]).as_bytes()[0..32]);

                SaplingOutgoingViewingKey(ovk)
            }
            // Get the ovk from the sapling extended spend key
            Some(spend_key) => spend_key.ovk,
        };

        // Build Sapling outputs

        for output in sapling_outputs {
            transaction
                .add_sapling_output(ovk, output.address, output.amount)
                .unwrap();
        }

        let mut proving_ctx = SaplingProvingContext::new();
        let mut verifying_ctx = SaplingVerificationContext::new();

        for (index, input) in inputs.iter().enumerate() {
            transaction
                .sign_raw_transaction(ZcashPrivateKey::from_str(input.private_key).unwrap(), index)
                .unwrap();
        }

        // Generate the sapling output and do verification checks

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

        let signed_transaction = hex::encode(transaction.serialize_transaction(false).unwrap());
        println!("signed transaction: {}", signed_transaction);

        // Note: All output/spend descriptions and proofs are verified upon creation.
    }

    fn test_transaction<N: ZcashNetwork>(
        header: u32,
        version_group_id: u32,
        lock_time: u32,
        expiry_height: u32,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        expected_signed_transaction: &str,
    ) {
        // Build raw transaction

        let mut transaction =
            ZcashTransaction::<N>::build_raw_transaction(header, version_group_id, lock_time, expiry_height).unwrap();

        // Add transparent inputs

        for input in &inputs {
            let private_key = ZcashPrivateKey::from_str(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();

            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = input.redeem_script.map(|script| hex::decode(script).unwrap());
            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());

            transaction
                .add_transparent_input(
                    address,
                    transaction_id,
                    input.index,
                    input.utxo_amount,
                    redeem_script,
                    script_pub_key,
                    sequence,
                    input.sig_hash_code,
                )
                .unwrap();
        }

        // Add transparent outputs

        for output in outputs {
            transaction.add_transparent_output(output.address, output.amount).unwrap();
        }

        // Sign the raw transaction

        for (index, input) in inputs.iter().enumerate() {
            transaction
                .sign_raw_transaction(ZcashPrivateKey::<N>::from_str(input.private_key).unwrap(), index)
                .unwrap();
        }

        let signed_transaction = hex::encode(transaction.serialize_transaction(false).unwrap());
        assert_eq!(expected_signed_transaction, signed_transaction);
    }

    mod test_testnet_sapling_transactions {
        use super::*;
        type N = Testnet;

        const SAPLING_SPEND_TRANSACTIONS: [Transaction; 3] = [
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 499999999,
                inputs: [
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER,
                ],
                outputs: [
                    Output {
                        address: "tmKXdkNCRxZ8Ha6voL4MVByBRkCPez5ak6Z",
                        amount: 499960000,
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                sapling_inputs: [
                    SaplingInput {
                        extended_secret_key: "secret-extended-key-test1qwq6zxvfqsqqpqzn4hxmcv7d9whwepfpx72aahddkf073x2cwr6fwar0p2ns4xkcu73xgs2pnxgux2nfx8a5nt2w7tm49ptnq9v3z4qncjlk8er7q27qewhcul9xtlxjqe56jyspamlhh8r4glmva2zxvkuejw8ypsfp5lsgc564r6g5w068kqlrcy0s0wnu0382tv2eqnlart5gjczwa0l72qgtaa794dqpva62206wwvemvath3t2f5j6x9nlvsgus0wavrvwavucculeth",
                        cmu: "40d9712ba3dd9787a0451462e4fdda07929305b06248dd8aaeabdce13985b576",
                        epk: "8dca2796416d9ab8409e40e3b3839eb28b5765ba9b7dcfb2c267ac54b85fc6be",
                        enc_ciphertext: "d259f0cb859e6bc1b92590600f2a5d9b3464c7c568c96926fb97b2ffcecd7f9c8bfb878e3650cf30378ec222797787ab2c354589cda6da227c9b72945751827857823848a03bddeef13ecc14570291ee6638da600e0f91ca0348a6146b9f176b60f053a7f4bd94f5d9c669e8958b3d03c2fd456caa4703ec1ffcf75759ffaf098502295c7eadbdab928e77740220339611c4c977b0185627f2ac6db5c0fca6c1d6a89f0ba6503f6d520e6814f0f592bc950023395b2907e39067242a87d74dc535a7decf37c4530b1b5f375cd588949cc9948c409ad3b7bf1bd6a307d076b34a1c93c330f7a42df419ef95965e747b43306f277255cc2fe4b7f4ec3e6ca06f7161ac4a89b703b2b99b201d3a2279b45d60b0f899931afc45a6be5496df192abade2039403132711d899bc8e02700d2f9cf225ca7de9b4c9e3899c9e63eb669e4b626006797ad61247bef423b27ad4e2d472c648420ac88d9f03abc9132d360b1e634684bb73eb251495f3c34a5ab6f73436b2b58e5fb89a5e41692ceea8f04d19b2dd76a796bda2d99f95b5aca03a750acb50f44924f7fea953fe33316255da6c5cadb80687875bc63b2865d79010a3d845d9bc1836a2726d3040ed05fe403f30a51597f8921e3c0c4544d1aab8d67a382410ce377654e79e27e9ff81bd8264d5fbd4e5915a7fa804424cc65ff19ca4d4dd0f3fb34585d18b75f6c39d99cc48e800bab6fa2324340922f62273fe371f2d725567fae988579a00bf7bc3b911cf03746cf47286f05d24c64c38f829d0d40a34799151176057cfe49d6b9fc6b9d983612d75d",
                        anchor: None,
                        witness: None,
                    },
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "",
            },
            Transaction { //
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 499999999,
                inputs: [
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER,
                ],
                outputs: [
                    Output {
                        address: "tmEDWXTm25SuuRgLGsD8j5CDsBxVBrZTEQ8",
                        amount: 499990000,
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                sapling_inputs: [
                    SaplingInput {
                        extended_secret_key: "secret-extended-key-test1qn7ydpt6qqqqqqr6xek4td34wfcgd229v5fhnzmntdcl5n4cltwg25pp0prydaktd7nam7grwchkhz8606zdscjc2ghjfmldqdjf2hcsa6y7e7jkugrspyfwdq34eweejzqpg003x5a8j5lvmxt63mlpy362wjssvmwp0eq2mfp5gp02mv5wvy25fh532jjggc7fwrnqgl97s6tg0ugmqzlrx0sufand5puvu9mxe9hawgv64k9x3pg7xz7lu9u38snjcwayus6s3hcemqac2",
                        cmu: "16ff8ed12ad3419672c9d344340bcb19aed41a3fb1c6d002bd713e683d804c43",
                        epk: "e7f2b7a37ef84f64a328abfbda51bac2542265008f2a851d8a594a033dafbf61",
                        enc_ciphertext: "14ed755988716e1e72abb02b0ddb926af406343a449b132d74554b01c6f9b9af1cf8d41ea3dfd83058608000aebbe55331820fd7514b05bdd9de80d9894d1381689c5cb6f4bc5a79e950e2ffdd8ac8db85e755c4fa12fd95c2610791d69848c91d5c5b93d60af6bc8c0f1aad6a841163bb9589059fbd7826d09dbc19a7cc99745f03812607fa16c3e88ace4cd0aad74a7f2f79b82f3112929a67d76d64b12a11ba0d2c0e4ee7c9e5946677bb089c6728bcf2476196415e321810be9bc4b1a8e3b289bfa28b22ebbd6981852e1fcaf939b7ae54a2ca2601a01f47a1d369ea066e8f2cff34e4a97534c15accf9d2c61953592f74dca60a3805f7ee7ae905ccb8375ee0741e3fe53f0444b0292d4ee5f57c432a984b57222acac9762cb6f9aefc34279e51599d95ed3f6b3a6f92fbb579d3c97c5cdbab092f8e819b37e4463ccd02c11db2e19ce842a24985315f7e06f088e46d2fb56a528462e04a087666cf1ade0beaadd08fb99806123cd8fed8b643609fcd26844215e536fe809780a6aafddcb28c4c3a2c84d9273232984342bb71fb55f1abbf2406958fd6a65eba4ab738f34e83940f35b2f2588beae1967c175a098551d616ed75db04f9a17f5bb111977aeaa110faae908aa6a4af98b5efb9d947937a75fb4997690d84e314447f4ed09e3b91a04d967c324ab421b6e5a5bf6ed7a5bf3b9ce7f1d919681a8359b7843537a233bd69a430758d1d0af4bc4dfddd85c913179fc525c85f4ffdcd5d41a948148ed7e94f220535d465336a5708e780bf15b2ec14d559f4f4bf569977379e988e385e4ec7",
                        anchor: None,
                        witness: None,
                    },
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "",
            },
            Transaction { // 6a25dbdbb4da6f8ff115d44aad9519be23e17e8322244ed61160d02a9249eca2
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 499999999,
                inputs: [
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER,
                ],
                outputs: [
                    Output {
                        address: "tmEn21pZv4FTPfXinSNfdtQyDVhnkRz9T7q",
                        amount: 999980000,
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                sapling_inputs: [
                    SaplingInput {
                        extended_secret_key: "secret-extended-key-test1qwq6zxvfqcqqpqx9yxfvz024pygvsyc5mk3tvx90c9xyvc8660xk9q3954rmdngzhsdms6h8mdwgmwgct0degp3x5aeruddxpxwg3c3gy4krptv47w2q6790n88h8uztvxzxjd9ndz4yx80vm8mqqjj73m5gyzz3edmnlxgp0y642f36dv3xl30pm7fetducd0rfcpg8nq9nuj5pxtlu35p946yk5nwa6gdzc5v4w7dpwzmdszqudq6ecn0esryntk9vly0fkh53grsnjunxl",
                        cmu: "6bea0e40d62442443a3475b3486b3b230e6f3895f6ec931bdcf378ab72e1f7b8",
                        epk: "bdfe7b1a08c3a43f8357be258d10ddbaf4f6ed58d99ba94184d4536b1ae7daac",
                        enc_ciphertext: "c8af78c4b420366f686c450c0652d28d0955c0bf26380d7cfd81501864b806ef868f1b5ec6d7ac2eb1809299074498a101ef370389129b90c7b10207a685148743b3c4f083538c62a33199ccf65d1987a73d5cf293a5691b4d57aba2b95d4c67c6d0001d4741bba826cd9c1f1695700146dcd65f4e61cc2b1dd96f03046c8c334d036c8f43d3d15c7f58c39dd35ecb2b34189710489c5aa0fa02d64f1d6d76014e6862be2e741025bd7f11f99a65518da4340854daa54b4719ed3716f3f409e7821e7cf973f2adeebc229458da60007b97c006398a0da0e5cf6753c44533e1fc97850705dbfd6cd68f1b618faf7e0b29c2c03ab3c8c7015db095e4ffcbb3be8e2a2fde2a40c7570e54cecc02348706251ff0ed88513051b9886b8a0d9681c2713f2d2162ef93c7c81c3cbc7e9a9685388c8690397b53ab217b048d22f5c9c019cce142eaef9f330ec5239dc4f61c0eafdb10bd4679e52a2863969c5cd6172f893a2a6e4af31c4b73456d339b127ca3e98595da3599f1a00c6804363e4b1d393f925d0f3eaa79e03d96411139fb024bbc2587334bb04f447f074e50639c627fd665d59253a261779ce5de22d678ceaad9a3e20078346d17bc6ca294df1ef3bfe239bbb1bb33bb34f6701874d48dab94c5649577aff9b98fa0f69adee522868da0cd31cd744f31b6f01d1701d36ae50af38a653651ce85dd432d90fbce2cdd06c69d644fdab912b89c7c69a7c19b95442c0ea62de16ad88ade0130c84ebead2ff99fe12bd686bbba322f9ff61531341513f6a4b51fa65c47cb45dd5cdeb85f0b9abf8f68a3",
                        anchor: Some("a4c8ea36def54b535c93a3d3d61daa5fbd04968b79ae3a518d2f1a097fcfe52d"),
                        witness: Some("2020b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c538142012935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d20e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef722028e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a20a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a20d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb582016d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a20fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712204c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850200769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c492008eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023208d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673206aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b15921620cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00206edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c201f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d3920d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f20bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c201b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab6512045e3d4899fcd7f0f1236ae31eafb3f4b65ad6b11a17eae1729cec09bd3afa01a20c104705fac60a85596010e41260d07f3a64f38f37a112eaef41cd9d736edc52720ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce7220bac21af2f8b1eba9d2eed719a3108efaa19b44386f2dd38212294253e6fa1102207b99abdc3730991cc9274727d7d82d28cb794edbc7034b4f0053ff7c4b680444204484e8faa977ac6a7372dfa525d10868666d9b8c8b06e95df0594bc33f5f7b5620b9e8757b6d27fcfd9adc914558e9bf055e125f610fd6170072b4778fa0c4f90b20db4ea7c2d058649c99ba7a9c700db7dfc53a2c14a4dd2a20dad9d35294b61559207ffb9317c7941ebc524eaceb48316ecdf9cdf39d190ab12c16836f885a0ab24820d8283386ef2ef07ebdbb4383c12a739a953a4d6e0d6fb1139a4036d693bfbb6c201a0564d96a7d7b6beb993318e8de10c44bb6eb0d91c674a8c04b0a15ccb33c7020bc540156b432138ebd0ab33dd371ee22ed7f5d3f987af37de468a7f74c055f5c2021cac521ca62e3b84381d8303660a7ca9fa99af47ee7080ea7f35f48c865b065f71a010000000000"),
                    },
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "",
            },
        ];

        const SAPLING_OUTPUT_TRANSACTIONS: [Transaction; 3] = [
            Transaction {
                // 289f33b35eb814d4c8df4d38f9d4eefe2a63c88e8af609dc64456bfa6a591495
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 499999999,
                inputs: [
                    Input {
                        private_key: "cUBFqbapRJBAKbpVq7LBDUrSY4UWquuTcA1UrLCvdym1zHiWFPBb",
                        address_format: Format::P2PKH,
                        transaction_id: "cdb426cbd9dfe1c27df683a891977d0a5be6cc87e3b618917bb124caba7a78f2",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(1000010000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL,
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER,
                ],
                outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    Output {
                        address:
                            "ztestsapling1z9thqxgzavwxfr58x72784y8uasz2hvzfvvzu3dl9prk3kyym04nf5vzwgpf5ddz2cu3ytf9jmg",
                        amount: 1000000000,
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "",
            },
            Transaction {
                // a018f5777860c7617266c43c9fecf53b939f96af70c1c21675351a51d373ac2a
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 499999999,
                inputs: [
                    Input {
                        private_key: "cUnh9NAShCGCur8PjxQnRz96n93Hs6tNAo6fmH41ig1vKzrXtWdC",
                        address_format: Format::P2PKH,
                        transaction_id: "35562b33fe8d03e0dcd9a2dd62154f3abdfcd7d29d61dcff0a09c1eb18a8f7ea",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(1000010000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL,
                    },
                    Input {
                        private_key: "cPZUjmuvdkcBMNyHn6wqXcVVqPbVrtxfcQc7UcrD2aD9mdrPBSf9",
                        address_format: Format::P2PKH,
                        transaction_id: "35562b33fe8d03e0dcd9a2dd62154f3abdfcd7d29d61dcff0a09c1eb18a8f7ea",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(1000010000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL,
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                ],
                outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    Output {
                        address:
                            "ztestsapling1w4q82skzstjkql5t9x96yl8pxkm0yaymlgp3z9w0z9nzgmqj20fz749wyc4j550gvp8uyauughk",
                        amount: 1000000000,
                    },
                    Output {
                        address:
                            "ztestsapling18zxfnamtuvl0hapcmmturn47ttgjftmfpjmk4nvph0yjfywhyrmp97hnepw8gf9gka925apsj5d",
                        amount: 1000000000,
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "",
            },
            Transaction {
                // f2f2408a3742c58ce24d96840bdfa1ff26b7042928075fb02ddb1847d1fd2038
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 499999999,
                inputs: [
                    Input {
                        private_key: "cMwUGSqBqKSavhstEH6Jsuf7cpqFf15ywuEaoUBmBuesdZxng41H",
                        address_format: Format::P2PKH,
                        transaction_id: "35562b33fe8d03e0dcd9a2dd62154f3abdfcd7d29d61dcff0a09c1eb18a8f7ea",
                        index: 2,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(1000010000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL,
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER,
                ],
                outputs: [
                    Output {
                        address: "tmGZKXeeSu2sVS72Lg1KAuKKUxg2S4iGXZ7",
                        amount: 500000000,
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    Output {
                        address:
                            "ztestsapling1j9kgn4sawrk8zdq63a6uarf8xggk9ugm9wfynlkg2z2lgh7p47tt69686xepn0t323dgs5ttaqn",
                        amount: 500000000,
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "",
            },
        ];

        #[test]
        fn test_sapling_spend_transactions() {
            let spend_path = Path::new("src/librustzcash/params/sapling-spend.params");
            let output_path = Path::new("src/librustzcash/params/sapling-output.params");

            let (spend_params, spend_vk, output_params, output_vk, _sprout_vk) = load_parameters(
                spend_path,
                "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c",
                output_path,
                "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028",
                None,
                None,
            );

            SAPLING_SPEND_TRANSACTIONS.iter().for_each(|transaction| {
                let mut pruned_inputs = transaction.inputs.to_vec();
                pruned_inputs.retain(|input| input.transaction_id != "");

                let mut pruned_outputs = transaction.outputs.to_vec();
                pruned_outputs.retain(|output| output.address != "");

                let mut pruned_sapling_inputs = transaction.sapling_inputs.to_vec();
                pruned_sapling_inputs.retain(|sapling_input| sapling_input.extended_secret_key != "");

                let mut pruned_sapling_outputs = transaction.sapling_outputs.to_vec();
                pruned_sapling_outputs.retain(|sapling_output| sapling_output.address != "");

                test_sapling_transaction::<N>(
                    transaction.header,
                    transaction.version_group_id,
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

        #[test]
        fn test_sapling_output_transactions() {
            let spend_path = Path::new("src/librustzcash/params/sapling-spend.params");
            let output_path = Path::new("src/librustzcash/params/sapling-output.params");

            let (spend_params, spend_vk, output_params, output_vk, _sprout_vk) = load_parameters(
                spend_path,
                "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c",
                output_path,
                "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028",
                None,
                None,
            );

            SAPLING_OUTPUT_TRANSACTIONS.iter().for_each(|transaction| {
                let mut pruned_inputs = transaction.inputs.to_vec();
                pruned_inputs.retain(|input| input.transaction_id != "");

                let mut pruned_outputs = transaction.outputs.to_vec();
                pruned_outputs.retain(|output| output.address != "");

                let mut pruned_sapling_inputs = transaction.sapling_inputs.to_vec();
                pruned_sapling_inputs.retain(|sapling_input| sapling_input.extended_secret_key != "");

                let mut pruned_sapling_outputs = transaction.sapling_outputs.to_vec();
                pruned_sapling_outputs.retain(|sapling_output| sapling_output.address != "");

                test_sapling_transaction::<N>(
                    transaction.header,
                    transaction.version_group_id,
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
    }

    mod test_mainnet_transparent_transactions {
        use super::*;
        type N = Mainnet;

        /// Keys and addresses were generated randomly and test transactions were built using the zcash-cli
        const TRANSACTIONS: [Transaction; 4] = [
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 0,
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
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "0400008085202f89015510a014f306f99a3e5e48460425777f210e0bd2c02301ec93f1baffe1b29710000000006a47304402207c2e6d5ec25a8ab67229f23a581ee8898eb087c2aa6c8db8acf21c3b96bab5fb02202ff7689945891a20961de1b4e18b40995fe7f07cb6dd1c97607c65259adeb1bd012102a7b8361f36eee68b96cbc72bab73295494161b8e670a29c99819e2b793939d25ffffffff0100e1f505000000001976a91459fec7e62fcf3e580656bc1bc6c220dad37709ab88ac00000000000000000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 456789,
                expiry_height: 600000,
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
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "0400008085202f8901394fc83a499e120c92269690c39e7507b34905ccd33d4e53f8c713835bd934f2000000006a473044022053637ac8ece0fd2c5cd2fa2c6abb6fec36317a7e60be6c5215ff83ab903409a502206cdcb354b7bca6a4aed08fc6409a6e0000ba263c47f6bb22ab74ad2fe270250501210325c97e86e09f91a9894b856c9b9ca6d7ea90754d66acc95fb57b46117492d3bdfeffffff0480f0fa02000000001976a914c4fafe5725a6ec3d2218458c00da884cd9a0507c88ac80f0fa02000000001976a9142a80f5573b12de286ecbe0f8d46acb9c2334375588ac80f0fa02000000001976a914167b3376103f458ea847ec6f5e763b0de2808f3e88ac80f0fa02000000001976a914473ce0a50b7a876fcba71973b49770b79cfb10b188ac55f80600c02709000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 456789,
                expiry_height: 0,
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
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "0400008085202f890350b2ed017b6c60080d9f9a2c6a2b8039be56cd17839474bc31a4d69d9195b5ff010000006b483045022100adcab54a2e437df28eebf4c19f33061467d951a035f12125d3ba16dc3a7ed21c02204a13ba64160a5a11fb22ada860202995df5f51f05eb882fc197109fba298b96e012103f632eeb38fa2fcc7af1881f1b6c1f4fe6155ee6267d92657d9a95fdbb15c010effffffff74941a58fce3c9eed67cfc23e90743314283774f1901c5093c3db04f23516346020000006b483045022100a14d25f96742b6a06f201db6811ed1bbbeab80be29ea45ad8e54ce583337056502200e04272216609ca7cf38729156c860e59a1e88632697456fb0639efebc6509bd0121026fba2e786f9351532a8f93de404d0c44b54e01a7f10bf1a61f734bc4249b58f9ffffffff5d3090f7a591c1426b209d43dc546070fcddceba5b2c81c164aa95ed121ad72e030000006a473044022005e9df51bedd7f95d567ef472040fb295f7dc7d742e1a894d48f67f5239fd860022076d170cb5be8435628c738f0beecbeb85fc6fb1f8f74d5dd18db0fdc584df6650121020621d94a64caf7183bef70f89cfca4cd3d30a76ce0335f7f10eb787e266bb2cdffffffff0100ca9a3b000000001976a9149d92a791abc62a9ca93ced9086c2129d31757ee088ac55f80600000000000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 584789,
                expiry_height: 710482,
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
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
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
                    pruned_inputs,
                    pruned_outputs,
                    transaction.expected_signed_transaction,
                );
            });
        }
    }

    mod test_testnet_transparent_transactions {
        use super::*;
        type N = Testnet;

        /// Keys and addresses were generated randomly and test transactions were built using the zcash-cli
        const TRANSACTIONS: [Transaction; 4] = [
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 307241,
                expiry_height: 307272,
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
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "0400008085202f8901a8c685478265f4c14dada651969c45a65e1aeb8cd6791f2f5bb6a1d9952104d9010000006b483045022100ef50a15eece0f43a0efd13a2c45aecf85e8e999858721150a70e75b106d80ea702202b3ff79fdcd2ff101dcacd74a7f6e3adb1250955f7a80962b259d1e17742f2f70121037e8e3a964e0f59c52633e25f9cec2fc8bb9af5b23eace85f6264f68b47db5cb6feffffff02005a6202000000001976a9148132712c3ff19f3a151234616777420a6d7ef22688ac8b959800000000001976a9145453e4698f02a38abdaa521cd1ff2dee6fac187188ac29b0040048b004000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 450000,
                expiry_height: 579945,
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
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "0400008085202f89013121b82a43576452d0136cd3a78852f4cd0f46bdb265a349b62d4d790ff103ce0c0000006a47304402201e563ac13e9ae03b0c0f19313dfc5ef32d633adc46d0e2ecad6185b46961e37902207d33d054cfaf1f25149298bb12f5f9dd063034415ec4ee0bad71437f846b04e00121029862bf5d37725419b03e9e3db90f60060de42d187c5ed28bdb41ed435742bd51feffffff0300e9a435000000001976a914c847ac8eafe8ecfac934a41c37b2720ab266b8b688ac80f0fa02000000001976a91416837e1ef0b93ef72d9a2cc235e4d342b476d1d788ace069f902000000001976a9142d6f726f415eaf3e8b609bb0cdc451d4777c800d88acd0dd060069d908000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 285895,
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
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "0400008085202f89013194cd7a9f2a354b158ea891792b7c60ff2184852d2769a348870e54342ec21e000000006a47304402203b1f53d5f4c56e5120cd9574328f68c7403772db8eb26b75566a1499a8da1c5002205b22f8870c467d206494448f364b3f2f632e747563dbcc74ddcf27bb3c8033020121030cb32083e4b93572483ac4a3a39df5de63047973eb424b3f202bf0438e80b7bcffffffff01c09ee605000000001976a91471000dc3823178a6a14b0d41547f1a4163bb6fd488ac00000000c75c04000000000000000000000000"
            },
            Transaction {
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 500000,
                expiry_height: 575098,
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
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
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
                    pruned_inputs,
                    pruned_outputs,
                    transaction.expected_signed_transaction,
                );
            });
        }
    }

    mod test_real_testnet_transparent_transactions {
        use super::*;
        type N = Testnet;

        const TRANSACTIONS: [Transaction; 5] = [
            Transaction { // d74cf2f55f267dc4bacaacaa09e3317ac74265d860045a535a9e663fc99818bf
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 499999999,
                inputs: [
                    Input {
                        private_key: "cVDVjUASqQn7qokRZqpHTdFpTEkwbpf7ZzhgTsqt79y9XWDyPod6",
                        address_format: Format::P2PKH,
                        transaction_id: "72a67442781a84eee2b327f9bb7030d725cf0fc90798aa51cb45a8acfd08c12d",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(20000000000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "tmNP9aZHniVeXmsMQxrN2pDJt4aCd6MGcYE",
                        amount: 10000000000
                    },
                    Output {
                        address: "tmVK7tKxTjnXdaEuDhyoAdZ1iViM2CrTQuV",
                        amount: 9999900000
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "0400008085202f89012dc108fdaca845cb51aa9807c90fcf25d73070bbf927b3e2ee841a784274a672000000006b483045022100a6255438be743890d53bf5a0818f58370361a0ff82f88dca30fba0aec1b2859b022055950c72f1111babcf01f58087300eb80e3acfff169d05338d8e2c7a0dd0b1fe012102386cb1f3211d689bcf9fd763381a4d7a9a0d719667c979ac485d6d2ec69a17e0ffffffff0200e40b54020000001976a9148af7ebff7dad3862258a44992915615bfd9e6d4388ac605d0a54020000001976a914d6fdb988e0ca149cb74eda244d8fc52481d6452088ac00000000ff64cd1d0000000000000000000000"
            },
            Transaction { // 22da774bc331dad798ffdf1a18b1ad984ce4255ed5f687fcd44e6609624727fc
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 576566,
                inputs: [
                    Input {
                        private_key: "cTQpmkaF8YNivhZKw6PposeYz1FN9PxmW2r776rBKBWcAP8nA4bf",
                        address_format: Format::P2PKH,
                        transaction_id: "d74cf2f55f267dc4bacaacaa09e3317ac74265d860045a535a9e663fc99818bf",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(9999900000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "tmFgo8Damu8M6fKF5rJzZnkFMERMvo97sjT",
                        amount: 3333266667
                    },
                    Output {
                        address: "tmLTBB1na4qudp1TMDqzxr6dcE8dAQXJxrK",
                        amount: 3333266667
                    },
                    Output {
                        address: "tmLmTTRLwYAsMWJgKWVW14echT89pYztU7u",
                        amount: 3333266666
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "0400008085202f8901bf1898c93f669e5a535a0460d86542c77a31e309aaaccabac47d265ff5f24cd7010000006b4830450221009b69008f53a9970c2f5c771b76462773baf18a2937cbc70af4dad9d7987fd13e022038a3d14301c657172759885a5e2e65d5c10b3208e6120cb819d66f56fae3c09401210332d388288132f696b4a75b2d2f40ccbd9a463d32e3c6c335f671df33f1a05973ffffffff03eb9cadc6000000001976a914418574564a7c48387a6557c491d14da904a4306c88aceb9cadc6000000001976a91475caaa31ae391da8121fe8d9577c30710bafc7f988acea9cadc6000000001976a914793fbe8ff3bae86202ad600fd60b86f59981b0c988ac0000000036cc08000000000000000000000000"
            },
            Transaction { //19a785b82a42c160ad954183ec3e8831b0c624c16d82408e293a4353a033c58a
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 576600,
                inputs: [
                    Input {
                        private_key: "cN2PtrZdZrZmoxgsg7fKcJPLGPX4sHDaZaNBsiRZQbQyC7kxAGxb",
                        address_format: Format::P2PKH,
                        transaction_id: "22da774bc331dad798ffdf1a18b1ad984ce4255ed5f687fcd44e6609624727fc",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(3333266667),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    Input {
                        private_key: "cT9pKXC1KMMG6g8dsCUGEHj3J4xnxwfBEhyv1ALs6Z6Ly9XH4qvj",
                        address_format: Format::P2PKH,
                        transaction_id: "22da774bc331dad798ffdf1a18b1ad984ce4255ed5f687fcd44e6609624727fc",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(3333266667),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER,
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "tmLmTTRLwYAsMWJgKWVW14echT89pYztU7u",
                        amount: 1666500000
                    },
                    Output {
                        address: "tmAgmYQnL7fnHvBHJExK2oZXrJBnkRfcq5f",
                        amount: 5000000000
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "0400008085202f8902fc27476209664ed4fc87f6d55e25e44c98adb1181adfff98d7da31c34b77da22000000006b483045022100ea49efe4132ce18d039cb2abe99ea52163611c25a35a8640a4bb15a88c93b60402202f7d4334bccd8f961d1becfd08bccdc1c0669533810cbbbfa5837f99ba94a7fe0121024aed9637c78499154afc06af10b2344233b3c968f1e7b1cfd9905fc38e440c12fffffffffc27476209664ed4fc87f6d55e25e44c98adb1181adfff98d7da31c34b77da22010000006a47304402203576c518c1f628469efcd182fa7d1d578cccdf7b51a41e44d119ca0c010747cc022069d9f390735567efff5e8f70afec6595060a79693540d6174b21681b21b4df70012102e49919f81e1fc11a65283e71dcce22dc65271f4ab6ef96f9e9b3d20fd62d1e87ffffffff02a0c55463000000001976a914793fbe8ff3bae86202ad600fd60b86f59981b0c988ac00f2052a010000001976a9140aab8113729e010d852820561dbee87459ad8dc888ac0000000058cc08000000000000000000000000"
            },
            Transaction { //fb6b95e4b3f7d1125fe81f4235dd156b12fb1553fc204fd22b4db200e54ddb5c
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 576600,
                inputs: [
                    Input {
                        private_key: "cR6NQzn89sCdRj1WmgQxF4mGJWi4bbgqzTDpmSfhmMQ2tfJCTPDF",
                        address_format: Format::P2PKH,
                        transaction_id: "d74cf2f55f267dc4bacaacaa09e3317ac74265d860045a535a9e663fc99818bf",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(10000000000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    Input {
                        private_key: "cUSFcxAXwFkLVciaxm7Le3mZF3g1nX5MZsxwDs23sCwWgUekfd18",
                        address_format: Format::P2PKH,
                        transaction_id: "22da774bc331dad798ffdf1a18b1ad984ce4255ed5f687fcd44e6609624727fc",
                        index: 2,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(3333266666),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    Input {
                        private_key: "cUSFcxAXwFkLVciaxm7Le3mZF3g1nX5MZsxwDs23sCwWgUekfd18",
                        address_format: Format::P2PKH,
                        transaction_id: "19a785b82a42c160ad954183ec3e8831b0c624c16d82408e293a4353a033c58a",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(1666500000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    Input {
                        private_key: "cMjLTdEgp48viTAL5eFXxaEpdj7jBJAg8ehw114BjBiZdUbCJLCr",
                        address_format: Format::P2PKH,
                        transaction_id: "19a785b82a42c160ad954183ec3e8831b0c624c16d82408e293a4353a033c58a",
                        index: 1,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(5000000000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                ],
                outputs: [
                    Output {
                        address: "tmFCcsdkr247okCfD61PBpzkP1GmkS7Zk6h",
                        amount: 19999500000
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "0400008085202f8904bf1898c93f669e5a535a0460d86542c77a31e309aaaccabac47d265ff5f24cd7000000006a47304402203f44fdfa0abb604a0b123fc95b4b0ad97bf535c9b2f9c2e37440a5627eabc6b902206c533152ba2efd78c16136f108847d8ea60e571f4dd7cbb47a5df582011cb3920121037517903ed1fafb50ab557970fc2d1948eaf88ad807308cc1fd50a63ca5f2d4d9fffffffffc27476209664ed4fc87f6d55e25e44c98adb1181adfff98d7da31c34b77da22020000006b48304502210089fe440a2b97bd12ad09c21cf4b3c811cddd17917fb5f4b84ec3fafa3c8ce26b022029e1bc2385d291eef1591775a73a77c5891afcfcf020a58c4fa35fb7d2995d280121020ef8f4c3fe101f3f47900c30423aeabfda7d502050c7067292afa5d971205b40ffffffff8ac533a053433a298e40826dc124c6b031883eec834195ad60c1422ab885a719000000006b483045022100d3c08145d11226c24acba293943f649b6acced719eaba5eee168705faa060046022077a220546a4654ee8bf14217da8c5dae9c64160b424be83557b24b79fb7b22400121020ef8f4c3fe101f3f47900c30423aeabfda7d502050c7067292afa5d971205b40ffffffff8ac533a053433a298e40826dc124c6b031883eec834195ad60c1422ab885a719010000006b483045022100a2649c5a237ac25db15ada343ea331865b9544a5ac32752c7800d3296085665602206c1722f0a3b0533f047e06ec2931fbe9dc9f6c01f4f1391fa02421369f8e4952012103b485498fb0843a5a058f251d7094fe8d2878faba8c17e7b3bbf854adb855a377ffffffff01e02610a8040000001976a9143c314002f07cf5ff5c84da1d9b456671b915bf8588ac0000000058cc08000000000000000000000000"
            },
            Transaction { // 35562b33fe8d03e0dcd9a2dd62154f3abdfcd7d29d61dcff0a09c1eb18a8f7ea
                header: 2147483652,
                version_group_id: 0x892F2085,
                lock_time: 0,
                expiry_height: 499999999,
                inputs: [
                    Input {
                        private_key: "cRi5RmG4fRjydFToBr1Z1FgD3jhCdmrsLs7WHn46ZVstPrKzwVHS",
                        address_format: Format::P2PKH,
                        transaction_id: "fb6b95e4b3f7d1125fe81f4235dd156b12fb1553fc204fd22b4db200e54ddb5c",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: Some(19999500000),
                        sequence: Some([0xff, 0xff, 0xff, 0xff]),
                        sig_hash_code: SigHashCode::SIGHASH_ALL
                    },
                    INPUT_FILLER,
                    INPUT_FILLER,
                    INPUT_FILLER
                ],
                outputs: [
                    Output {
                        address: "tmXYJ4cPwLTNYgs6y9tZxJJNC9sBiNDto7e",
                        amount: 1000010000
                    },
                    Output {
                        address: "tmEJE9sBgQfm2g3qXk4tZoWbhLkJmfxf6y7",
                        amount: 1000010000
                    },
                    Output {
                        address: "tmAuJ3R6tmb3mb8n1ps9DTNHatgYagaZpMd",
                        amount: 1000010000
                    },
                    Output {
                        address: "tmQQSuLgnnymA1FEo81Z32ng8JDu9q7zEnh",
                        amount: 1000010000
                    },
                    Output {
                        address: "tmEQbGRRVoFWFRqdPE7qCJXgeWBWV5vmcyF",
                        amount: 15999450000
                    },
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER
                ],
                sapling_inputs: [
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                    SAPLING_INPUT_FILLER,
                ],
                sapling_outputs: [
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                    OUTPUT_FILLER,
                ],
                expected_signed_transaction: "0400008085202f89015cdb4de500b24d2bd24f20fc5315fb126b15dd35421fe85f12d1f7b3e4956bfb000000006b483045022100e0095db90aca41ff28eea19d9e7e99a776e31b842d8bebf16856313153e2ac5c02205c4842046b790f45a3cdb12cc57e0a32539df8108f2f0849d19c037b69fce44101210324518c52cb40b86c8e8ed345c434af290835b18dc9ac6e1e060c86d040ee9a5cffffffff0510f19a3b000000001976a914ef6be120406ad9306214d50dca65604d20c6377c88ac10f19a3b000000001976a9143248a77a3b917a2aec9f9f2c4da147ec0abf61af88ac10f19a3b000000001976a9140d09f4b898d3f87efb7c17d20e48d78cdff9fd8288ac10f19a3b000000001976a914a1270cf4c1141c65312bcc4c0c1d681d389405be88ac903ba4b9030000001976a914337cc6354d31515f291b90a9a01b4911aecda5a788ac00000000ff64cd1d0000000000000000000000"
            },
        ];

        #[test]
        fn test_real_testnet_transactions() {
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
                    pruned_inputs,
                    pruned_outputs,
                    transaction.expected_signed_transaction,
                );
            });
        }
    }

    mod test_invalid_transparent_transactions {
        use super::*;
        type N = Mainnet;

        const INVALID_INPUTS: [Input; 4] = [
            Input {
                private_key: "KwNJ5ppQ1wCbXdpW5GBoxcBex1avA99cBFgBvgH16rf5pmBLu6WX",
                address_format: Format::P2PKH,
                transaction_id: "61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d",
                index: 0,
                redeem_script: None,
                script_pub_key: Some("0000000000"),
                utxo_amount: None,
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sig_hash_code: SigHashCode::SIGHASH_ALL,
            },
            Input {
                private_key: "KxyXFjrX9FjFX3HWWbRNxBrfZCRmD8A5kG31meyXtJDRPXrCXufK",
                address_format: Format::P2PKH,
                transaction_id: "7dabce",
                index: 0,
                redeem_script: None,
                script_pub_key: Some("a914e39b100350d6896ad0f572c9fe452fcac549fe7b87"),
                utxo_amount: Some(10000),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sig_hash_code: SigHashCode::SIGHASH_ALL,
            },
            Input {
                private_key: "KxyXFjrX9FjFX3HWWbRNxBrfZCRmD8A5kG31meyXtJDRPXrCXufK",
                address_format: Format::P2PKH,
                transaction_id: "7dabce",
                index: 0,
                redeem_script: None,
                script_pub_key: Some("000014ff3e3ce0fc1febf95e0e0eac49a205ad04a7d47688ac"),
                utxo_amount: Some(10000),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sig_hash_code: SigHashCode::SIGHASH_ALL,
            },
            INPUT_FILLER,
        ];

        const INVALID_OUTPUTS: [Output; 5] = [
            Output {
                address: "ABCD",
                amount: 100,
            },
            Output {
                address: "INVALID ADDRESS",
                amount: 12345,
            },
            Output {
                address: "0xE345828db876E265Dc2cea04c6b16F62021841A1",
                amount: 100000,
            },
            Output {
                address: "t1Z2Jwhs5D4vmYgH5MDgSATADnGqrjeRy",
                amount: 5,
            },
            OUTPUT_FILLER,
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
                        let invalid_input = ZcashTransactionInput::<N>::new(
                            address,
                            transaction_id,
                            input.index,
                            input.utxo_amount,
                            redeem_script,
                            script_pub_key,
                            sequence,
                            input.sig_hash_code,
                        );
                        assert!(invalid_input.is_err());
                    }
                    _ => assert!(private_key.is_err()),
                }
            }
        }

        #[test]
        fn test_invalid_outputs() {
            for output in INVALID_OUTPUTS.iter() {
                let invalid_output = ZcashTransactionOutput::<N>::new(output.address, output.amount);
                assert!(invalid_output.is_err());
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
