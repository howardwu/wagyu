use crate::private_key::EthereumPrivateKey;

use tiny_keccak::keccak256;
use secp256k1::Secp256k1;
use rlp::RlpStream;
use ethereum_types::U256;


/// Represents a raw Ethereum transaction
pub struct Transaction {
    // Ethereum account nonce
    pub nonce: U256,
    // Transaction gas price in wei
    pub gas_price: U256,
    // Transaction gas limit in wei
    pub gas: U256,
    // Transaction destination address
    pub to: Vec<u8>,
    // Transaction transfer amount
    pub value: U256,
    // Transaction data
    pub data: Vec<u8>
}

struct TransactionSignature {
    // The V field of the signature protected with a chain_id
    v: Vec<u8>,
    // The R field of the signature
    r: Vec<u8>,
    // The S field of the signature
    s: Vec<u8>,
}

pub struct TransactionOutput {
    pub signed_transaction: String,
    pub transaction_hash: String
}

impl Transaction {

    // Generates a raw Ethereum transaction
    pub fn new(nonce: &str, gas_price: &str, gas: &str, to: &str, value: &str, data: &str) -> Self {
        let nonce = Self::str_to_u256(nonce);
        let gas_price = Self::str_to_u256(gas_price);
        let gas = Self::str_to_u256(gas);
        let to = hex::decode(&to[2..]).unwrap();
        let value = Self::str_to_u256(value);
        let data = data.as_bytes().to_vec();

        Self { nonce, gas_price, gas, to, value, data}
    }

    // Generate a Recursive Length Prefix encoding from the raw transaction
    pub fn encode_transaction_rlp (&self, transaction_rlp: &mut RlpStream) {
        transaction_rlp.append(&self.nonce);
        transaction_rlp.append(&self.gas_price);
        transaction_rlp.append(&self.gas);
        transaction_rlp.append(&self.to);
        transaction_rlp.append(&self.value);
        transaction_rlp.append(&self.data);
    }

    // Generate the raw transaction hash
    pub fn raw_transaction_hash(&self, chain_id: u8) -> Vec<u8> {
        let mut transaction_rlp = RlpStream::new();
        transaction_rlp.begin_unbounded_list();
        self.encode_transaction_rlp(&mut transaction_rlp);
        transaction_rlp.append(&chain_id);
        transaction_rlp.append(&U256::zero());
        transaction_rlp.append(&U256::zero());
        transaction_rlp.complete_unbounded_list();

        keccak256(&transaction_rlp.as_raw()).into_iter().cloned().collect()
    }

    // Sign the transaction with a given private key and output the encoded signature
    pub fn sign_transaction(&self, private_key: &str, chain_id: u8) -> TransactionOutput {
        let hash = self.raw_transaction_hash(chain_id);
        let signature = Self::ecdsa_sign(&hash, private_key, &chain_id);
        let mut signed_transaction_rlp = RlpStream::new();
        signed_transaction_rlp.begin_unbounded_list();
        self.encode_transaction_rlp(&mut signed_transaction_rlp);
        signed_transaction_rlp.append(&signature.v);
        signed_transaction_rlp.append(&signature.r);
        signed_transaction_rlp.append(&signature.s);
        signed_transaction_rlp.complete_unbounded_list();

        let signed_transaction_bytes= signed_transaction_rlp.as_raw();
        let mut signed_transaction= "0x".to_owned();
        let mut transaction_hash = "0x".to_owned();
        signed_transaction.push_str(&hex::encode(signed_transaction_bytes));
        transaction_hash.push_str(&hex::encode(keccak256(signed_transaction_bytes)));

        TransactionOutput { signed_transaction, transaction_hash }
    }

    // Sign the transaction hash with a given private key
    fn ecdsa_sign(hash: &[u8], private_key: &str, chain_id: &u8) -> TransactionSignature {
        let ethereum_private_key = EthereumPrivateKey::from(private_key).unwrap();
        let signing_key = ethereum_private_key.secret_key;
        let message = secp256k1::Message::from_slice(hash).unwrap();
        let s = Secp256k1::signing_only();

        let (v, sig_bytes) = s.sign_recoverable(&message, &signing_key).serialize_compact(&s);
        let protected_v = Self::chain_replay_protection(v.to_i32() as u8, chain_id);

        TransactionSignature {
            v: protected_v,
            r: sig_bytes[0..32].to_vec(),
            s: sig_bytes[32..64].to_vec(),
        }
    }

    // Convert integer strings into U246
    fn str_to_u256(s: &str) -> U256 {
        U256::from_dec_str(s).unwrap()
    }

    // Apply chain replay protection - EIP155
    fn chain_replay_protection(v: u8, chain_id: &u8) -> Vec<u8> {
        let protected_v = v + chain_id * 2 + 35;
        vec![protected_v]
    }
}
