use crate::private_key::EthereumPrivateKey;

use tiny_keccak::keccak256;
use secp256k1::Secp256k1;
use rlp::RlpStream;
use ethereum_types::U256;


/// Represents a raw Ethereum transaction
pub struct Transaction {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub to: Vec<u8>,
    pub value: U256,
    pub data: Vec<u8>
}

pub struct TransactionSignature {
    v: Vec<u8>,
    r: Vec<u8>,
    s: Vec<u8>
}

impl Transaction {

    // Generates a raw Ethereum transaction
    fn new(nonce: &str, gas_price: &str, gas: &str, to: &str, value: &str, data: &str) -> Self {
        let nonce = Self::str_to_U256(nonce);
        let gas_price = Self::str_to_U256(gas_price);
        let gas = Self::str_to_U256(gas);
        let to = hex::decode(to).unwrap();
        let value = Self::str_to_U256(value);
        let data = data.as_bytes().to_vec();

        Self { nonce, gas_price, gas, to, value, data}
    }

    // Create a Recursive Length Prefix from the raw transaction
    fn encode_transaction_rlp (&self, stream: &mut RlpStream) {
        //Encode individual transaction attributes into RLP Type
        stream.append(&self.nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas);
        stream.append(&self.to);
        stream.append(&self.value);
        stream.append(&self.data);
    }

    pub fn raw_transaction_hash(&self, chain_id: u8) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        self.encode_transaction_rlp(&mut stream);
        stream.append(&chain_id);
        stream.append(&U256::zero());
        stream.append(&U256::zero());
        stream.complete_unbounded_list();

        keccak256(&stream.as_raw()).into_iter().cloned().collect()
    }

    pub fn sign_transaction(&self, private_key: &str, chain_id: u8) -> Vec<u8> {
        let hash = self.raw_transaction_hash(chain_id);
        let signature = ecdsa_sign(&hash, private_key, &chain_id);
        let mut signed_transaction = RlpStream::new();
        signed_transaction.begin_unbounded_list();
        self.encode_transaction_rlp(&mut signed_transaction);
        signed_transaction.append(&signature.v);
        signed_transaction.append(&signature.r);
        signed_transaction.append(&signature.s);
        signed_transaction.complete_unbounded_list();

        signed_transaction.as_raw().to_vec()
    }

    pub fn str_to_U256(s: &str) -> U256 {
        U256::from_dec_str(s).unwrap()
    }
}

pub fn ecdsa_sign(hash: &[u8], private_key_wif: &str, chain_id: &u8) -> TransactionSignature {
    let s = Secp256k1::signing_only();
    let msg = secp256k1::Message::from_slice(hash).unwrap();
    let ethPrivateKey = EthereumPrivateKey::from_wif(private_key_wif).unwrap();
    let key = ethPrivateKey.secret_key;
    let (v, sig_bytes) = s.sign_recoverable(&msg, &key).serialize_compact(&s);

    TransactionSignature {
        v: vec![v.to_i32() as u8 + chain_id * 2 + 35],
        r: sig_bytes[0..32].to_vec(),
        s: sig_bytes[32..64].to_vec(),
    }
}
