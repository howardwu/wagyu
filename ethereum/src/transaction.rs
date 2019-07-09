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
    // Transaction gas limit
    pub gas: U256,
    // Transaction destination address
    pub to: Vec<u8>,
    // Transaction transfer amount
    pub value: U256,
    // Transaction data
    pub data: Vec<u8>
}

// Represents an Ethereum transaction signature
struct TransactionSignature {
    // The V field of the signature protected with a chain_id
    v: Vec<u8>,
    // The R field of the signature
    r: Vec<u8>,
    // The S field of the signature
    s: Vec<u8>,
}

// Represents an Ethereum transaction output
pub struct TransactionOutput {
    // Signed transaction output
    pub signed_transaction: String,
    // Hash of the signed transaction
    pub transaction_hash: String
}

impl Transaction {
    // Generate a raw Ethereum transaction
    pub fn new(nonce: &str, gas_price: &str, gas: &str, to: &str, value: &str, data: &str) -> Self {
        let nonce = Self::str_to_u256(nonce);
        let gas_price = Self::str_to_u256(gas_price);
        let gas = Self::str_to_u256(gas);
        let to = hex::decode(&to[2..]).unwrap();
        let value = Self::str_to_u256(value);
        let data = data.as_bytes().to_vec();

        Self { nonce, gas_price, gas, to, value, data }
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
    pub fn raw_transaction_hash(&self, chain_id: u8) -> Result<Vec<u8>, &'static str> {
        if (chain_id == 0) {
            return Err("invalid chain_id");
        }

        let mut transaction_rlp = RlpStream::new();
        transaction_rlp.begin_unbounded_list();
        self.encode_transaction_rlp(&mut transaction_rlp);
        transaction_rlp.append(&chain_id);
        transaction_rlp.append(&U256::zero());
        transaction_rlp.append(&U256::zero());
        transaction_rlp.complete_unbounded_list();

        Ok( keccak256(&transaction_rlp.as_raw()).into_iter().cloned().collect())
    }

    // Sign the transaction with a given private key and output the encoded signature
    pub fn sign_transaction(&self, private_key: &str, chain_id: u8) -> Result<TransactionOutput, &'static str> {
        if (chain_id == 0) {
            return Err("invalid chain_id");
        }

        let hash = self.raw_transaction_hash(chain_id).unwrap();
        let ethereum_private_key = EthereumPrivateKey::from(private_key);
        if(ethereum_private_key.is_err()) {
            return Err("invalid private key");
        }

        let signature = Self::ecdsa_sign(&hash, ethereum_private_key.unwrap(), &chain_id);
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

        Ok(TransactionOutput { signed_transaction, transaction_hash })
    }

    // Sign the transaction hash with a given private key
    fn ecdsa_sign(hash: &[u8], private_key: EthereumPrivateKey, chain_id: &u8) -> TransactionSignature {
        let signing_key = private_key.secret_key;
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

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSACTIONS: [(&str, &str, &str, &str, &str, &str, u8, &str, &str, &str); 4] = [
        (
            // Nonce
            "0",
            // Gas Price
            "1000000000",
            // Gas
            "21000",
            // To
            "0xB5D590A6aBf5E349C1b6C511Bc87CEAbFB3D7e65",
            // Value
            "1000000000000000000",
            // Data
            "",
            // Chain_id
            1 as u8,
            // Private Key
            "51ce358ffdcf208fadfb01a339f3ab715a89045a093777a44784d9e215277c1c",
            // Signed Transaction
            "0xf86b80843b9aca0082520894b5d590a6abf5e349c1b6c511bc87ceabfb3d7e65880de0b6b3a76400008026a0e19742af3c215eca3b0391ab9edbf3cbad726a18c5209388ebdcccda028197baa034ec566c3d7bf23441873205a7abd6f5c37996a1a3889cdb83ecc20b14f9dcc3",
            // Transaction Hash
            "0x03efc01e0ba13750867f4b04381f533409b4f5eb4b905cb33202d6c6612f0793"
        ),
        (
            // Nonce
            "0",
            // Gas Price
            "41000000000",
            // Gas
            "40000",
            // To
            "0xa554952EEBBC85464F32B7b470F5B7077df4f7e2",
            // Value
            "0",
            // Data
            "Transaction 1",
            // Chain_id
            3 as u8,
            // Private Key
            "51ce358ffdcf208fadfb01a339f3ab715a89045a093777a44784d9e215277c1c",
            // Signed Transaction
            "0xf8718085098bca5a00829c4094a554952eebbc85464f32b7b470f5b7077df4f7e2808d5472616e73616374696f6e203129a086541fe081eb1a77cb14545fce6d9324c82dab0e1e62dd994662c3f3798ddce9a018be7c3a8aeb32e06d479ec2b17d398239589f3aa6f1896479c12fa8499754a1",
            // Transaction Hash
            "0x145f0d0303ac319911044ff7fb708f23a0a7814c7bcadcec94fb7dbc74f76fff"
        ),
        (
            // Nonce
            "11",
            // Gas Price
            "2000000000",
            // Gas
            "100000",
            // To
            "0x52C3a8a79a521D10b25569847CB1a3FfB66550D6",
            // Value
            "5000000000000000000",
            // Data
            "Test Data",
            // Chain_id
            4 as u8,
            // Private Key
            "763459f13c14e02490e71590fe0ebb43cd8758c4adc9fb4bc084b0a798f557e7",
            // Signed Transaction
            "0xf8750b8477359400830186a09452c3a8a79a521d10b25569847cb1a3ffb66550d6884563918244f40000895465737420446174612ba0d2751ac5bc52917575ffb4354fbb9bf0fd339d9eabd3dc5f016b0f695c848afaa014e76c21d60dde6b2452db6bd16d97201ec89ffdfe3c9930646f843220cd99ae",
            // Transaction Hash
            "0x437c266938314b6816014922202efb22a467fa87c8af40ae3d871cadac3de11e"
        ),
        (
            // Nonce
            "12345",
            // Gas Price
            "2000000000",
            // Gas
            "54000",
            // To
            "0x52C3a8a79a521D10b25569847CB1a3FfB66550D6",
            // Value
            "1000000000000000000000",
            // Data
            "Send 1000 ETH",
            // Chain_id
            1 as u8,
            // Private Key
            "6cff516706e4eef887c3906f279efa86ac2eeb669b1a2a9f009e85c362fb640c",
            // Signed Transaction
            "0xf87b823039847735940082d2f09452c3a8a79a521d10b25569847cb1a3ffb66550d6893635c9adc5dea000008d53656e6420313030302045544825a0c13bfa13ac09b33ebaf846c9f134633fe03d94b4a3b5b94a6266158740064744a04963f584f3e96c51dc1800b35781e97990771d767766fc5dd5d8913ec2e0858b",
            // Transaction Hash
            "0x862e6475238f7ac42747fcc88373be739b60699563eb80b70a69f11409933761"
        )
    ];

    #[test]
    fn test_transactions() {
        TRANSACTIONS.iter().for_each(|(
                                          nonce,
                                          gas_price,
                                          gas,
                                          to,
                                          value,
                                          data,
                                          chain_id,
                                          private_key,
                                          signed_transaction,
                                          transaction_hash
                                      )| {
            let tx = Transaction::new(nonce, gas_price, gas, to, value, data);
            let tx_output = tx.sign_transaction(private_key, *chain_id).unwrap();

            assert_eq!(*signed_transaction, tx_output.signed_transaction);
            assert_eq!(*transaction_hash, tx_output.transaction_hash);
        });
    }

    #[test]
    fn invalid_chain_id() {
        TRANSACTIONS.iter().for_each(|(
                                          nonce,
                                          gas_price,
                                          gas,
                                          to,
                                          value,
                                          data,
                                          chain_id,
                                          private_key,
                                          signed_transaction,
                                          transaction_hash
                                      )| {
            let chain_id: u8 = 0;
            let tx = Transaction::new(nonce, gas_price, gas, to, value, data);
            let tx_output = tx.sign_transaction(private_key, chain_id);
            assert!( tx_output.is_err());
        });
    }

    #[test]
    fn invalid_private_key() {
        TRANSACTIONS.iter().for_each(|(
                                          nonce,
                                          gas_price,
                                          gas,
                                          to,
                                          value,
                                          data,
                                          chain_id,
                                          private_key,
                                          signed_transaction,
                                          transaction_hash
                                      )| {
            let private_key = "DEADBEEF";
            let tx = Transaction::new(nonce, gas_price, gas, to, value, data);
            let tx_output = tx.sign_transaction(private_key, *chain_id);
            assert!( tx_output.is_err());
        });
    }
}