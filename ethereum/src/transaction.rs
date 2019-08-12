use crate::address::EthereumAddress;
use crate::public_key::EthereumPublicKey;
use crate::private_key::EthereumPrivateKey;

use ethereum_types::U256;
use rlp::RlpStream;
use secp256k1;
use std::{marker::PhantomData, str::FromStr};
use tiny_keccak::keccak256;
use wagyu_model::{Transaction, TransactionError};

/// Represents a raw Ethereum transaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransaction {
    /// Ethereum account nonce
    pub nonce: U256,
    /// Transaction gas price in wei
    pub gas_price: U256,
    /// Transaction gas limit
    pub gas: U256,
    /// Transaction destination address
    pub to: Vec<u8>,
    /// Transaction transfer amount
    pub value: U256,
    /// Transaction data
    pub data: Vec<u8>,
}

/// Represents an Ethereum transaction signature
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct EthereumTransactionSignature {
    /// The V field of the signature protected with a chain_id
    v: Vec<u8>,
    /// The R field of the signature
    r: Vec<u8>,
    /// The S field of the signature
    s: Vec<u8>,
}

/// Represents an Ethereum transaction output
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransactionOutput {
    /// Signed transaction output
    pub signed_transaction: String,
    /// Hash of the signed transaction
    pub transaction_hash: String,
}

impl Transaction for EthereumTransaction {
    type Address = EthereumAddress;
    type Format = PhantomData<u8>;
    type PrivateKey = EthereumPrivateKey;
    type PublicKey = EthereumPublicKey;
}

impl EthereumTransaction {
    /// Generate a raw Ethereum transaction
    pub fn new(nonce: &str, gas_price: &str, gas: &str, to: &str, value: &str, data: &str) -> Result<Self, TransactionError> {
        Ok(
            Self {
                nonce: U256::from_dec_str(nonce)?,
                gas_price: U256::from_dec_str(gas_price)?,
                gas: U256::from_dec_str(gas)?,
                to: hex::decode(&EthereumAddress::from_str(to)?.to_string()[2..])?,
                value: U256::from_dec_str(value)?,
                data: data.as_bytes().to_vec()
            }
        )
    }

    /// Sign the transaction with a given private key and output the encoded signature
    pub fn sign_transaction(&self, private_key: <Self as Transaction>::PrivateKey, chain_id: u8) -> Result<EthereumTransactionOutput, TransactionError> {
        if chain_id == 0 {
            return Err(TransactionError::InvalidChainId(chain_id));
        }

        let signature = Self::ecdsa_sign(
            &self.raw_transaction_hash(chain_id),
            private_key,
            &chain_id
        )?;

        let mut signed_transaction_rlp = RlpStream::new();
        signed_transaction_rlp.begin_list(9);
        self.encode_transaction_rlp(&mut signed_transaction_rlp);
        signed_transaction_rlp.append(&signature.v);
        signed_transaction_rlp.append(&signature.r);
        signed_transaction_rlp.append(&signature.s);

        let signed_transaction_bytes= signed_transaction_rlp.as_raw();
        let signed_transaction = format!("0x{}", &hex::encode(signed_transaction_bytes));
        let transaction_hash = format!("0x{}", &hex::encode(keccak256(signed_transaction_bytes)));

        Ok(EthereumTransactionOutput { signed_transaction, transaction_hash })
    }

    /// Encode the transactions using the Recursive Length Prefix format
    /// https://github.com/ethereum/wiki/wiki/RLP
    fn encode_transaction_rlp (&self, transaction_rlp: &mut RlpStream) {
        transaction_rlp.append(&self.nonce);
        transaction_rlp.append(&self.gas_price);
        transaction_rlp.append(&self.gas);
        transaction_rlp.append(&self.to);
        transaction_rlp.append(&self.value);
        transaction_rlp.append(&self.data);
    }

    /// Generate the raw transaction hash
    fn raw_transaction_hash(&self, chain_id: u8) -> Vec<u8> {
        let mut transaction_rlp = RlpStream::new();
        transaction_rlp.begin_list(9);
        self.encode_transaction_rlp(&mut transaction_rlp);
        transaction_rlp.append(&chain_id);
        transaction_rlp.append(&0u8);
        transaction_rlp.append(&0u8);

        keccak256(&transaction_rlp.as_raw()).into_iter().cloned().collect()
    }

    /// Sign the transaction hash with a given private key
    fn ecdsa_sign(hash: &[u8], private_key: <Self as Transaction>::PrivateKey, chain_id: &u8) -> Result<EthereumTransactionSignature, TransactionError> {
        let message = secp256k1::Message::from_slice(hash)?;
        let (v, signature) = secp256k1::Secp256k1::new().sign_recoverable(&message, &private_key.to_secp256k1_secret_key()).serialize_compact();
        let protected_v = vec![(v.to_i32() as u8 + chain_id * 2 + 35)]; // EIP155

        Ok (
            EthereumTransactionSignature {
                v: protected_v,
                r: signature[0..32].to_vec(),
                s: signature[32..64].to_vec(),
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub struct Transaction {
        pub nonce: &'static str,
        pub gas_price: &'static str,
        pub gas: &'static str,
        pub to: &'static str,
        pub value: &'static str,
        pub data: &'static str,
        pub chain_id: u8,
        pub private_key: &'static str,
        pub signed_transaction: &'static str,
        pub transaction_hash: &'static str,
    }

    const TRANSACTIONS: [Transaction; 4] = [
        Transaction {
            nonce: "0",
            gas_price: "1000000000",
            gas: "21000",
            to: "0xB5D590A6aBf5E349C1b6C511Bc87CEAbFB3D7e65",
            value: "1000000000000000000",
            data: "",
            chain_id: 1 as u8,
            private_key: "51ce358ffdcf208fadfb01a339f3ab715a89045a093777a44784d9e215277c1c",
            signed_transaction: "0xf86b80843b9aca0082520894b5d590a6abf5e349c1b6c511bc87ceabfb3d7e65880de0b6b3a76400008026a0e19742af3c215eca3b0391ab9edbf3cbad726a18c5209388ebdcccda028197baa034ec566c3d7bf23441873205a7abd6f5c37996a1a3889cdb83ecc20b14f9dcc3",
            transaction_hash: "0x03efc01e0ba13750867f4b04381f533409b4f5eb4b905cb33202d6c6612f0793"
        },
        Transaction {
            nonce: "0",
            gas_price: "41000000000",
            gas: "40000",
            to: "0xa554952EEBBC85464F32B7b470F5B7077df4f7e2",
            value: "0",
            data: "Transaction 1",
            chain_id: 3 as u8,
            private_key: "51ce358ffdcf208fadfb01a339f3ab715a89045a093777a44784d9e215277c1c",
            signed_transaction: "0xf8718085098bca5a00829c4094a554952eebbc85464f32b7b470f5b7077df4f7e2808d5472616e73616374696f6e203129a086541fe081eb1a77cb14545fce6d9324c82dab0e1e62dd994662c3f3798ddce9a018be7c3a8aeb32e06d479ec2b17d398239589f3aa6f1896479c12fa8499754a1",
            transaction_hash: "0x145f0d0303ac319911044ff7fb708f23a0a7814c7bcadcec94fb7dbc74f76fff"
        },
        Transaction {
            nonce: "11",
            gas_price: "2000000000",
            gas: "100000",
            to: "0x52C3a8a79a521D10b25569847CB1a3FfB66550D6",
            value: "5000000000000000000",
            data: "Test Data",
            chain_id: 4 as u8,
            private_key: "763459f13c14e02490e71590fe0ebb43cd8758c4adc9fb4bc084b0a798f557e7",
            signed_transaction: "0xf8750b8477359400830186a09452c3a8a79a521d10b25569847cb1a3ffb66550d6884563918244f40000895465737420446174612ba0d2751ac5bc52917575ffb4354fbb9bf0fd339d9eabd3dc5f016b0f695c848afaa014e76c21d60dde6b2452db6bd16d97201ec89ffdfe3c9930646f843220cd99ae",
            transaction_hash: "0x437c266938314b6816014922202efb22a467fa87c8af40ae3d871cadac3de11e"
        },
        Transaction {
            nonce: "12345",
            gas_price: "2000000000",
            gas: "54000",
            to: "0x52C3a8a79a521D10b25569847CB1a3FfB66550D6",
            value: "1000000000000000000000",
            data: "Send 1000 ETH",
            chain_id: 1 as u8,
            private_key: "6cff516706e4eef887c3906f279efa86ac2eeb669b1a2a9f009e85c362fb640c",
            signed_transaction: "0xf87b823039847735940082d2f09452c3a8a79a521d10b25569847cb1a3ffb66550d6893635c9adc5dea000008d53656e6420313030302045544825a0c13bfa13ac09b33ebaf846c9f134633fe03d94b4a3b5b94a6266158740064744a04963f584f3e96c51dc1800b35781e97990771d767766fc5dd5d8913ec2e0858b",
            transaction_hash: "0x862e6475238f7ac42747fcc88373be739b60699563eb80b70a69f11409933761"
        },
    ];

    #[test]
    fn test_valid_transactions() {
        TRANSACTIONS.iter().for_each(|transaction| {
            let tx = EthereumTransaction::new(
                transaction.nonce,
                transaction.gas_price,
                transaction.gas,
                transaction.to,
                transaction.value,
                transaction.data
            ).unwrap();

            let tx_output = tx.sign_transaction(
                EthereumPrivateKey::from_str(transaction.private_key).unwrap(),
                transaction.chain_id
            ).unwrap();

            assert_eq!(transaction.signed_transaction, tx_output.signed_transaction);
            assert_eq!(transaction.transaction_hash, tx_output.transaction_hash);
        });
    }

    #[test]
    fn invalid_output_address() {
        let nonce = "1";
        let gas_price = "1000000000";
        let gas = "21000";
        let value = "1000000000000000000";
        let data = "invalid output addresses";

        let to = "";
        assert!(EthereumTransaction::new(nonce, gas_price, gas, to, value, data).is_err());

        let to = "0x";
        assert!(EthereumTransaction::new(nonce, gas_price, gas, to, value, data).is_err());

        let to = "0x0";
        assert!(EthereumTransaction::new(nonce, gas_price, gas, to, value, data).is_err());

        let to = "invalid address";
        assert!(EthereumTransaction::new(nonce, gas_price, gas, to, value, data).is_err());

        let to = "0x3f9bcf82";
        assert!(EthereumTransaction::new(nonce, gas_price, gas, to, value, data).is_err());

        let to = "0x3f9bcf82295DbB7";
        assert!(EthereumTransaction::new(nonce, gas_price, gas, to, value, data).is_err());

        let to = "0x3f9bcf82295DbB7d192aFA481D1B20dDa042";
        assert!(EthereumTransaction::new(nonce, gas_price, gas, to, value, data).is_err());
    }

    #[test]
    fn invalid_chain_id() {
        TRANSACTIONS.iter().for_each(|transaction| {
            let chain_id: u8 = 0;
            let tx = EthereumTransaction::new(
                transaction.nonce,
                transaction.gas_price,
                transaction.gas,
                transaction.to,
                transaction.value,
                transaction.data
            ).unwrap();

            assert!(tx.sign_transaction(EthereumPrivateKey::from_str(transaction.private_key).unwrap(), chain_id).is_err());
        });
    }
}