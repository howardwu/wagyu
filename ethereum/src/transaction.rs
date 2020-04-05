use crate::address::EthereumAddress;
use crate::amount::EthereumAmount;
use crate::format::EthereumFormat;
use crate::network::EthereumNetwork;
use crate::private_key::EthereumPrivateKey;
use crate::public_key::EthereumPublicKey;
use wagyu_model::{PrivateKey, PublicKey, Transaction, TransactionError, TransactionId};

use ethereum_types::U256;
use rlp::{decode_list, RlpStream};
use secp256k1;
use std::{fmt, marker::PhantomData, str::FromStr};
use tiny_keccak::keccak256;

pub fn to_bytes(value: u32) -> Result<Vec<u8>, TransactionError> {
    match value {
        // bounded by u8::max_value()
        0..=255 => Ok(vec![value as u8]),
        // bounded by u16::max_value()
        256..=65535 => Ok((value as u16).to_le_bytes().to_vec()),
        // bounded by u32::max_value()
        _ => Ok(value.to_le_bytes().to_vec()),
    }
}

pub fn from_bytes(value: &Vec<u8>) -> Result<u32, TransactionError> {
    match value.len() {
        0 => Ok(0u32),
        1 => Ok(u32::from_le_bytes([value[0], 0, 0, 0])),
        2 => Ok(u32::from_le_bytes([value[0], value[1], 0, 0])),
        3 => Ok(u32::from_le_bytes([value[0], value[1], value[2], 0])),
        4 => Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]])),
        _ => Err(TransactionError::Message(
            "invalid byte length for u32 value".to_string(),
        )),
    }
}

/// Represents the parameters for an Ethereum transaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransactionParameters {
    /// The address of the receiver
    pub receiver: EthereumAddress,
    /// The amount (in wei)
    pub amount: EthereumAmount,
    /// The transaction gas limit
    pub gas: U256,
    /// The transaction gas price in wei
    pub gas_price: EthereumAmount,
    /// The nonce of the Ethereum account
    pub nonce: U256,
    /// The transaction data
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

/// Represents an Ethereum transaction id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransactionId {
    pub txid: Vec<u8>,
}

impl TransactionId for EthereumTransactionId {}

impl fmt::Display for EthereumTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", &hex::encode(&self.txid))
    }
}

/// Represents an Ethereum transaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumTransaction<N: EthereumNetwork> {
    /// The address of the sender
    sender: Option<EthereumAddress>,
    /// The transaction parameters (gas, gas_price, nonce, data)
    parameters: EthereumTransactionParameters,
    /// The transaction signature
    signature: Option<EthereumTransactionSignature>,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: EthereumNetwork> Transaction for EthereumTransaction<N> {
    type Address = EthereumAddress;
    type Format = EthereumFormat;
    type PrivateKey = EthereumPrivateKey;
    type PublicKey = EthereumPublicKey;
    type TransactionId = EthereumTransactionId;
    type TransactionParameters = EthereumTransactionParameters;

    /// Returns an unsigned transaction given the transaction parameters.
    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            sender: None,
            parameters: parameters.clone(),
            signature: None,
            _network: PhantomData,
        })
    }

    /// Returns a signed transaction given the private key of the sender.
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
    fn sign(&self, private_key: &Self::PrivateKey) -> Result<Self, TransactionError> {
        match (&self.sender, &self.signature) {
            (Some(_), Some(_)) => Ok(self.clone()),
            (Some(_), None) | (None, Some(_)) => Err(TransactionError::InvalidTransactionState),
            (None, None) => {
                let (signature, v) = secp256k1::sign(
                    &secp256k1::Message::parse_slice(&self.to_transaction_id()?.txid)?,
                    &private_key.to_secp256k1_secret_key(),
                );
                let signature = signature.serialize();

                let mut transaction = self.clone();
                transaction.sender = Some(private_key.to_address(&EthereumFormat::Standard)?);
                transaction.signature = Some(EthereumTransactionSignature {
                    v: to_bytes(Into::<i32>::into(v) as u32 + N::CHAIN_ID * 2 + 35)?, // EIP155
                    r: signature[0..32].to_vec(),
                    s: signature[32..64].to_vec(),
                });
                Ok(transaction)
            }
        }
    }

    /// Returns a transaction given the transaction bytes.
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
    fn from_transaction_bytes(transaction: &Vec<u8>) -> Result<Self, TransactionError> {
        let list: Vec<Vec<u8>> = decode_list(&transaction);
        if list.len() != 9 {
            return Err(TransactionError::InvalidRlpLength(list.len()));
        }

        let parameters = EthereumTransactionParameters {
            receiver: EthereumAddress::from_str(&hex::encode(&list[3]))?,
            amount: match list[4].is_empty() {
                true => EthereumAmount::from_u256(U256::zero()),
                false => EthereumAmount::from_u256(U256::from(list[4].as_slice())),
            },
            gas: match list[2].is_empty() {
                true => U256::zero(),
                false => U256::from(list[2].as_slice()),
            },
            gas_price: match list[1].is_empty() {
                true => EthereumAmount::from_u256(U256::zero()),
                false => EthereumAmount::from_u256(U256::from(list[1].as_slice())),
            },
            nonce: match list[0].is_empty() {
                true => U256::zero(),
                false => U256::from(list[0].as_slice()),
            },
            data: list[5].clone(),
        };

        match list[7].is_empty() && list[8].is_empty() {
            true => {
                // Raw transaction
                Ok(Self {
                    sender: None,
                    parameters,
                    signature: None,
                    _network: PhantomData,
                })
            }
            false => {
                // Signed transaction
                let v = from_bytes(&list[6])?;
                let recovery_id = secp256k1::RecoveryId::parse((v - N::CHAIN_ID * 2 - 35) as u8)?;
                let mut signature = list[7].clone();
                signature.extend_from_slice(&list[8]);

                let raw_transaction = Self {
                    sender: None,
                    parameters: parameters.clone(),
                    signature: None,
                    _network: PhantomData,
                };
                let message = secp256k1::Message::parse_slice(&raw_transaction.to_transaction_id()?.txid)?;
                let public_key = EthereumPublicKey::from_secp256k1_public_key(
                    secp256k1::recover(&message, &secp256k1::Signature::parse_slice(signature.as_slice())?, &recovery_id)?,
                );

                Ok(Self {
                    sender: Some(public_key.to_address(&EthereumFormat::Standard)?),
                    parameters,
                    signature: Some(EthereumTransactionSignature {
                        v: list[6].clone(),
                        r: list[7].clone(),
                        s: list[8].clone(),
                    }),
                    _network: PhantomData,
                })
            }
        }
    }

    /// Returns the transaction in bytes.
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
    fn to_transaction_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        // Returns an encoded transaction in Recursive Length Prefix (RLP) format.
        // https://github.com/ethereum/wiki/wiki/RLP
        fn encode_transaction(
            transaction_rlp: &mut RlpStream,
            parameters: &EthereumTransactionParameters,
        ) -> Result<(), TransactionError> {
            transaction_rlp.append(&parameters.nonce);
            transaction_rlp.append(&parameters.gas_price.0);
            transaction_rlp.append(&parameters.gas);
            transaction_rlp.append(&hex::decode(&parameters.receiver.to_string()[2..])?);
            transaction_rlp.append(&parameters.amount.0);
            transaction_rlp.append(&parameters.data);
            Ok(())
        }

        // Returns the raw transaction (in RLP).
        fn raw_transaction<N: EthereumNetwork>(
            parameters: &EthereumTransactionParameters,
        ) -> Result<RlpStream, TransactionError> {
            let mut transaction_rlp = RlpStream::new();
            transaction_rlp.begin_list(9);
            encode_transaction(&mut transaction_rlp, parameters)?;
            transaction_rlp.append(&to_bytes(N::CHAIN_ID)?);
            transaction_rlp.append(&0u8);
            transaction_rlp.append(&0u8);
            Ok(transaction_rlp)
        }

        // Returns the signed transaction (in RLP).
        fn signed_transaction(
            parameters: &EthereumTransactionParameters,
            signature: &EthereumTransactionSignature,
        ) -> Result<RlpStream, TransactionError> {
            let mut transaction_rlp = RlpStream::new();
            transaction_rlp.begin_list(9);
            encode_transaction(&mut transaction_rlp, parameters)?;
            transaction_rlp.append(&signature.v);
            transaction_rlp.append(&signature.r);
            transaction_rlp.append(&signature.s);
            Ok(transaction_rlp)
        }

        match &self.signature {
            Some(signature) => Ok(signed_transaction(&self.parameters, signature)?.out()),
            None => Ok(raw_transaction::<N>(&self.parameters)?.out()),
        }
    }

    /// Returns the hash of the signed transaction, if the signature is present.
    /// Otherwise, returns the hash of the raw transaction.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        Ok(Self::TransactionId {
            txid: keccak256(&self.to_transaction_bytes()?).iter().cloned().collect(),
        })
    }
}

impl<N: EthereumNetwork> FromStr for EthereumTransaction<N> {
    type Err = TransactionError;

    fn from_str(transaction: &str) -> Result<Self, Self::Err> {
        Self::from_transaction_bytes(&hex::decode(transaction)?)
    }
}

impl<N: EthereumNetwork> fmt::Display for EthereumTransaction<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "0x{}",
            &hex::encode(match self.to_transaction_bytes() {
                Ok(transaction) => transaction,
                _ => return Err(fmt::Error),
            })
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::EthereumNetwork;
    use crate::{Goerli, Kovan, Mainnet, Rinkeby, Ropsten};
    use wagyu_model::{PrivateKey, Transaction};

    pub struct TransactionTestCase {
        pub nonce: &'static str,
        pub gas_price: &'static str,
        pub gas: &'static str,
        pub to: &'static str,
        pub value: &'static str,
        pub data: &'static str,
        pub chain_id: u8,
        pub private_key: &'static str,
        pub signed_transaction: &'static str,
        pub signed_transaction_hash: &'static str,
    }

    fn test_new<N: EthereumNetwork>(transaction: &TransactionTestCase) {
        let expected_signed_transaction = transaction.signed_transaction;
        let expected_signed_transaction_hash = transaction.signed_transaction_hash;
        let private_key = EthereumPrivateKey::from_str(transaction.private_key).unwrap();
        let parameters = EthereumTransactionParameters {
            receiver: EthereumAddress::from_str(transaction.to).unwrap(),
            amount: EthereumAmount::from_wei(transaction.value).unwrap(),
            gas: U256::from_dec_str(transaction.gas).unwrap(),
            gas_price: EthereumAmount::from_wei(transaction.gas_price).unwrap(),
            nonce: U256::from_dec_str(transaction.nonce).unwrap(),
            data: transaction.data.as_bytes().to_vec(),
        };

        let transaction = EthereumTransaction::<N>::new(&parameters).unwrap();
        let signed_transaction = transaction.sign(&private_key).unwrap();
        assert_eq!(expected_signed_transaction, signed_transaction.to_string());
        assert_eq!(
            expected_signed_transaction_hash,
            signed_transaction.to_transaction_id().unwrap().to_string()
        );
    }

    fn test_sign<N: EthereumNetwork>(transaction: &TransactionTestCase) {
        let expected_signed_transaction = transaction.signed_transaction;
        let private_key = EthereumPrivateKey::from_str(transaction.private_key).unwrap();
        let parameters = EthereumTransactionParameters {
            receiver: EthereumAddress::from_str(transaction.to).unwrap(),
            amount: EthereumAmount::from_wei(transaction.value).unwrap(),
            gas: U256::from_dec_str(transaction.gas).unwrap(),
            gas_price: EthereumAmount::from_wei(transaction.gas_price).unwrap(),
            nonce: U256::from_dec_str(transaction.nonce).unwrap(),
            data: transaction.data.as_bytes().to_vec(),
        };

        let transaction = EthereumTransaction::<N>::new(&parameters).unwrap();
        let signed_transaction = transaction.sign(&private_key).unwrap();

        assert_eq!(None, transaction.sender);
        assert_eq!(
            private_key.to_address(&EthereumFormat::Standard).unwrap(),
            signed_transaction.sender.clone().unwrap()
        );

        assert_eq!(parameters, transaction.parameters);
        assert_eq!(expected_signed_transaction, signed_transaction.to_string());
    }

    fn test_from_transaction_bytes<N: EthereumNetwork>(transaction: &TransactionTestCase) {
        let private_key = EthereumPrivateKey::from_str(transaction.private_key).unwrap();
        let expected_sender = Some(private_key.to_address(&EthereumFormat::Standard).unwrap());
        let expected_parameters = EthereumTransactionParameters {
            receiver: EthereumAddress::from_str(transaction.to).unwrap(),
            amount: EthereumAmount::from_wei(transaction.value).unwrap(),
            gas: U256::from_dec_str(transaction.gas).unwrap(),
            gas_price: EthereumAmount::from_wei(transaction.gas_price).unwrap(),
            nonce: U256::from_dec_str(transaction.nonce).unwrap(),
            data: transaction.data.as_bytes().to_vec(),
        };
        let signed_transaction_bytes = hex::decode(&transaction.signed_transaction[2..]).unwrap();

        let transaction = EthereumTransaction::<N>::from_transaction_bytes(&signed_transaction_bytes).unwrap();
        assert_eq!(expected_sender, transaction.sender);
        assert_eq!(expected_parameters, transaction.parameters);
        assert_eq!(signed_transaction_bytes, transaction.to_transaction_bytes().unwrap());
    }

    fn test_to_transaction_bytes<N: EthereumNetwork>(transaction: &TransactionTestCase) {
        let expected_signed_transaction_bytes = hex::decode(&transaction.signed_transaction[2..]).unwrap();
        let private_key = EthereumPrivateKey::from_str(transaction.private_key).unwrap();
        let parameters = EthereumTransactionParameters {
            receiver: EthereumAddress::from_str(transaction.to).unwrap(),
            amount: EthereumAmount::from_wei(transaction.value).unwrap(),
            gas: U256::from_dec_str(transaction.gas).unwrap(),
            gas_price: EthereumAmount::from_wei(transaction.gas_price).unwrap(),
            nonce: U256::from_dec_str(transaction.nonce).unwrap(),
            data: transaction.data.as_bytes().to_vec(),
        };

        let transaction = EthereumTransaction::<N>::new(&parameters).unwrap();
        let signed_transaction = transaction.sign(&private_key).unwrap();
        assert_eq!(
            expected_signed_transaction_bytes,
            signed_transaction.to_transaction_bytes().unwrap()
        );
    }

    fn test_to_transaction_id<N: EthereumNetwork>(transaction: &TransactionTestCase) {
        let expected_signed_transaction_hash = transaction.signed_transaction_hash;
        let private_key = EthereumPrivateKey::from_str(transaction.private_key).unwrap();
        let parameters = EthereumTransactionParameters {
            receiver: EthereumAddress::from_str(transaction.to).unwrap(),
            amount: EthereumAmount::from_wei(transaction.value).unwrap(),
            gas: U256::from_dec_str(transaction.gas).unwrap(),
            gas_price: EthereumAmount::from_wei(transaction.gas_price).unwrap(),
            nonce: U256::from_dec_str(transaction.nonce).unwrap(),
            data: transaction.data.as_bytes().to_vec(),
        };

        let transaction = EthereumTransaction::<N>::new(&parameters).unwrap();
        let signed_transaction = transaction.sign(&private_key).unwrap();
        assert_eq!(
            expected_signed_transaction_hash,
            signed_transaction.to_transaction_id().unwrap().to_string()
        );
    }

    fn test_to_string<N: EthereumNetwork>(transaction: &TransactionTestCase) {
        let expected_signed_transaction = transaction.signed_transaction;
        let private_key = EthereumPrivateKey::from_str(transaction.private_key).unwrap();
        let parameters = EthereumTransactionParameters {
            receiver: EthereumAddress::from_str(transaction.to).unwrap(),
            amount: EthereumAmount::from_wei(transaction.value).unwrap(),
            gas: U256::from_dec_str(transaction.gas).unwrap(),
            gas_price: EthereumAmount::from_wei(transaction.gas_price).unwrap(),
            nonce: U256::from_dec_str(transaction.nonce).unwrap(),
            data: transaction.data.as_bytes().to_vec(),
        };

        let transaction = EthereumTransaction::<N>::new(&parameters).unwrap();
        let signed_transaction = transaction.sign(&private_key).unwrap();
        assert_eq!(expected_signed_transaction, signed_transaction.to_string());
    }

    mod mainnet {
        use super::*;

        type N = Mainnet;

        const FAKE_TRANSACTIONS: [TransactionTestCase; 2] = [
            TransactionTestCase {
                nonce: "0",
                gas_price: "1000000000",
                gas: "21000",
                to: "0xB5D590A6aBf5E349C1b6C511Bc87CEAbFB3D7e65",
                value: "1000000000000000000",
                data: "",
                chain_id: Mainnet::CHAIN_ID as u8,
                private_key: "51ce358ffdcf208fadfb01a339f3ab715a89045a093777a44784d9e215277c1c",
                signed_transaction: "0xf86b80843b9aca0082520894b5d590a6abf5e349c1b6c511bc87ceabfb3d7e65880de0b6b3a76400008026a0e19742af3c215eca3b0391ab9edbf3cbad726a18c5209388ebdcccda028197baa034ec566c3d7bf23441873205a7abd6f5c37996a1a3889cdb83ecc20b14f9dcc3",
                signed_transaction_hash: "0x03efc01e0ba13750867f4b04381f533409b4f5eb4b905cb33202d6c6612f0793"
            },
            TransactionTestCase {
                nonce: "12345",
                gas_price: "2000000000",
                gas: "54000",
                to: "0x52C3a8a79a521D10b25569847CB1a3FfB66550D6",
                value: "1000000000000000000000",
                data: "Send 1000 ETH",
                chain_id: Mainnet::CHAIN_ID as u8,
                private_key: "6cff516706e4eef887c3906f279efa86ac2eeb669b1a2a9f009e85c362fb640c",
                signed_transaction: "0xf87b823039847735940082d2f09452c3a8a79a521d10b25569847cb1a3ffb66550d6893635c9adc5dea000008d53656e6420313030302045544825a0c13bfa13ac09b33ebaf846c9f134633fe03d94b4a3b5b94a6266158740064744a04963f584f3e96c51dc1800b35781e97990771d767766fc5dd5d8913ec2e0858b",
                signed_transaction_hash: "0x862e6475238f7ac42747fcc88373be739b60699563eb80b70a69f11409933761"
            },
        ];

        #[test]
        fn new() {
            FAKE_TRANSACTIONS.iter().for_each(test_new::<N>);
        }

        #[test]
        fn sign() {
            FAKE_TRANSACTIONS.iter().for_each(test_sign::<N>);
        }

        #[test]
        fn from_transaction_bytes() {
            FAKE_TRANSACTIONS.iter().for_each(test_from_transaction_bytes::<N>);
        }

        #[test]
        fn to_transaction_bytes() {
            FAKE_TRANSACTIONS.iter().for_each(test_to_transaction_bytes::<N>);
        }

        #[test]
        fn to_transaction_id() {
            FAKE_TRANSACTIONS.iter().for_each(test_to_transaction_id::<N>);
        }

        #[test]
        fn to_string() {
            FAKE_TRANSACTIONS.iter().for_each(test_to_string::<N>);
        }
    }

    mod rinkeby {
        use super::*;

        type N = Rinkeby;

        const FAKE_TRANSACTIONS: [TransactionTestCase; 1] = [
            TransactionTestCase {
                nonce: "11",
                gas_price: "2000000000",
                gas: "100000",
                to: "0x52C3a8a79a521D10b25569847CB1a3FfB66550D6",
                value: "5000000000000000000",
                data: "Test Data",
                chain_id: Rinkeby::CHAIN_ID as u8,
                private_key: "763459f13c14e02490e71590fe0ebb43cd8758c4adc9fb4bc084b0a798f557e7",
                signed_transaction: "0xf8750b8477359400830186a09452c3a8a79a521d10b25569847cb1a3ffb66550d6884563918244f40000895465737420446174612ba0d2751ac5bc52917575ffb4354fbb9bf0fd339d9eabd3dc5f016b0f695c848afaa014e76c21d60dde6b2452db6bd16d97201ec89ffdfe3c9930646f843220cd99ae",
                signed_transaction_hash: "0x437c266938314b6816014922202efb22a467fa87c8af40ae3d871cadac3de11e"
            },
        ];

        const REAL_TRANSACTIONS: [TransactionTestCase; 1] = [
            TransactionTestCase {
                nonce: "0",
                gas_price: "41000000000",
                gas: "21000",
                to: "0x4A6fF8173CeB9Ee12873C8b5D663c6044B08B04E",
                value: "199139000000000000",
                data: "",
                chain_id: Rinkeby::CHAIN_ID as u8,
                private_key: "3e5d0b2fd29b473b310ba4c84c14a77a1325a85494b7514ad77e201ff35367ee",
                signed_transaction: "0xf86c8085098bca5a00825208944a6ff8173ceb9ee12873c8b5d663c6044b08b04e8802c37bdd8bed3000802ba06cd94f2a28d4e695504b6cd2458761fe6d27726d251501320fff6dc4e113c960a028b2b5dc5979d0e0d5d7e8868b7cdc2a74d1d1bcacb8ba982ae6d55a9d540694",
                signed_transaction_hash: "0xa79ec2950c873c878d2a2ea77e38662c17e3f1ab254fa3704b0917e245e49549"
            },
        ];

        #[test]
        fn new() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_new::<N>);
        }

        #[test]
        fn sign() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_sign::<N>);
        }

        #[test]
        fn from_transaction_bytes() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_from_transaction_bytes::<N>);
        }

        #[test]
        fn to_transaction_bytes() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_transaction_bytes::<N>);
        }

        #[test]
        fn to_transaction_id() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_transaction_id::<N>);
        }

        #[test]
        fn to_string() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_string::<N>);
        }
    }

    mod ropsten {
        use super::*;

        type N = Ropsten;

        const FAKE_TRANSACTIONS: [TransactionTestCase; 1] = [
            TransactionTestCase {
                nonce: "0",
                gas_price: "41000000000",
                gas: "40000",
                to: "0xa554952EEBBC85464F32B7b470F5B7077df4f7e2",
                value: "0",
                data: "Transaction 1",
                chain_id: Ropsten::CHAIN_ID as u8,
                private_key: "51ce358ffdcf208fadfb01a339f3ab715a89045a093777a44784d9e215277c1c",
                signed_transaction: "0xf8718085098bca5a00829c4094a554952eebbc85464f32b7b470f5b7077df4f7e2808d5472616e73616374696f6e203129a086541fe081eb1a77cb14545fce6d9324c82dab0e1e62dd994662c3f3798ddce9a018be7c3a8aeb32e06d479ec2b17d398239589f3aa6f1896479c12fa8499754a1",
                signed_transaction_hash: "0x145f0d0303ac319911044ff7fb708f23a0a7814c7bcadcec94fb7dbc74f76fff"
            },
        ];

        const REAL_TRANSACTIONS: [TransactionTestCase; 1] = [
            TransactionTestCase {
                nonce: "0",
                gas_price: "99000000000",
                gas: "21000",
                to: "0x24130a9e027D89d5da3ef5F4eAb94b4c42f506de",
                value: "997921000000000000",
                data: "",
                chain_id: Ropsten::CHAIN_ID as u8,
                private_key: "da690842b1c8207b8c82940f6b50f8b83c4d8facdf604e0a323fb557e92d3141",
                signed_transaction: "0xf86c8085170cdc1e008252089424130a9e027d89d5da3ef5f4eab94b4c42f506de880dd953dcbee71000802aa0a4d67df068d7cbf24e8f4694284029bc18cdd6f3c2d8cfeea703eb596a623e64a03eae1d47f06fa9fa0edc5709ce8c0aa0c90c856a183289659853c80775d0e4a7",
                signed_transaction_hash: "0x1d1240fd80dd85aa8ccb0716ea156c70a2940e0f22fc8464abf0dce361c1829f"
            },
        ];

        #[test]
        fn new() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_new::<N>);
        }

        #[test]
        fn sign() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_sign::<N>);
        }

        #[test]
        fn from_transaction_bytes() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_from_transaction_bytes::<N>);
        }

        #[test]
        fn to_transaction_bytes() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_transaction_bytes::<N>);
        }

        #[test]
        fn to_transaction_id() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_transaction_id::<N>);
        }

        #[test]
        fn to_string() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_string::<N>);
        }
    }

    mod goerli {
        use super::*;

        type N = Goerli;

        const FAKE_TRANSACTIONS: [TransactionTestCase; 0] = [];
        const REAL_TRANSACTIONS: [TransactionTestCase; 1] = [
            TransactionTestCase {
                nonce: "0",
                gas_price: "20000000000",
                gas: "21000",
                to: "0x9Fd6441Ce8CC4524FaCd033921B6A2e910EC00FC",
                value: "49580000000000000",
                data: "",
                chain_id: Goerli::CHAIN_ID as u8,
                private_key: "72a5f407855ca5bd8e30fe390362cf15c85313a2269ce142ad8fe51ef5b4ac1e",
                signed_transaction: "0xf86b808504a817c800825208949fd6441ce8cc4524facd033921b6a2e910ec00fc87b024bf4ff6c000802da03b2a07447818c1f85ca0d28c819575fa2796f8633a7641ebe8aedc56e91a7bffa0330acba28c47630bf49f4d8b0e36f7c28aaa83672081d57adc56e80937f49977",
                signed_transaction_hash: "0x9683157f5d2a49ec36ecf93f0a18012db77b09e9dc0dc1f146fd3d42619d94a5"
            },
        ];

        #[test]
        fn new() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_new::<N>);
        }

        #[test]
        fn sign() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_sign::<N>);
        }

        #[test]
        fn from_transaction_bytes() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_from_transaction_bytes::<N>);
        }

        #[test]
        fn to_transaction_bytes() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_transaction_bytes::<N>);
        }

        #[test]
        fn to_transaction_id() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_transaction_id::<N>);
        }

        #[test]
        fn to_string() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_string::<N>);
        }
    }

    mod kovan {
        use super::*;

        type N = Kovan;

        const FAKE_TRANSACTIONS: [TransactionTestCase; 0] = [];
        const REAL_TRANSACTIONS: [TransactionTestCase; 1] = [
            TransactionTestCase {
                nonce: "0",
                gas_price: "35000000000",
                gas: "22496",
                to: "0xAf28B521C99D392eF50BD0cAd2A7e1A52F62184a",
                value: "999212640000000000",
                data: "Test Kovan Transaction",
                chain_id: Kovan::CHAIN_ID as u8,
                private_key: "a54c2d5b587df5cc529ef1f843cce324cb11201705328361b54421b0ba737883",
                signed_transaction: "0xf88280850826299e008257e094af28b521c99d392ef50bd0cad2a7e1a52f62184a880dddea9a1e47c0009654657374204b6f76616e205472616e73616374696f6e77a029d204aad100a463a5b19974775b7c05c07c534553cc930b7257edb66392c346a04bd016c3180a7cdeb41b05bd07ea6517e698f879695b1f5aeac3ce62e144f17f",
                signed_transaction_hash: "0x1e20b0d7a7d0db79753a3ad6ac14b0e76bd453bf19883d185b627a8cf2413f4d"
            },
        ];

        #[test]
        fn new() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_new::<N>);
        }

        #[test]
        fn sign() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_sign::<N>);
        }

        #[test]
        fn from_transaction_bytes() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_from_transaction_bytes::<N>);
        }

        #[test]
        fn to_transaction_bytes() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_transaction_bytes::<N>);
        }

        #[test]
        fn to_transaction_id() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_transaction_id::<N>);
        }

        #[test]
        fn to_string() {
            FAKE_TRANSACTIONS
                .iter()
                .chain(&REAL_TRANSACTIONS)
                .into_iter()
                .for_each(test_to_string::<N>);
        }
    }
}
