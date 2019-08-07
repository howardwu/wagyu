//use crate::address::{MoneroAddress, Format};
//use crate::network::MoneroNetwork;
//use crate::private_key::MoneroPrivateKey;
//use crate::public_key::MoneroPublicKey;
//use wagyu_model::{PrivateKey, TransactionError, Transaction};
//
///// Represents a Monero transaction
//pub struct MoneroTransaction<N: MoneroNetwork> {
//    /// Transaction format version
//    /// Unix timestamp
//    /// Transaction inputs
//    /// Transaction outputs
//    /// Extra field: transaction public key or additional public keys
//    /// MLSAG signatures
//    /// RingCT (Bulletproof) signatures
//}
//
///// Represents a Monero transaction input
//pub struct MoneroTransactionInput<N: MoneroNetwork> {
//    /// Block height of where the coinbase transaction is included
//    /// A key input from a key output
//    /// Input from script output
//    /// Input from script hash output
//}
//
///// Represents a Monero transaction output
//pub struct MoneroTransactionOutput<N: MoneroNetwork> {
//    /// Output to script
//    /// Output to one-time public key
//    /// Output to script hash
//}
//
//impl <N: MoneroNetwork> Transaction for MoneroTransaction<N> {
//    type Address = MoneroAddress<N>;
//    type Format = Format;
//    type PrivateKey = MoneroPrivateKey<N>;
//    type PublicKey = MoneroPublicKey<N>;
//}