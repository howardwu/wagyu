use crate::address::EthereumAddress;
use model::address::Address;
use model::private_key::PrivateKey;
use model::public_key::PublicKey;
use crate::private_key::EthereumPrivateKey;
use crate::public_key::EthereumPublicKey;

use std::marker::PhantomData;

const PRIVATE_KEY_STR: &str = "208065a247edbe5df4d86fbdc0171303f23a76961be9f6013850dd2bdc759bbb";
const PUBLIC_KEY_STR: &str = "04836b35a026743e823a90a0ee3b91bf615c6a757e2b60b9e1dc1826fd0dd16106f7bc1e8179f665015f43c6c81f39062fc2086ed849625c06e04697698b21855e";
const ADDRESS_STR: &str = "0x0BED7ABd61247635c1973eB38474A2516eD1D884";

#[test]
fn ethereum_address_from_private_key() {
    let private_key = EthereumPrivateKey::from_wif(PRIVATE_KEY_STR).unwrap();
    let address =
        EthereumAddress::from_private_key(&private_key, &PhantomData);

    assert_eq!(address.to_string(), ADDRESS_STR);
}

#[test]
fn ethereum_address_from_public_key() {
    let public_key = ethereum_get_public_key();
    let address = EthereumAddress::from_public_key(&public_key, &PhantomData, &PhantomData);

    assert_eq!(address.to_string(), ADDRESS_STR);
}

#[test]
fn ethereum_private_key_to_public_key() {
    let private_key = ethereum_get_private_key();
    let public_key = EthereumPublicKey::from_private_key(&private_key);

    assert_eq!(public_key.to_string(), PUBLIC_KEY_STR);
}

#[test]
fn ethereum_private_key_to_address() {
    let private_key = ethereum_get_private_key();
    let address = private_key.to_address(&PhantomData);

    assert_eq!(address.to_string(), ADDRESS_STR);
}

#[test]
fn ethereum_public_key_from_private_key() {
    let private_key = ethereum_get_private_key();
    let public_key = EthereumPublicKey::from_private_key(&private_key);

    assert_eq!(public_key.to_string(), PUBLIC_KEY_STR);
}

#[test]
fn ethereum_public_key_to_address() {
    let public_key = ethereum_get_public_key();

    assert_eq!(public_key.to_address(&PhantomData, &PhantomData).to_string(), ADDRESS_STR);
}

// Utility functions for testing

fn ethereum_get_private_key() -> EthereumPrivateKey {
    let secret_key_bytes = hex::decode(PRIVATE_KEY_STR).unwrap();
    let secret_key =
        secp256k1::SecretKey::from_slice(&secp256k1::Secp256k1::new(), &secret_key_bytes).unwrap();

    EthereumPrivateKey {
        secret_key,
        wif: PRIVATE_KEY_STR.to_string(),
    }
}

fn ethereum_get_public_key() -> EthereumPublicKey {
    let public_key_bytes = hex::decode(PUBLIC_KEY_STR).unwrap();
    let public_key =
        secp256k1::PublicKey::from_slice(&secp256k1::Secp256k1::new(), &public_key_bytes).unwrap();

    EthereumPublicKey { public_key }
}
