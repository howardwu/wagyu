//! Monero Wallet generator
use network::{get_prefix, Network};

use std::fmt;

use super::prelude::*;
use arrayvec::ArrayVec;
use base58::ToBase58;
use ed25519::{keypair_from_bytes, PublicKey};
use hex_slice::HexSlice;
use openssl::bn::BigNumContext;
use openssl::rand::rand_bytes;
use tiny_keccak::keccak256;

/// Represents Monero keypairs
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MoneroWallet {
    /// public monero address
    pub address: String,
    /// private spend key
    pub private_spend_key: String,
    /// public spend key
    pub public_spend_key: String,
    /// private view key
    pub private_view_key: String,
    /// public view key
    pub public_view_key: String,
}

impl MoneroWallet {
    /// Generates a new MoneroWallet for a given `network`
    pub fn new(network: Network) -> Result<MoneroWallet> {
        let mut seed = [0; 32];
        rand_bytes(&mut seed[..])?;

        let mut ctx = BigNumContext::new()?;

        let spend_keypair = keypair_from_bytes(seed, &mut ctx)?;
        let view_keypair = {
            let mut buffer = keccak256(spend_keypair.private.as_ref());
            keypair_from_bytes(buffer, &mut ctx)?
        };

        let address =
            MoneroWallet::generate_address(network, &spend_keypair.public, &view_keypair.public)?;

        Ok(MoneroWallet {
            address: address,
            private_spend_key: HexSlice::new(spend_keypair.private.as_ref()).format(),
            public_spend_key: HexSlice::new(spend_keypair.public.as_ref()).format(),
            private_view_key: HexSlice::new(view_keypair.private.as_ref()).format(),
            public_view_key: HexSlice::new(view_keypair.public.as_ref()).format(),
        })
    }

    /// Generates a MoneroWallet for a given `network` from a seed.
    pub fn from_seed(network: Network, seed: [u8; 32]) -> Result<MoneroWallet> {
        let mut ctx = BigNumContext::new()?;

        let spend_keypair = keypair_from_bytes(seed, &mut ctx)?;
        let view_keypair = {
            let mut buffer = keccak256(spend_keypair.private.as_ref());
            keypair_from_bytes(buffer, &mut ctx)?
        };

        let address =
            MoneroWallet::generate_address(network, &spend_keypair.public, &view_keypair.public)?;

        Ok(MoneroWallet {
            address: address,
            private_spend_key: HexSlice::new(spend_keypair.private.as_ref()).format(),
            public_spend_key: HexSlice::new(spend_keypair.public.as_ref()).format(),
            private_view_key: HexSlice::new(view_keypair.private.as_ref()).format(),
            public_view_key: HexSlice::new(view_keypair.public.as_ref()).format(),
        })
    }

    /// Generate the Cryptonote wallet address from the two public keys
    /// reference: https://gitlab.com/standard-mining/wallet-gen/blob/master/src/cryptonote.rs
    pub fn generate_address(
        network: Network,
        spend_key: &PublicKey,
        view_key: &PublicKey,
    ) -> Result<String> {
        let mut bytes = ArrayVec::<[u8; 72]>::new();

        // Add coin prefix
        match get_prefix(network) {
            Some(prefix) => bytes.extend(prefix.iter().cloned()),
            None => panic!("Invalid prefix"), // make more descriptive
        };

        // Add public keys
        bytes.extend(spend_key.iter().cloned());
        bytes.extend(view_key.iter().cloned());

        // Add checksum
        let hash = &keccak256(bytes.as_slice())[..4];
        bytes.extend(hash.iter().cloned());

        // Convert to base58 in 8 byte chunks
        let mut base58 = String::new();
        for chunk in bytes.as_slice().chunks(8) {
            let mut part = chunk.to_base58();
            let exp_len = match chunk.len() {
                8 => 11,
                6 => 9,
                5 => 7,
                _ => panic!("Invalid chunk length: {}", chunk.len()),
            };
            let missing = exp_len - part.len();
            if missing > 0 {
                part.insert_str(0, &"11111111111"[..missing]);
            }
            base58.push_str(&part);
        }

        Ok(base58)
    }

    /// returns public address
    pub fn address(&self) -> &String {
        &self.address
    }

    /// returns spend private key
    pub fn private_spend_key(&self) -> &String {
        &self.private_spend_key
    }

    /// returns spend public key
    pub fn public_spend_key(&self) -> &String {
        &self.public_spend_key
    }

    /// returns view private key
    pub fn private_view_key(&self) -> &String {
        &self.private_view_key
    }

    /// returns view public key
    pub fn public_view_key(&self) -> &String {
        &self.public_view_key
    }

    // pub fn to_json(&self) -> String {
    //     to_string_pretty(&self).unwrap()
    // }
}

impl fmt::Display for MoneroWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "
        Address:              {}
        Private Spend Key:    {}
        Private View Key:     {}
        -- OPTIONAL --
        Public Spend Key:     {}
        Public View Key:      {}
        -- OPTIONAL --
        ",
            self.address(),
            self.private_spend_key(),
            self.private_view_key(),
            self.public_spend_key(),
            self.public_view_key()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_new_wallet() {
        println!("Monero {:?}", MoneroWallet::new(Network::Mainnet).unwrap())
    }

    // #[test]
    // fn test_from_seed() {

    //     let seed = [
    //         0xbd, 0xb2, 0x5d, 0x9d, 0x7b, 0xdb, 0xda, 0x38, 0x97, 0xf6, 0xc9, 0x42, 0x7a, 0xd6, 0x57,
    //         0xd1, 0x56, 0x75, 0xa9, 0x4a, 0x06, 0xf0, 0xdb, 0x66, 0xb9, 0xb0, 0x53, 0xb0, 0xb2, 0x78,
    //         0xa8, 0x00,
    //     ];

    // // bdb25d9d7bdbda3897f6c9427ad657d15675a94a06f0db66b9b053b0b278a800

    //     let wallet = MoneroWallet::from_seed(Network::Mainnet, seed).unwrap();

    //     assert_eq!(
    //         &wallet.address,
    //         "4B5hMDhQyxb3aCpo7aQjrN8WCVfW3fRZwYGwDiMYBuHdPSfxSxxk5PG7arpdLpLi91N8ozt129c4w2vxhfQURRP8JQHmbvi");
    //     assert_eq!(
    //         &wallet.public_spend_key,
    //         "f99782b370c9100f613e341bf2577f2cdc28d6a3795e86bafabcc0cd3fb05486",
    //     );
    //     assert_eq!(
    //         &wallet.private_spend_key,
    //         "bdb25d9d7bdbda3897f6c9427ad657d15675a94a06f0db66b9b053b0b278a800",
    //     );
    //     assert_eq!(
    //         &wallet.public_view_key,
    //         "2cf5e093e437e3275ca066fdf27fdc7e5b1ae7c6fe98600b8a72dc213294b39a",
    //     );
    //     assert_eq!(
    //         &wallet.private_view_key,
    //         "afc9d176516ecbe8cc6b4bc0efea956b1f0c3ffede0ddd919a8486b143a09d0d",
    //     );
    // }
}
