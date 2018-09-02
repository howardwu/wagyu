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
    /// private view key
    pub private_view_key: String,
    /// public spend key
    pub public_spend_key: String,
    /// public view key
    pub public_view_key: String,
}

impl MoneroWallet {
    /// Generates a new MoneroWallet for a given `network`
    pub fn new(network: &Network) -> Result<MoneroWallet> {
        let mut seed = [0; 32];
        rand_bytes(&mut seed[..])?;

        let mut ctx = BigNumContext::new()?;

        println!("seed {:?}", format!("{:x}", 68));

        let spend_keypair = keypair_from_bytes(seed, &mut ctx)?;
        let view_keypair = {
            let mut buffer = keccak256(spend_keypair.private.as_ref());
            keypair_from_bytes(buffer, &mut ctx)?
        };

        let address =
            MoneroWallet::generate_address(&network, &spend_keypair.public, &view_keypair.public)?;

        Ok(MoneroWallet {
            address,
            private_spend_key: HexSlice::new(spend_keypair.private.as_ref()).format(),
            private_view_key: HexSlice::new(view_keypair.private.as_ref()).format(),
            public_spend_key: HexSlice::new(spend_keypair.public.as_ref()).format(),
            public_view_key: HexSlice::new(view_keypair.public.as_ref()).format(),
        })
    }

    /// Generates a MoneroWallet for a given `network` from a seed.
    pub fn from_seed(network: &Network, seed: [u8; 32]) -> Result<MoneroWallet> {
        let mut ctx = BigNumContext::new()?;

        let spend_keypair = keypair_from_bytes(seed, &mut ctx)?;
        let view_keypair = {
            let mut buffer = keccak256(spend_keypair.private.as_ref());
            keypair_from_bytes(buffer, &mut ctx)?
        };

        let address =
            MoneroWallet::generate_address(&network, &spend_keypair.public, &view_keypair.public)?;

        Ok(MoneroWallet {
            address,
            private_spend_key: HexSlice::new(spend_keypair.private.as_ref()).format(),
            private_view_key: HexSlice::new(view_keypair.private.as_ref()).format(),
            public_spend_key: HexSlice::new(spend_keypair.public.as_ref()).format(),
            public_view_key: HexSlice::new(view_keypair.public.as_ref()).format(),
        })
    }

    /// Generate the Cryptonote wallet address from the two public keys
    /// reference: https://gitlab.com/standard-mining/wallet-gen/blob/master/src/cryptonote.rs
    pub fn generate_address(
        network: &Network,
        spend_key: &PublicKey,
        view_key: &PublicKey,
    ) -> Result<String> {
        let mut bytes = ArrayVec::<[u8; 72]>::new();

        // Add coin prefix
        match get_prefix(&network) {
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

    /// returns view private key
    pub fn private_view_key(&self) -> &String {
        &self.private_view_key
    }
    /// returns spend public key
    pub fn public_spend_key(&self) -> &String {
        &self.public_spend_key
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
        ",
            self.address(),
            self.private_spend_key(),
            self.private_view_key()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_new_wallet() {
        println!("Monero {:?}", MoneroWallet::new(&Network::Mainnet).unwrap())
    }

    #[test]
    fn test_from_seed() {
        let seed = [
            68, 49, 179, 87, 16, 197, 157, 230, 143, 50, 126, 44, 68, 63, 140, 252, 55, 165, 0, 21,
            89, 117, 205, 207, 77, 189, 251, 141, 193, 131, 96, 54,
        ];

        let wallet = MoneroWallet::from_seed(&Network::Mainnet, seed).unwrap();

        assert_eq!(
            &wallet.address,
            "444SttAXhqVUeqCpPiTTwHcYTGpApapxjgsBzqSxWANvfmxGHJTLTTE6JgYM6yYNjmGBrGLhsVu8ZJh6RnFP8yqM6F8Lmb1");
        assert_eq!(
            &wallet.private_spend_key,
            "7db5d140c19b66de0c5c9743a851efbd37a500155975cdcf4dbdfb8dc1836006",
        );
        assert_eq!(
            &wallet.private_view_key,
            "2d4f19ff6f2a2b2e918996e7ebbbabba791c29120ceb66518a4f232f3a88e30a",
        );
        assert_eq!(
            &wallet.public_spend_key,
            "404e19168faffca55272b37aff9494d47e54fa7fd6ed34ee56db492a057953e7",
        );
        assert_eq!(
            &wallet.public_view_key,
            "d22475de8a58511fb7362dc18fc79c5acc2848cbd73cc669c4e93811465e4c2e",
        );
    }
}
