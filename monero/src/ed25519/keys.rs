/*
 * ed25519/keys.rs
 *
 * Copyright 2018 Standard Mining
 *
 * Available to be used and modified under the terms of the MIT License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use super::prelude::*;
use ed25519::crypto::{bn_to_vec32, derive_pubkey, sc_reduce32};
use openssl::bn::BigNumContextRef;
use std::ops::Deref;

/// An ed25519 private key.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PrivateKey([u8; 32]);

impl PrivateKey {
    /// Generate a private key from the given seed. The byte data will be converted
    /// to a valid private ed25519 key.
    pub fn from_bytes(mut bytes: [u8; 32], ctx: &mut BigNumContextRef) -> Result<Self> {
        let bn = sc_reduce32(&mut bytes, ctx)?;
        let vec = bn_to_vec32(&bn);

        {
            let dest = &mut bytes[..];
            dest.copy_from_slice(vec.as_slice());
        }

        Ok(PrivateKey(bytes))
    }

    /// Converts this private key into an array of its bytes
    #[inline]
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Gets a copy of this private key's bytes
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Gets a reference to the internally stored private key bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Deref for PrivateKey {
    type Target = [u8; 32];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for PrivateKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

/// An ed25519 public key.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Calculates the ed25519 public key from the given private key.
    pub fn from_private(priv_key: &PrivateKey, ctx: &mut BigNumContextRef) -> Result<Self> {
        let mut bytes = priv_key.to_bytes();
        derive_pubkey(&mut bytes, ctx)?;
        Ok(PublicKey(bytes))
    }

    /// Converts this public key into an array of its bytes
    #[inline]
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Gets a copy of this public key's bytes
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Gets a reference to the internally stored public key bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Deref for PublicKey {
    type Target = [u8; 32];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

/// A ed25519 keypair, containing both a private and public part.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Keypair {
    /// The public key.
    pub public: PublicKey,

    /// The private key.
    pub private: PrivateKey,
}
