/*
 * ed25519/mod.rs
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

//! Modified ed25519 cryptography for use by Cryptonote.
//! Specifically, public-key calculation is performed using scalar multiplication
//! without using SHA512 at all.

mod crypto;
mod keys;

pub use self::keys::{Keypair, PrivateKey, PublicKey};

use super::prelude;
use super::prelude::*;
use openssl::bn::BigNumContextRef;

/// Creates an ed25519 [`Keypair`] from the given random seed.
///
/// [`Keypair`]: ./keys/struct.Keypair.html
pub fn keypair_from_bytes(bytes: [u8; 32], ctx: &mut BigNumContextRef) -> Result<Keypair> {
    let priv_key = PrivateKey::from_bytes(bytes, ctx)?;
    let pub_key = PublicKey::from_private(&priv_key, ctx)?;

    Ok(Keypair {
        public: pub_key,
        private: priv_key,
    })
}
