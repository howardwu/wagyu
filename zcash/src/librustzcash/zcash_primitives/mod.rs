pub mod keys;
pub mod zip32;

use crate::librustzcash::sapling_crypto::jubjub::JubjubBls12;

lazy_static! {
    pub static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}
