#[cfg_attr(tarpaulin, skip)]
pub mod algebra;
#[cfg_attr(tarpaulin, skip)]
pub mod sapling_crypto;
#[cfg_attr(tarpaulin, skip)]
pub mod zip32;

use crate::librustzcash::sapling_crypto::jubjub::JubjubBls12;

lazy_static! {
    pub static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}
