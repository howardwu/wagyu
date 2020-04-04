//! # Bitcoin
//!
//! A library for generating Bitcoin wallets.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused_extern_crates, dead_code)]
#![forbid(unsafe_code)]

#[cfg(not(feature="std"))]
#[allow(unused_imports)]
#[doc(hidden)]
#[macro_use]
extern crate alloc;

#[macro_use]
extern crate failure;

mod no_std {
    #[cfg(not(feature = "std"))]
    #[doc(hidden)]
    pub use alloc::{format, string::String, string::ToString, vec, vec::Vec};

    #[cfg(feature = "std")]
    #[doc(hidden)]
    pub use std::{format, string::String, string::ToString, vec, vec::Vec};
}

pub mod address;
pub use self::address::*;

pub mod amount;
pub use self::amount::*;

pub mod derivation_path;
pub use self::derivation_path::*;

pub mod extended_private_key;
pub use self::extended_private_key::*;

pub mod extended_public_key;
pub use self::extended_public_key::*;

pub mod format;
pub use self::format::*;

pub mod mnemonic;
pub use self::mnemonic::*;

pub mod network;
pub use self::network::*;

pub mod private_key;
pub use self::private_key::*;

pub mod public_key;
pub use self::public_key::*;

pub mod transaction;
pub use self::transaction::*;

mod witness_program;

pub mod wordlist;
pub use self::wordlist::*;
