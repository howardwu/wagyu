//! Monero
//!
//! Enable the `serde` feature to add `#[derive(Serialize, Deserialize)]`
//!

#![deny(missing_debug_implementations, missing_docs)]
#![warn(missing_docs)]
#![allow(unknown_lints)]

extern crate arrayvec;
extern crate base58;
extern crate digest;
extern crate either;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
extern crate openssl;
extern crate safemem;
extern crate tiny_keccak;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;


pub mod builder;
pub mod ed25519;
pub mod error;
pub mod network;
pub mod prelude;
pub mod wallet;
pub mod hex_slice;
