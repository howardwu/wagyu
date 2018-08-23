//! # Monero
//!
//! A library for generating Monero Wallets.
// extern crate base58;
// extern crate arrayvec;
// extern crate base58;
// extern crate digest;
// extern crate either;

// extern crate openssl;
// extern crate rand;
// extern crate safemem;
// extern crate tiny_keccak;
// #[macro_use]
// extern crate lazy_static;

#![deny(missing_debug_implementations, missing_docs)]
#![warn(missing_docs)]
#![allow(unknown_lints)]

//! A Rust library to generate various cryptocurrency wallets.
//!
//! Enable the `serde` feature to add `#[derive(Serialize, Deserialize)]`
//! to structures and naming to [`Coin`].
//!
//! [`Coin`]: coin/enum.Coin.html

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


// pub mod address;
pub mod builder;
pub mod ed25519;
pub mod error;
pub mod network;
pub mod prelude;
// pub mod privatekey;
// pub mod utils;
pub mod wallet;
pub mod hex_slice;
