//! # Ethereum
//!
//! A library for generating Ethereum Wallets.
#[macro_use]
extern crate serde_derive;
extern crate tiny_keccak;

pub mod address;
pub mod builder;
pub mod keypair;
pub mod utils;
pub mod wallet;
