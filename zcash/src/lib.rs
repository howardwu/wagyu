//! # Bitcoin
//!
//! A library for generating Bitcoin Wallets.
#[macro_use]
extern crate serde_derive;
pub mod address;
pub mod builder;
pub mod network;
pub mod privatekey;
pub mod utils;
pub mod wallet;
