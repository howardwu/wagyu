//! # Monero
//!
//! A library for generating Monero wallets.
#![warn(unused_extern_crates)]
//#![forbid(unsafe_code)] must comment this out to make call to external static c library

//#[link(name = "serial_bridge_index.cpp")]
//extern "C" {
//    fn send_step1__prepare_params_for_get_decoys();
//}

//#[no_mangle]
//pub extern fn echo() {
//    println!("Hello Back! Echo");
//}


pub mod address;
pub use self::address::*;

pub mod mnemonic;
pub use self::mnemonic::*;

pub mod network;
pub use self::network::*;

pub mod one_time_key;
pub use self::one_time_key::*;

pub mod private_key;
pub use self::private_key::*;

pub mod public_key;
pub use self::public_key::*;

pub mod transaction;
pub use self::transaction::*;

pub mod wordlist;
pub use self::wordlist::*;
