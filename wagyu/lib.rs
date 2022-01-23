#![warn(unused_extern_crates, dead_code)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate failure;

pub extern crate wagyu_bitcoin as bitcoin;
pub extern crate wagyu_ethereum as ethereum;
pub extern crate wagyu_model as model;
pub extern crate wagyu_monero as monero;
pub extern crate wagyu_zcash as zcash;
pub extern crate wagyu_tron as tron;

#[cfg_attr(tarpaulin, skip)]
pub mod cli;
