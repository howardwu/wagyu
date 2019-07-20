//! # Mnemonic
//!
//! A library for generating mnemonic seed phrases.

#![forbid(unsafe_code)]

pub mod language;
pub use self::language::*;

pub mod mnemonic;
pub use self::mnemonic::*;
