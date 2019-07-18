//!
//! WitnessProgram
//!
//! This module contains the representation of a Bitcoin witness program and utility functions
//! related to the representation of such programs.
//!
//! If the version byte is 0, and the witness program is 20 bytes:
//! - It is interpreted as a pay-to-witness-public-key-hash (P2WPKH) program.
//! - The witness must consist of exactly 2 items (≤ 520 bytes each). The first one a signature, and the second one a public key.
//! - The HASH160 of the public key must match the 20-byte witness program.
//! - After normal script evaluation, the signature is verified against the public key with CHECKSIG operation. The verification must result in a single TRUE on the stack.
//!
//! If the version byte is 0, and the witness program is 32 bytes:
//! - It is interpreted as a pay-to-witness-script-hash (P2WSH) program.
//! - The witness must consist of an input stack to feed to the script, followed by a serialized script (witnessScript).
//! - The witnessScript (≤ 10,000 bytes) is popped off the initial witness stack. SHA256 of the witnessScript must match the 32-byte witness program.
//! - The witnessScript is deserialized, and executed after normal script evaluation with the remaining witness stack (≤ 520 bytes for each stack item).
//! - The script must not fail, and result in exactly a single TRUE on the stack.
//!
//! If the version byte is 0, but the witness program is neither 20 nor 32 bytes, the script must fail.
//!

use std::fmt;
use std::str::FromStr;
use hex;

pub struct WitnessProgram {
    /// The version byte
    pub version: u8,
    /// The witness program bytes
    pub program: Vec<u8>,
}

impl WitnessProgram {
    /// Returns a new WitnessProgram given a program with a version byte, data size, and data.
    pub fn new(program: &[u8]) -> Result<WitnessProgram, &'static str> {
        if program.len() < 2 {
            return Err("Invalid program");
        }

        // https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#Decoding
        let data_size = program[1] as usize;
        let data = program[2..].to_vec();
        if data_size != data.len() {
            return Err("Mismatched program length");
        }

        let program = WitnessProgram { version: program[0], program: data };
        match program.validate() {
            Ok(()) => Ok(program),
            Err(e) => Err(e)
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.program.len() < 2 || self.program.len() > 40 {
            return Err("Invalid program length");
        }

        if  self.version > 16 {
            return Err("Invalid version");
        }

        // P2SH_P2WPKH start with 0x0014
        // P2SH_P2WSH starts with 0x0020
        // https://bitcoincore.org/en/segwit_wallet_dev/#creation-of-p2sh-p2wpkh-address
        if self.version == 0 && !(self.program.len() == 20 || self.program.len() == 32) {
            return Err("Invalid program length for witness version 0");
        }

        Ok(())
    }

    /// Returns the witness program as a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut output = vec![WitnessProgram::convert_version(self.version)];
        output.push(self.program.len() as u8);
        output.copy_from_slice(&self.program);
        output
    }

    /// A BIP173 version conversion utility function.
    /// Convert a given version to a value between 0 and 16 or OP_1 through OP_16
    pub fn convert_version(version: u8) -> u8 {
        if version > 0x00 && version <= 0x10 { // encode OP_1 through OP_16
            version + 0x50
        } else if version > 0x50 { // decode OP_1 through OP_16
            version - 0x50
        } else { // OP_0
            version
        }
    }
}

impl FromStr for WitnessProgram {
    type Err = &'static str;

    /// Returns a witness program given its hex representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        WitnessProgram::new(&match hex::decode(s) {
            Ok(bytes) => bytes,
            Err(_) => return Err("Error decoding hex string")
        })
    }
}

impl fmt::Display for WitnessProgram {
    /// Prints a witness program in hex representation.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_vec()))
    }
}