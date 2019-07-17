//!WitnessProgram
//! This module contains a representation of a Bitcoin witness program and utility functions
//! related to the representation of such programs.
use std::fmt;
use std::str::FromStr;
use hex::encode;

pub struct WitnessProgram {
    pub version: u8,
    pub program: Vec<u8>,
}

impl WitnessProgram {
    /// Creates a new WitnessProgram given a program with a version byte, data size, and data
    pub fn new(prog_bytes: &[u8]) -> Result<WitnessProgram, &'static str> {
        if prog_bytes.len() < 2 {
            return Err("Invalid program");
        }

        let mut program: Vec<u8> = Vec::new();
        program.extend_from_slice(&prog_bytes[2..]);

        // https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#Decoding
        let program_length = prog_bytes[1];

        if program.len() != program_length as usize {
            return Err("Mismatched program length");
        }

        let mut version = prog_bytes[0];
        if version > 0x50 && version <= 0x60 {
            version -= 0x50;
        }
        else if version != 0x00 {
            return Err("Invalid witness version")
        }

        let new_program = WitnessProgram { version, program };
        match new_program.validate() {
            Ok(()) => Ok(new_program),
            Err(e) => Err(e)
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.program.len() > 40 || self.program.len() < 2 {
            return Err("Invalid program length");
        }

        // https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#Decoding
        let mut version = self.version;
        if version > 0 {
            version -= 0x50;
        }

        // P2SH_P2WPKH start with 0x0014
        // P2SH_P2WSH starts with 0x0020
        // https://bitcoincore.org/en/segwit_wallet_dev/#creation-of-p2sh-p2wpkh-address
        if version > 16 {
            return Err("Invalid version");
        }
        if version == 0 && !(self.program.len() == 20 || self.program.len() == 32) {
            return Err("Invalid program length for witness version 0");
        }
        Ok(())
    }

    /// Returns a byte vector representing a witness program
    #[allow(dead_code)]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        let version = WitnessProgram::convert_version(self.version);
        ret.push(version);
        ret.push(self.program.len() as u8);
        ret.extend_from_slice(&self.program);

        ret
    }

    /// A BIP173 version conversion utility function.
    /// Converts given version to a value between 0 and 16
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

    /// Converts a hex string into a witness program
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prog_bytes = match hex::decode(s) {
            Ok(bytes) => bytes,
            Err(_) => return Err("Error decoding hex string")
        };
        WitnessProgram::new(&prog_bytes)
    }
}

impl fmt::Display for WitnessProgram {
    /// Prints the hex representation of a witness program
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "{:02x}{:02x}{}",
               WitnessProgram::convert_version(self.version),
               self.program.len() as u8,
               encode(&self.program)
        )
    }
}