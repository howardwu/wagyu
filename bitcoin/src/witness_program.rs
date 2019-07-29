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

use wagu_model::AddressError;

use hex;
use std::fmt;
use std::str::FromStr;

pub struct WitnessProgram {
    /// The version byte
    pub version: u8,
    /// The witness program bytes
    pub program: Vec<u8>,
}

#[derive(Debug, Fail, PartialEq, Eq)]
pub enum WitnessProgramError {
    #[fail(display = "expected program with length at least 2, at most 40, actual program was length {}", _0)]
    InvalidProgramLength(usize),

    #[fail(display = "invalid program length {} for script version {}", _0, _1)]
    InvalidProgramLengthForVersion(usize, u8),

    #[fail(display = "expected version no greater than 16")]
    InvalidVersion(u8),

    #[fail(display = "expected program length {} to equal length {} as specified by input", _0, _1)]
    MismatchedProgramLength(usize, usize),

    #[fail(display = "error decoding program from hex string")]
    ProgramDecodingError,
}

impl From<WitnessProgramError> for AddressError {
    fn from(error: WitnessProgramError) -> Self {
        AddressError::Crate("WitnessProgram", format!("{:?}", error))
    }
}

impl WitnessProgram {
    /// Returns a new witness program given a program with a version byte, data size, and data.
    pub fn new(program: &[u8]) -> Result<WitnessProgram, WitnessProgramError> {
        if program.len() < 2 {
            return Err(WitnessProgramError::InvalidProgramLength(program.len()));
        }

        // https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#Decoding
        let data_size = program[1] as usize;
        let data = program[2..].to_vec();
        if data_size != data.len() {
            return Err(WitnessProgramError::MismatchedProgramLength(data.len(), data_size));
        }

        let program = WitnessProgram {
            version: program[0],
            program: data,
        };
        match program.validate() {
            Ok(()) => Ok(program),
            Err(e) => Err(e),
        }
    }

    pub fn validate(&self) -> Result<(), WitnessProgramError> {
        if self.program.len() < 2 || self.program.len() > 40 {
            return Err(WitnessProgramError::InvalidProgramLength(self.program.len()));
        }

        if self.version > 16 {
            return Err(WitnessProgramError::InvalidVersion(self.version));
        }

        // P2SH_P2WPKH start with 0x0014
        // P2SH_P2WSH starts with 0x0020
        // https://bitcoincore.org/en/segwit_wallet_dev/#creation-of-p2sh-p2wpkh-address
        if self.version == 0 && !(self.program.len() == 20 || self.program.len() == 32) {
            return Err(WitnessProgramError::InvalidProgramLengthForVersion(self.program.len(), self.version));
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
    /// Convert a given version to a value between 0 and 16 or OP_1 through OP_16.
    pub fn convert_version(version: u8) -> u8 {
        if version > 0x00 && version <= 0x10 {
            // encode OP_1 through OP_16
            version + 0x50
        } else if version > 0x50 {
            // decode OP_1 through OP_16
            version - 0x50
        } else {
            // OP_0
            version
        }
    }
}

impl FromStr for WitnessProgram {
    type Err = WitnessProgramError;

    /// Returns a witness program given its hex representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        WitnessProgram::new(&match hex::decode(s) {
            Ok(bytes) => bytes,
            Err(_) => return Err(WitnessProgramError::ProgramDecodingError),
        })
    }
}

impl fmt::Display for WitnessProgram {
    /// Prints a witness program in hex representation.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_vec()))
    }
}
