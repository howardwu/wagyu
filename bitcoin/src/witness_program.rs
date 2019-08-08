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

use std::str::FromStr;

use wagyu_model::AddressError;

#[derive(Debug, Fail, PartialEq, Eq)]
pub enum WitnessProgramError {
    #[fail(display = "invalid program length {}", _0)]
    InvalidProgramLength(usize),

    #[fail(display = "invalid program length {} for script version {}", _0, _1)]
    InvalidProgramLengthForVersion(usize, u8),

    #[fail(display = "invalid version {}", _0)]
    InvalidVersion(u8),

    #[fail(display = "invalid program length: {{ expected: {:?}, found: {:?} }}", _0, _1)]
    MismatchedProgramLength(usize, usize),

    #[fail(display = "error decoding program from hex string")]
    ProgramDecodingError,
}

impl From<WitnessProgramError> for AddressError {
    fn from(error: WitnessProgramError) -> Self {
        AddressError::Crate("WitnessProgram", format!("{:?}", error))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessProgram {
    /// The version byte
    pub version: u8,
    /// The witness program bytes
    pub program: Vec<u8>,
}

impl WitnessProgram {
    /// Returns a new witness program given a program with a version, data size, and data.
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

    /// Returns the witness program's scriptpubkey as a byte vector.
    pub fn to_scriptpubkey(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.program.len() + 2);
        let encoded_version = if self.version > 0 {
            self.version + 0x50
        } else {
            self.version
        };
        output.push(encoded_version);
        output.push(self.program.len() as u8);
        output.extend_from_slice(&self.program);
        output
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_from_str(program_str: &str, expected_version: u8, expected_program: &[u8]) {
        let witness_program = WitnessProgram::from_str(program_str).unwrap();
        assert_eq!(expected_version, witness_program.version);
        assert_eq!(expected_program.to_vec(), witness_program.program);
    }

    fn test_to_scriptpubkey(version: u8, program: &[u8], expected_scriptpubkey: &[u8]) {
        let witness_program = WitnessProgram {
            version,
            program: program.to_vec(),
        };
        assert_eq!(expected_scriptpubkey.to_vec(), witness_program.to_scriptpubkey());
    }

    mod p2sh_p2wpkh {
        use super::*;

        const VALID_P2SH_P2WPKH_PROGRAMS: [(&str, u8, &[u8], &[u8]); 1] = [
            (
                "0014751e76e8199196d454941c45d1b3a323f1433bd6",
                0x00,
                &[0x75, 0x1e, 0x76, 0xe8, 0x19,
                    0x91, 0x96, 0xd4, 0x54, 0x94,
                    0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                    0x23, 0xf1, 0x43, 0x3b, 0xd6],
                &[0x00, 0x14,
                    0x75, 0x1e, 0x76, 0xe8, 0x19,
                    0x91, 0x96, 0xd4, 0x54, 0x94,
                    0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                    0x23, 0xf1, 0x43, 0x3b, 0xd6
                ]
            )
        ];

        #[test]
        fn from_str() {
            VALID_P2SH_P2WPKH_PROGRAMS.iter().for_each(
                |&(program_str, expected_version, expected_program, _)| {
                    test_from_str(program_str, expected_version, &expected_program);
                });
        }

        #[test]
        fn to_scriptpubkey() {
            VALID_P2SH_P2WPKH_PROGRAMS.iter().for_each(
                |&(_, version, program, expected_scriptpubkey)| {
                    test_to_scriptpubkey(version, program, expected_scriptpubkey);
                });
        }
    }

    mod p2sh_p2wsh {
        use super::*;

        const VALID_P2SH_P2WSH_PROGRAMS: [(&str, u8, &[u8], &[u8]); 1] = [
            (
                "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                0x00,
                &[0x18, 0x63, 0x14, 0x3c, 0x14,
                    0xc5, 0x16, 0x68, 0x04, 0xbd,
                    0x19, 0x20, 0x33, 0x56, 0xda,
                    0x13, 0x6c, 0x98, 0x56, 0x78,
                    0xcd, 0x4d, 0x27, 0xa1, 0xb8,
                    0xc6, 0x32, 0x96, 0x04, 0x90,
                    0x32, 0x62],
                &[0x00, 0x20,
                    0x18, 0x63, 0x14, 0x3c, 0x14,
                    0xc5, 0x16, 0x68, 0x04, 0xbd,
                    0x19, 0x20, 0x33, 0x56, 0xda,
                    0x13, 0x6c, 0x98, 0x56, 0x78,
                    0xcd, 0x4d, 0x27, 0xa1, 0xb8,
                    0xc6, 0x32, 0x96, 0x04, 0x90,
                    0x32, 0x62
                ]
            )
        ];

        #[test]
        fn from_str() {
            VALID_P2SH_P2WSH_PROGRAMS.iter().for_each(
                |&(program_str, expected_version, expected_program, _)| {
                    test_from_str(program_str, expected_version, expected_program);
                });
        }

        #[test]
        fn to_scriptpubkey() {
            VALID_P2SH_P2WSH_PROGRAMS.iter().for_each(
                |&(_, version, program, expected_scriptpubkey)| {
                    test_to_scriptpubkey(version, program, expected_scriptpubkey);
                });
        }
    }

    mod version_1 {
        use super::*;

        const VALID_OP_1_PROGRAMS: [(&str, u8, &[u8], &[u8]); 1] = [
            (
                "0128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
                0x01,
                &[0x75, 0x1e, 0x76, 0xe8, 0x19,
                    0x91, 0x96, 0xd4, 0x54, 0x94,
                    0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                    0x23, 0xf1, 0x43, 0x3b, 0xd6,
                    0x75, 0x1e, 0x76, 0xe8, 0x19,
                    0x91, 0x96, 0xd4, 0x54, 0x94,
                    0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                    0x23, 0xf1, 0x43, 0x3b, 0xd6],
                &[0x51, 0x28,
                    0x75, 0x1e, 0x76, 0xe8, 0x19,
                    0x91, 0x96, 0xd4, 0x54, 0x94,
                    0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                    0x23, 0xf1, 0x43, 0x3b, 0xd6,
                    0x75, 0x1e, 0x76, 0xe8, 0x19,
                    0x91, 0x96, 0xd4, 0x54, 0x94,
                    0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                    0x23, 0xf1, 0x43, 0x3b, 0xd6
                ]
            )
        ];

        #[test]
        fn from_str() {
            VALID_OP_1_PROGRAMS.iter().for_each(
                |&(program_str, expected_version, expected_program, _)| {
                    test_from_str(program_str, expected_version, expected_program);
                });
        }

        #[test]
        fn to_scriptpubkey() {
            VALID_OP_1_PROGRAMS.iter().for_each(
                |&(_, version, program, expected_scriptpubkey)| {
                    test_to_scriptpubkey(version, program, expected_scriptpubkey);
                });
        }
    }

    mod test_invalid {
        use super::*;

        mod new {
            use super::*;

            const INVALID_VERSION_PROGRAM: &[u8] = &[0x19, 0x03, 0x00, 0x00, 0x00];
            const INVALID_LENGTH_FOR_VERSION: &[u8] = &[0x00, 0x0f, // Version 0, data length is incorrect
                0x75, 0x1e, 0x76, 0xe8, 0x19,
                0x91, 0x96, 0xd4, 0x54, 0x94,
                0x1c, 0x45, 0xd1, 0xb3, 0xa3];
            const INVALID_LENGTH_PROGRAM: &[u8] = &[0x19];
            const INVALID_LENGTH_PROGRAM_TOO_LONG: &[u8] = &[0x00, 0x29,
                0x75, 0x1e, 0x76, 0xe8, 0x19,
                0x91, 0x96, 0xd4, 0x54, 0x94,
                0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                0x23, 0xf1, 0x43, 0x3b, 0xd6,
                0x75, 0x1e, 0x76, 0xe8, 0x19,
                0x91, 0x96, 0xd4, 0x54, 0x94,
                0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                0x23, 0xf1, 0x43, 0x3b, 0xd6,
                0x00];

            #[test]
            fn new_invalid_version() {
                let witness_program_error = WitnessProgram::new(INVALID_VERSION_PROGRAM).unwrap_err();
                assert_eq!(WitnessProgramError::InvalidVersion(0x19), witness_program_error);
            }

            #[test]
            fn new_invalid_length() {
                let witness_program_error = WitnessProgram::new(INVALID_LENGTH_PROGRAM).unwrap_err();
                assert_eq!(WitnessProgramError::InvalidProgramLength(1), witness_program_error);
            }

            #[test]
            fn new_invalid_program_length_for_version() {
                let witness_program_error = WitnessProgram::new(INVALID_LENGTH_FOR_VERSION).unwrap_err();
                assert_eq!(WitnessProgramError::InvalidProgramLengthForVersion(15, 0x00), witness_program_error);
            }

            #[test]
            fn new_invalid_program_length_too_long() {
                let witness_program_error = WitnessProgram::new(INVALID_LENGTH_PROGRAM_TOO_LONG).unwrap_err();
                assert_eq!(WitnessProgramError::InvalidProgramLength(41), witness_program_error);
            }
        }

        mod from_str {
            use super::*;

            const INVALID_P2SH_P2WPKH_PROGRAM_LENGTH: &str = "0014751e76e8199196d454941c45d1b3a323f143";
            const INVALID_P2SH_P2WSH_PROGRAM_LENGTH: &str = "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c632960490";
            const INVALID_OP_1_PROGRAM_LENGTH: &str = "0128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f143";
            const INVALID_HEX_STR: &str = "001122zzxxyy";

            #[test]
            fn from_str_invalid_p2sh_p2wpkh_program_len() {
                let witness_program_error = WitnessProgram::from_str(INVALID_P2SH_P2WPKH_PROGRAM_LENGTH).unwrap_err();
                assert_eq!(WitnessProgramError::MismatchedProgramLength(18, 20), witness_program_error);
            }

            #[test]
            fn from_str_invalid_p2sh_p2wsh_program_len() {
                let witness_program_error = WitnessProgram::from_str(INVALID_P2SH_P2WSH_PROGRAM_LENGTH).unwrap_err();
                assert_eq!(WitnessProgramError::MismatchedProgramLength(30, 32), witness_program_error);
            }

            #[test]
            fn from_str_invalid_op_1_program_len() {
                let witness_program_error = WitnessProgram::from_str(INVALID_OP_1_PROGRAM_LENGTH).unwrap_err();
                assert_eq!(WitnessProgramError::MismatchedProgramLength(38, 40), witness_program_error);
            }

            #[test]
            fn from_str_invalid_hex_str() {
                let witness_program_error = WitnessProgram::from_str(INVALID_HEX_STR).unwrap_err();
                assert_eq!(WitnessProgramError::ProgramDecodingError, witness_program_error);
            }
        }
    }
}
