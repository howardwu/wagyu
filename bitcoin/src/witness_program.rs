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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// Returns a new witness program given a program with a version byte (where 0 <= version <= 16), data size, and data.
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
    mod test_from_str {
        use std::str::FromStr;

        use crate::witness_program::{WitnessProgram, WitnessProgramError};

        const VALID_P2SH_P2WPKH_PROGRAM: &str = "0014751e76e8199196d454941c45d1b3a323f1433bd6";
        const INVALID_P2SH_P2WPKH_PROGRAM_LENGTH: &str = "0014751e76e8199196d454941c45d1b3a323f143";

        #[test]
        fn from_str_invalid_p2sh_p2wpkh_program_len() {
            match WitnessProgram::from_str(INVALID_P2SH_P2WPKH_PROGRAM_LENGTH) {
                Ok(_) => assert_eq!(None, Some("Error, invalid program decoded successfully")),
                Err(e) => {
                    assert_eq!(WitnessProgramError::MismatchedProgramLength(18, 20), e)
                }
            }
        }

        #[test]
        fn from_str_valid_p2sh_p2wpkh_program() {
            match WitnessProgram::from_str(VALID_P2SH_P2WPKH_PROGRAM) {
                Ok(witness_program) => {
                    assert_eq!(0x00, witness_program.version);
                    assert_eq!(vec![0x75, 0x1e, 0x76, 0xe8, 0x19,
                                    0x91, 0x96, 0xd4, 0x54, 0x94,
                                    0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                                    0x23, 0xf1, 0x43, 0x3b, 0xd6
                    ], witness_program.program);
                }
                Err(e) => assert_eq!(None, Some(e))
            }
        }

        const VALID_P2SH_P2WSH_PROGRAM: &str = "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262";
        const INVALID_P2SH_P2WSH_PROGRAM_LENGTH: &str = "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c632960490";

        #[test]
        fn from_str_invalid_p2sh_p2wsh_program_len() {
            match WitnessProgram::from_str(INVALID_P2SH_P2WSH_PROGRAM_LENGTH) {
                Ok(_) => assert_eq!(None, Some("Error, invalid program decoded successfully")),
                Err(e) => {
                    assert_eq!(WitnessProgramError::MismatchedProgramLength(30, 32), e)
                }
            }
        }

        #[test]
        fn from_str_valid_p2sh_p2wsh_program() {
            match WitnessProgram::from_str(VALID_P2SH_P2WSH_PROGRAM) {
                Ok(witness_program) => {
                    assert_eq!(0x00, witness_program.version);
                    assert_eq!(vec![0x18, 0x63, 0x14, 0x3c, 0x14,
                                    0xc5, 0x16, 0x68, 0x04, 0xbd,
                                    0x19, 0x20, 0x33, 0x56, 0xda,
                                    0x13, 0x6c, 0x98, 0x56, 0x78,
                                    0xcd, 0x4d, 0x27, 0xa1, 0xb8,
                                    0xc6, 0x32, 0x96, 0x04, 0x90,
                                    0x32, 0x62
                    ], witness_program.program);
                }
                Err(e) => assert_eq!(None, Some(e))
            }
        }

        const VALID_OP_1_PROGRAM: &str = "0128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6";
        const INVALID_OP_1_PROGRAM_LENGTH: &str = "0128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f143";

        #[test]
        fn from_str_invalid_op_1_program_len() {
            match WitnessProgram::from_str(INVALID_OP_1_PROGRAM_LENGTH) {
                Ok(_) => assert_eq!(None, Some("Error, invalid program decoded successfully")),
                Err(e) => {
                    assert_eq!(WitnessProgramError::MismatchedProgramLength(38, 40), e)
                }
            }
        }

        #[test]
        fn from_str_valid_op_1_program() {
            match WitnessProgram::from_str(VALID_OP_1_PROGRAM) {
                Ok(witness_program) => {
                    assert_eq!(0x01, witness_program.version);
                    assert_eq!(vec![0x75, 0x1e, 0x76, 0xe8, 0x19,
                                    0x91, 0x96, 0xd4, 0x54, 0x94,
                                    0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                                    0x23, 0xf1, 0x43, 0x3b, 0xd6,
                                    0x75, 0x1e, 0x76, 0xe8, 0x19,
                                    0x91, 0x96, 0xd4, 0x54, 0x94,
                                    0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                                    0x23, 0xf1, 0x43, 0x3b, 0xd6
                    ], witness_program.program);
                }
                Err(e) => assert_eq!(None, Some(e))
            }
        }

        #[test]
        fn from_str_invalid_hex_str() {
            match WitnessProgram::from_str("001122zzxxyy") {
                Ok(_) => assert_eq!(None, Some("Error, invalid hex string decoded successfully")),
                Err(e) => assert_eq!(WitnessProgramError::ProgramDecodingError, e)
            }
        }
    }

    mod test_new {
        use crate::witness_program::{WitnessProgram, WitnessProgramError};

        const INVALID_VERSION_PROGRAM: &[u8] = &[0x19, 0x03, 0x00, 0x00, 0x00];

        #[test]
        fn new_invalid_version() {
            match WitnessProgram::new(INVALID_VERSION_PROGRAM) {
                Ok(_) => assert_eq!(None, Some("Error, program created with invalid version")),
                Err(e) => assert_eq!(WitnessProgramError::InvalidVersion(0x19), e)
            }
        }

        const INVALID_LENGTH_PROGRAM: &[u8] = &[0x19];

        #[test]
        fn new_invalid_length() {
            match WitnessProgram::new(INVALID_LENGTH_PROGRAM) {
                Ok(_) => assert_eq!(None, Some("Error, program created with invalid version")),
                Err(e) => assert_eq!(WitnessProgramError::InvalidProgramLength(1), e)
            }
        }

        const INVALID_LENGTH_FOR_VERSION: &[u8] = &[0x00, 0x0f, // Version 0, data length is incorrect
            0x75, 0x1e, 0x76, 0xe8, 0x19,
            0x91, 0x96, 0xd4, 0x54, 0x94,
            0x1c, 0x45, 0xd1, 0xb3, 0xa3];

        #[test]
        fn new_invalid_program_length_for_version() {
            match WitnessProgram::new(INVALID_LENGTH_FOR_VERSION) {
                Ok(_) => assert_eq!(None, Some("Error, program created with invalid version")),
                Err(e) => assert_eq!(WitnessProgramError::InvalidProgramLengthForVersion(15, 0x00), e)
            }
        }

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
        fn new_invalid_program_length_too_long() {
            match WitnessProgram::new(INVALID_LENGTH_PROGRAM_TOO_LONG) {
                Ok(_) => assert_eq!(None, Some("Error, program created with invalid version")),
                Err(e) => assert_eq!(WitnessProgramError::InvalidProgramLength(41), e)
            }
        }
    }

    mod test_to_scriptpubkey {
        use crate::witness_program::WitnessProgram;

        #[test]
        fn to_scriptpubkey_valid_p2sh_p2wpkh_program() {
            let witness_program = WitnessProgram {
                version: 0x00,
                program: vec![
                    0x75, 0x1e, 0x76, 0xe8, 0x19,
                    0x91, 0x96, 0xd4, 0x54, 0x94,
                    0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                    0x23, 0xf1, 0x43, 0x3b, 0xd6
                ],
            };
            assert_eq!(vec![0x00, 0x14,
                            0x75, 0x1e, 0x76, 0xe8, 0x19,
                            0x91, 0x96, 0xd4, 0x54, 0x94,
                            0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                            0x23, 0xf1, 0x43, 0x3b, 0xd6
            ], witness_program.to_scriptpubkey());
        }

        #[test]
        fn to_scriptpubkey_valid_p2sh_p2wsh_program() {
            let witness_program = WitnessProgram {
                version: 0x00,
                program: vec![0x18, 0x63, 0x14, 0x3c, 0x14,
                              0xc5, 0x16, 0x68, 0x04, 0xbd,
                              0x19, 0x20, 0x33, 0x56, 0xda,
                              0x13, 0x6c, 0x98, 0x56, 0x78,
                              0xcd, 0x4d, 0x27, 0xa1, 0xb8,
                              0xc6, 0x32, 0x96, 0x04, 0x90,
                              0x32, 0x62
                ],
            };
            assert_eq!(vec![0x00, 0x20,
                            0x18, 0x63, 0x14, 0x3c, 0x14,
                            0xc5, 0x16, 0x68, 0x04, 0xbd,
                            0x19, 0x20, 0x33, 0x56, 0xda,
                            0x13, 0x6c, 0x98, 0x56, 0x78,
                            0xcd, 0x4d, 0x27, 0xa1, 0xb8,
                            0xc6, 0x32, 0x96, 0x04, 0x90,
                            0x32, 0x62
            ], witness_program.to_scriptpubkey());
        }

        #[test]
        fn to_scriptpubkey_valid_op_1_program() {
            let witness_program = WitnessProgram {
                version: 0x01,
                program: vec![0x75, 0x1e, 0x76, 0xe8, 0x19,
                              0x91, 0x96, 0xd4, 0x54, 0x94,
                              0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                              0x23, 0xf1, 0x43, 0x3b, 0xd6,
                              0x75, 0x1e, 0x76, 0xe8, 0x19,
                              0x91, 0x96, 0xd4, 0x54, 0x94,
                              0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                              0x23, 0xf1, 0x43, 0x3b, 0xd6
                ],
            };
            assert_eq!(vec![0x51, 0x28, // Encodes version and pushes correct length into vec
                            0x75, 0x1e, 0x76, 0xe8, 0x19,
                            0x91, 0x96, 0xd4, 0x54, 0x94,
                            0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                            0x23, 0xf1, 0x43, 0x3b, 0xd6,
                            0x75, 0x1e, 0x76, 0xe8, 0x19,
                            0x91, 0x96, 0xd4, 0x54, 0x94,
                            0x1c, 0x45, 0xd1, 0xb3, 0xa3,
                            0x23, 0xf1, 0x43, 0x3b, 0xd6
            ], witness_program.to_scriptpubkey());
        }
    }
}
