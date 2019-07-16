//! Bech32
//! This module contains a representation and utility functions for the Bech32 encoding format
//! specified in BIP173, compliant with all test vectors in the BIP.
use std::fmt;
use std::str::FromStr;
use crate::witness_program::WitnessProgram;

// https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

#[derive(Debug)]
pub struct Bech32 {
    pub hrp: String,
    pub data: Vec<u8>,
}

/// Error types for Bech32 encoding / decoding
#[derive(PartialEq, Debug)]
pub enum CodingError {
    /// String does not contain the separator character
    MissingSeparator,
    /// The checksum does not match the rest of the data
    InvalidChecksum,
    /// The data or human-readable part is too long or too short
    InvalidLength,
    /// Some part of the string contains an invalid character
    InvalidChar,
    /// Some part of the data has an invalid value
    InvalidData,
    /// The whole string must be of one case
    MixedCase,
}

// Human-readable part and data part separator
const SEP: char = '1';

// Encoding character set. Maps data value -> char
const CHARSET: [char; 32] = [
    'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0', 's', '3', 'j',
    'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l',
];

// Reverse character set. Maps ASCII byte -> CHARSET index on [0,31]
const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
    -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1,
    -1, -1, -1, -1,
];

// Generator coefficients
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

impl Bech32 {
    /// Returns a segwit witness program from the bech32 address
    pub fn to_witness_program(&self) -> Result<WitnessProgram, &'static str> {
        if self.data.len() < 2 {
            return Err("Invalid data length when converting to witness program")
        }

        let (v, data) = self.data.split_at(1);
        let mut program = match Bech32::convert_bits(data, 5, 8, false) {
            Ok(prog) => prog,
            Err(_) => return Err("Error converting data")
        };
        program.insert(0, program.len() as u8);
        program.insert(0, v[0]);

        WitnessProgram::new(&program)
    }

    /// Returns a Bech32 object from a segwit witness program
    pub fn from_witness_program(hrp: String, witness_program: WitnessProgram) -> Result<Self, CodingError> {
        let version= witness_program.version;
        // Ignore the program size when creating the address
        let program = &witness_program.program;
        let grouped_data: Vec<u8> = match Bech32::convert_bits(program, 8, 5, true) {
            Ok(data) => data,
            Err(_) => return Err(CodingError::InvalidData)
        };

        let mut data = vec![version]; // using prog version 0
        data.extend_from_slice(&grouped_data);

        Ok(Bech32 { hrp, data })
    }

    /// Creates a Bech32 checksum
    pub fn create_checksum(hrp: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
        let mut values: Vec<u8> = Bech32::hrp_expand(hrp);
        values.extend_from_slice(data);
        // Pad with 6 zeros
        values.extend_from_slice(&[0u8; 6]);
        let plm: u32 = Bech32::polymod(values) ^ 1;
        let mut checksum: Vec<u8> = Vec::new();
        for p in 0..6 {
            checksum.push(((plm >> 5 * (5 - p)) & 0x1f) as u8);
        }
        checksum
    }

    /// Verifies a Bech32 checksum
    pub fn verify_checksum(hrp: &Vec<u8>, data: &Vec<u8>) -> bool {
        let mut exp = Bech32::hrp_expand(&hrp);
        exp.extend_from_slice(data);
        Bech32::polymod(exp) == 1u32
    }

    fn polymod(values: Vec<u8>) -> u32 {
        let mut chk: u32 = 1;
        let mut b: u8;
        for v in values {
            b = (chk >> 25) as u8;
            chk = (chk & 0x1ffffff) << 5 ^ (v as u32);
            for i in 0..5 {
                if (b >> i) & 1 == 1 {
                    chk ^= GEN[i]
                }
            }
        }
        chk
    }

    fn hrp_expand(hrp: &Vec<u8>) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        for b in hrp {
            v.push(*b >> 5);
        }
        v.push(0);
        for b in hrp {
            v.push(*b & 0x1f);
        }
        v
    }

    // Take hrp and data bytes and convert to a Bech32 object
    fn from_bytes(hrp: Vec<u8>, data: Vec<u8>) -> Result<Self, CodingError> {
        let mut has_lower = false;
        let mut has_upper = false;
        let mut hrp_bytes = Vec::<u8>::new();
        for b in hrp {
            let mut c = b;
            // MUST contain 1 to 83 US-ASCII characters having a value in the range [33-126]
            if b < 33 || b > 126 {
                return Err(CodingError::InvalidChar);
            }

            if b.is_ascii_lowercase() {
                has_lower = true;
            }

            if b.is_ascii_uppercase() {
                has_upper = true;
                c = b.to_ascii_lowercase();
            }

            hrp_bytes.push(c);
        }

        let mut data_bytes = Vec::<u8>::new();
        for b in data {
            let mut c = b;
            if !b.is_ascii_alphanumeric() {
                return Err(CodingError::InvalidChar);
            }

            if b == b'1' || b == b'b' || b == b'i' || b == b'o' {
                return Err(CodingError::InvalidChar);
            }

            if b.is_ascii_lowercase() {
                has_lower = true;
            }

            if b.is_ascii_uppercase() {
                has_upper = true;
                c = b.to_ascii_lowercase();
            }

            data_bytes.push(CHARSET_REV[c as usize] as u8);
        }

        if has_upper && has_lower {
            return Err(CodingError::MixedCase);
        }

        if !Bech32::verify_checksum(&hrp_bytes, &data_bytes) {
            return Err(CodingError::InvalidChecksum);
        }

        let data_bytes_len = data_bytes.len();
        data_bytes.truncate(data_bytes_len - 6);

        return Ok(Bech32 {
            hrp: String::from_utf8(hrp_bytes).unwrap(),
            data: data_bytes,
        });
    }

    // Convert between bit sizes
    fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, &'static str> {
        if from > 8 || to > 8 {
            panic!("convert_bits `from` and `to` parameters greater than 8");
        }
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut ret: Vec<u8> = Vec::new();
        let maxv: u32 = (1<<to) - 1;
        for &value in data {
            let v: u32 = value as u32;
            if (v >> from) != 0 {
                // Input value exceeds `from` bit size
                return Err("InvalidInputValue")
            }
            acc = (acc << from) | v;
            bits += from;
            while bits >= to {
                bits -= to;
                ret.push(((acc >> bits) & maxv) as u8);
            }
        }
        if pad {
            if bits > 0 {
                ret.push(((acc << (to - bits)) & maxv) as u8);
            }
        } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
            return Err("InvalidPadding")
        }
        Ok(ret)
    }
}

impl FromStr for Bech32 {
    type Err = CodingError;

    /// Creates a Bech32 object from a bech32 encoded string
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let len = s.len();
        if len < 8 || len > 90 {
            return Err(CodingError::InvalidLength);
        }

        if s.find(SEP).is_none() {
            return Err(CodingError::MissingSeparator);
        }

        let parts: Vec<&str> = s.rsplitn(2, SEP).collect();
        let raw_data = parts[0];
        let raw_hrp = parts[1];

        // hrp must be at least len 1, raw data must be at least len 6
        if raw_hrp.len() < 1 || raw_data.len() < 6 {
            return Err(CodingError::InvalidLength);
        }

        Bech32::from_bytes(raw_hrp.as_bytes().to_vec(), raw_data.as_bytes().to_vec())
    }
}

impl fmt::Display for Bech32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.hrp.len() < 1 {
            return Err(fmt::Error)
        }
        let hrp_bytes: Vec<u8> = self.hrp.clone().into_bytes();
        let mut combined: Vec<u8> = self.data.clone();
        combined.extend_from_slice(&Bech32::create_checksum(&hrp_bytes, &self.data));
        let mut encoded: String = format!("{}{}", self.hrp, SEP);
        for p in combined {
            if p >= 32 {
                return Err(fmt::Error)
            }
            encoded.push(CHARSET[p as usize]);
        }
        write!(f, "{}", encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::Bech32;
    use super::CodingError;
    use std::str::FromStr;
    use crate::witness_program::WitnessProgram;

    fn test_from_str_is_ok(bech32_str: &str) {
        let bech32_result = Bech32::from_str(bech32_str);
        assert_eq!(true, bech32_result.is_ok());
    }

    fn test_from_str_is_err(bech32_str: &str, error: CodingError) {
        let bech32_result = Bech32::from_str(bech32_str);
        assert_eq!(true, bech32_result.is_err());
        assert_eq!(error, bech32_result.unwrap_err());
    }

    const VALID_BECH32_STRS: [&str; 7] = [
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        "?1ezyfcl"
    ];

    #[test]
    fn test_valid_bech32_strs() {
        VALID_BECH32_STRS.iter().for_each(|bech32_str| {
            test_from_str_is_ok(bech32_str);
        });
    }

    const HRP_CHARACTER_OUT_OF_RANGE_STRS: [&str; 3] = ["\x201nwldj5", "\x7F1axkwrx", "\u{80}1eym55h"];

    #[test]
    fn test_hrp_character_out_of_range() {
        HRP_CHARACTER_OUT_OF_RANGE_STRS
            .iter()
            .for_each(|invalid_str| {
                test_from_str_is_err(invalid_str, CodingError::InvalidChar);
            });
    }

    const INVALID_LENGTH_STR: &str =
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx";

    #[test]
    fn test_invalid_length() {
        test_from_str_is_err(INVALID_LENGTH_STR, CodingError::InvalidLength);
    }

    const NO_SEPARATOR_STR: &str = "pzry9x0s0muk";

    #[test]
    fn test_no_separator() {
        test_from_str_is_err(NO_SEPARATOR_STR, CodingError::MissingSeparator);
    }

    const EMPTY_HRP: &str = "1pzry9x0s0muk";

    #[test]
    fn test_empty_hrp() {
        test_from_str_is_err(EMPTY_HRP, CodingError::InvalidLength);
    }

    const INVALID_DATA_CHAR: &str = "x1b4n0q5v";

    #[test]
    fn test_invalid_data_char() {
        test_from_str_is_err(INVALID_DATA_CHAR, CodingError::InvalidChar);
    }

    const TOO_SHORT_CHECKSUM: &str = "li1dgmt3";

    #[test]
    fn test_too_short_checksum() {
        test_from_str_is_err(TOO_SHORT_CHECKSUM, CodingError::InvalidLength);
    }

    const INVALID_CHAR_IN_CHEKSUM: &str = "de1lg7wt\u{ff}";

    #[test]
    fn test_invalid_char_in_checksum() {
        test_from_str_is_err(&INVALID_CHAR_IN_CHEKSUM, CodingError::InvalidChar);
    }

    const ADDRESS_SCRIPT_PUB_KEY_PAIRS: [(&str, &str); 6] = [
        (
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            "0014751e76e8199196d454941c45d1b3a323f1433bd6"
        ),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
        ),
        (
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
            "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"
        ),
        (
            "BC1SW50QA3JX3S",
            "6002751e"
        ),
        (
            "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
            "5210751e76e8199196d454941c45d1b3a323"
        ),
        (
            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
        ),
    ];

    #[test]
    fn from_address_bip173_tests() {
        ADDRESS_SCRIPT_PUB_KEY_PAIRS.iter().for_each(|(address, witness_program)| {
            let bech32 = Bech32::from_str(address).unwrap();
            let wit_prog = bech32.to_witness_program().unwrap();
            assert_eq!(witness_program.to_owned(), wit_prog.to_string());
        });
    }

    #[test]
    fn to_address_bip173_tests() {
        ADDRESS_SCRIPT_PUB_KEY_PAIRS.iter().for_each(|(address, witness_program)| {
            let wit_prog = WitnessProgram::from_str(witness_program).unwrap();
            let (hrp, _) = address.split_at(2);
            let bech32 = Bech32::from_witness_program(hrp.to_owned().to_lowercase(), wit_prog).unwrap();
            assert_eq!(address.to_owned().to_lowercase(), bech32.to_string());
        });
    }
}
