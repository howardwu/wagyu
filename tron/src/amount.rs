use wagyu_model::{Amount, AmountError};
use wagyu_model::no_std::*;

use core::fmt;
use serde::Serialize;

// Number of satoshis (base unit) per BTC
const COIN: i64 = 1_0000_0000;

// Maximum number of satoshis
const MAX_COINS: i64 = 21_000_000 * COIN;

/// Represents the amount of Tron in satoshis
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct TronAmount(pub i64);

pub enum Denomination {
    // sat
    Satoshi,
    // uBTC (bit)
    MicroBit,
    // mBTC
    MilliBit,
    // cBTC
    CentiBit,
    // dBTC
    DeciBit,
    // BTC
    Tron,
}

impl Denomination {
    /// The number of decimal places more than a satoshi.
    fn precision(self) -> u32 {
        match self {
            Denomination::Satoshi => 0,
            Denomination::MicroBit => 2,
            Denomination::MilliBit => 5,
            Denomination::CentiBit => 6,
            Denomination::DeciBit => 7,
            Denomination::Tron => 8,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::Satoshi => "satoshi",
                Denomination::MicroBit => "uBTC",
                Denomination::MilliBit => "mBTC",
                Denomination::CentiBit => "cBTC",
                Denomination::DeciBit => "dBTC",
                Denomination::Tron => "BTC",
            }
        )
    }
}

impl Amount for TronAmount {}

impl TronAmount {
    /// The zero amount.
    pub const ZERO: TronAmount = TronAmount(0);
    /// Exactly one satoshi.
    pub const ONE_SAT: TronAmount = TronAmount(1);
    /// Exactly one tron.
    pub const ONE_BTC: TronAmount = TronAmount(COIN);

    pub fn from_satoshi(satoshis: i64) -> Result<Self, AmountError> {
        if -MAX_COINS <= satoshis && satoshis <= MAX_COINS {
            Ok(Self(satoshis))
        } else {
            return Err(AmountError::AmountOutOfBounds(
                satoshis.to_string(),
                MAX_COINS.to_string(),
            ));
        }
    }

    pub fn from_ubtc(ubtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = ubtc_value * 10_i64.pow(Denomination::MicroBit.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn from_mbtc(mbtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = mbtc_value * 10_i64.pow(Denomination::MilliBit.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn from_cbtc(cbtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = cbtc_value * 10_i64.pow(Denomination::CentiBit.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn from_dbtc(dbtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = dbtc_value * 10_i64.pow(Denomination::DeciBit.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn from_btc(btc_value: i64) -> Result<Self, AmountError> {
        let satoshis = btc_value * 10_i64.pow(Denomination::Tron.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn add(self, b: Self) -> Result<Self, AmountError> {
        Self::from_satoshi(self.0 + b.0)
    }

    pub fn sub(self, b: TronAmount) -> Result<Self, AmountError> {
        Self::from_satoshi(self.0 - b.0)
    }
}

impl fmt::Display for TronAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_from_satoshi(sat_value: i64, expected_amount: TronAmount) {
        let amount = TronAmount::from_satoshi(sat_value).unwrap();
        assert_eq!(expected_amount, amount)
    }

    fn test_from_ubtc(ubtc_value: i64, expected_amount: TronAmount) {
        let amount = TronAmount::from_ubtc(ubtc_value).unwrap();
        assert_eq!(expected_amount, amount)
    }

    fn test_from_mbtc(mbtc_value: i64, expected_amount: TronAmount) {
        let amount = TronAmount::from_mbtc(mbtc_value).unwrap();
        assert_eq!(expected_amount, amount)
    }

    fn test_from_cbtc(cbtc_value: i64, expected_amount: TronAmount) {
        let amount = TronAmount::from_cbtc(cbtc_value).unwrap();
        assert_eq!(expected_amount, amount)
    }

    fn test_from_dbtc(dbtc_value: i64, expected_amount: TronAmount) {
        let amount = TronAmount::from_dbtc(dbtc_value).unwrap();
        assert_eq!(expected_amount, amount)
    }

    fn test_from_btc(btc_value: i64, expected_amount: TronAmount) {
        let amount = TronAmount::from_btc(btc_value).unwrap();
        assert_eq!(expected_amount, amount)
    }

    fn test_addition(a: &i64, b: &i64, result: &i64) {
        let a = TronAmount::from_satoshi(*a).unwrap();
        let b = TronAmount::from_satoshi(*b).unwrap();
        let result = TronAmount::from_satoshi(*result).unwrap();

        assert_eq!(result, a.add(b).unwrap());
    }

    fn test_subtraction(a: &i64, b: &i64, result: &i64) {
        let a = TronAmount::from_satoshi(*a).unwrap();
        let b = TronAmount::from_satoshi(*b).unwrap();
        let result = TronAmount::from_satoshi(*result).unwrap();

        assert_eq!(result, a.sub(b).unwrap());
    }

    pub struct AmountDenominationTestCase {
        satoshi: i64,
        micro_bit: i64,
        milli_bit: i64,
        centi_bit: i64,
        deci_bit: i64,
        tron: i64,
    }

    mod valid_conversions {
        use super::*;

        const TEST_AMOUNTS: [AmountDenominationTestCase; 5] = [
            AmountDenominationTestCase {
                satoshi: 0,
                micro_bit: 0,
                milli_bit: 0,
                centi_bit: 0,
                deci_bit: 0,
                tron: 0,
            },
            AmountDenominationTestCase {
                satoshi: 100000000,
                micro_bit: 1000000,
                milli_bit: 1000,
                centi_bit: 100,
                deci_bit: 10,
                tron: 1,
            },
            AmountDenominationTestCase {
                satoshi: 100000000000,
                micro_bit: 1000000000,
                milli_bit: 1000000,
                centi_bit: 100000,
                deci_bit: 10000,
                tron: 1000,
            },
            AmountDenominationTestCase {
                satoshi: 123456700000000,
                micro_bit: 1234567000000,
                milli_bit: 1234567000,
                centi_bit: 123456700,
                deci_bit: 12345670,
                tron: 1234567,
            },
            AmountDenominationTestCase {
                satoshi: 2100000000000000,
                micro_bit: 21000000000000,
                milli_bit: 21000000000,
                centi_bit: 2100000000,
                deci_bit: 210000000,
                tron: 21000000,
            },
        ];

        #[test]
        fn test_satoshi_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_satoshi(amounts.satoshi, TronAmount(amounts.satoshi)));
        }

        #[test]
        fn test_ubtc_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_ubtc(amounts.micro_bit, TronAmount(amounts.satoshi)));
        }

        #[test]
        fn test_mbtc_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_mbtc(amounts.milli_bit, TronAmount(amounts.satoshi)));
        }

        #[test]
        fn test_cbtc_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_cbtc(amounts.centi_bit, TronAmount(amounts.satoshi)));
        }

        #[test]
        fn test_dbtc_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_dbtc(amounts.deci_bit, TronAmount(amounts.satoshi)));
        }

        #[test]
        fn test_btc_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_btc(amounts.tron, TronAmount(amounts.satoshi)));
        }
    }

    mod valid_arithmetic {
        use super::*;

        const TEST_VALUES: [(i64, i64, i64); 7] = [
            (0, 0, 0),
            (1, 2, 3),
            (100000, 0, 100000),
            (123456789, 987654321, 1111111110),
            (100000000000000, 2000000000000000, 2100000000000000),
            (-100000000000000, -2000000000000000, -2100000000000000),
            (1000000, -1000000, 0),
        ];

        #[test]
        fn test_valid_addition() {
            TEST_VALUES.iter().for_each(|(a, b, c)| test_addition(a, b, c));
        }

        #[test]
        fn test_valid_subtraction() {
            TEST_VALUES.iter().for_each(|(a, b, c)| test_subtraction(c, b, a));
        }
    }

    mod test_invalid {
        use super::*;

        mod test_out_of_bounds {
            use super::*;

            const INVALID_TEST_AMOUNTS: [AmountDenominationTestCase; 4] = [
                AmountDenominationTestCase {
                    satoshi: 2100000100000000,
                    micro_bit: 21000001000000,
                    milli_bit: 21000001000,
                    centi_bit: 2100000100,
                    deci_bit: 210000010,
                    tron: 21000001,
                },
                AmountDenominationTestCase {
                    satoshi: -2100000100000000,
                    micro_bit: -21000001000000,
                    milli_bit: -21000001000,
                    centi_bit: -2100000100,
                    deci_bit: -210000010,
                    tron: -21000001,
                },
                AmountDenominationTestCase {
                    satoshi: 1000000000000000000,
                    micro_bit: 10000000000000000,
                    milli_bit: 10000000000000,
                    centi_bit: 1000000000000,
                    deci_bit: 100000000000,
                    tron: 10000000000,
                },
                AmountDenominationTestCase {
                    satoshi: -1000000000000000000,
                    micro_bit: -10000000000000000,
                    milli_bit: -10000000000000,
                    centi_bit: -1000000000000,
                    deci_bit: -100000000000,
                    tron: -10000000000,
                },
            ];

            #[should_panic(expected = "AmountOutOfBounds")]
            #[test]
            fn test_invalid_satoshi_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_satoshi(amounts.satoshi, TronAmount(amounts.satoshi)));
            }

            #[should_panic(expected = "AmountOutOfBounds")]
            #[test]
            fn test_invalid_ubtc_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_ubtc(amounts.micro_bit, TronAmount(amounts.satoshi)));
            }

            #[should_panic(expected = "AmountOutOfBounds")]
            #[test]
            fn test_invalid_mbtc_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_mbtc(amounts.milli_bit, TronAmount(amounts.satoshi)));
            }

            #[should_panic(expected = "AmountOutOfBounds")]
            #[test]
            fn test_invalid_cbtc_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_cbtc(amounts.centi_bit, TronAmount(amounts.satoshi)));
            }

            #[should_panic(expected = "AmountOutOfBounds")]
            #[test]
            fn test_invalid_dbtc_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_dbtc(amounts.deci_bit, TronAmount(amounts.satoshi)));
            }

            #[should_panic(expected = "AmountOutOfBounds")]
            #[test]
            fn test_invalid_btc_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_btc(amounts.tron, TronAmount(amounts.satoshi)));
            }
        }

        mod test_invalid_conversion {
            use super::*;

            const INVALID_TEST_AMOUNTS: [AmountDenominationTestCase; 4] = [
                AmountDenominationTestCase {
                    satoshi: 1,
                    micro_bit: 1,
                    milli_bit: 1,
                    centi_bit: 1,
                    deci_bit: 1,
                    tron: 1,
                },
                AmountDenominationTestCase {
                    satoshi: 1,
                    micro_bit: 10,
                    milli_bit: 100,
                    centi_bit: 1000,
                    deci_bit: 1000000,
                    tron: 100000000,
                },
                AmountDenominationTestCase {
                    satoshi: 123456789,
                    micro_bit: 1234567,
                    milli_bit: 1234,
                    centi_bit: 123,
                    deci_bit: 12,
                    tron: 1,
                },
                AmountDenominationTestCase {
                    satoshi: 2100000000000000,
                    micro_bit: 21000000000000,
                    milli_bit: 21000000000,
                    centi_bit: 2100000000,
                    deci_bit: 210000000,
                    tron: 20999999,
                },
            ];

            #[should_panic]
            #[test]
            fn test_invalid_ubtc_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_ubtc(amounts.micro_bit, TronAmount(amounts.satoshi)));
            }

            #[should_panic]
            #[test]
            fn test_invalid_mbtc_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_mbtc(amounts.milli_bit, TronAmount(amounts.satoshi)));
            }

            #[should_panic]
            #[test]
            fn test_invalid_cbtc_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_cbtc(amounts.centi_bit, TronAmount(amounts.satoshi)));
            }

            #[should_panic]
            #[test]
            fn test_invalid_dbtc_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_dbtc(amounts.deci_bit, TronAmount(amounts.satoshi)));
            }

            #[should_panic]
            #[test]
            fn test_invalid_btc_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_btc(amounts.tron, TronAmount(amounts.satoshi)));
            }
        }

        mod invalid_arithmetic {
            use super::*;

            const TEST_VALUES: [(i64, i64, i64); 8] = [
                (0, 0, 1),
                (1, 2, 5),
                (100000, 1, 100000),
                (123456789, 123456789, 123456789),
                (-1000, -1000, 2000),
                (2100000000000000, 1, 2100000000000001),
                (2100000000000000, 2100000000000000, 4200000000000000),
                (-2100000000000000, -2100000000000000, -4200000000000000),
            ];

            #[should_panic]
            #[test]
            fn test_invalid_addition() {
                TEST_VALUES.iter().for_each(|(a, b, c)| test_addition(a, b, c));
            }

            #[should_panic]
            #[test]
            fn test_invalid_subtraction() {
                TEST_VALUES.iter().for_each(|(a, b, c)| test_subtraction(a, b, c));
            }
        }
    }
}
