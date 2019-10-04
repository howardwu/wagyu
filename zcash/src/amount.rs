use wagyu_model::{Amount, AmountError};

use serde::Serialize;
use std::fmt;

// Number of zatoshis (base unit) per ZEC
const COIN: i64 = 1_0000_0000;

// Maximum number of zatoshis
const MAX_COINS: i64 = 21_000_000 * COIN;

/// Represents the amount of ZEC in zatoshis
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZcashAmount(i64);

impl Amount for ZcashAmount {}

impl ZcashAmount {
    /// The zero amount.
    pub const ZERO: ZcashAmount = ZcashAmount(0);
    /// Exactly one zatoshi.
    pub const ONE_ZAT: ZcashAmount = ZcashAmount(1);
    /// Exactly one ZEC.
    pub const ONE_ZEC: ZcashAmount = ZcashAmount(COIN);

    pub fn from_zatoshi(zatoshis: i64) -> Result<Self, AmountError> {
        if -MAX_COINS <= zatoshis && zatoshis <= MAX_COINS {
            Ok(ZcashAmount(zatoshis))
        } else {
            return Err(AmountError::AmountOutOfBounds(
                zatoshis.to_string(),
                MAX_COINS.to_string(),
            ));
        }
    }

    pub fn from_zec(zec_value: i64) -> Result<Self, AmountError> {
        let zatoshis = zec_value * COIN;

        Self::from_zatoshi(zatoshis)
    }

    pub fn add(self, b: Self) -> Result<Self, AmountError> {
        Self::from_zatoshi(self.0 + b.0)
    }

    pub fn sub(self, b: Self) -> Result<Self, AmountError> {
        Self::from_zatoshi(self.0 - b.0)
    }
}

impl fmt::Display for ZcashAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_from_zatoshi(zat_value: i64, expected_amount: ZcashAmount) {
        let amount = ZcashAmount::from_zatoshi(zat_value).unwrap();
        assert_eq!(expected_amount, amount)
    }

    fn test_from_zec(zec_value: i64, expected_amount: ZcashAmount) {
        let amount = ZcashAmount::from_zec(zec_value).unwrap();
        assert_eq!(expected_amount, amount)
    }

    fn test_addition(a: &i64, b: &i64, result: &i64) {
        let a = ZcashAmount::from_zatoshi(*a).unwrap();
        let b = ZcashAmount::from_zatoshi(*b).unwrap();
        let result = ZcashAmount::from_zatoshi(*result).unwrap();

        assert_eq!(result, a.add(b).unwrap());
    }

    fn test_subtraction(a: &i64, b: &i64, result: &i64) {
        let a = ZcashAmount::from_zatoshi(*a).unwrap();
        let b = ZcashAmount::from_zatoshi(*b).unwrap();
        let result = ZcashAmount::from_zatoshi(*result).unwrap();

        assert_eq!(result, a.sub(b).unwrap());
    }

    pub struct AmountDenominationTestCase {
        zatoshi: i64,
        zcash: i64,
    }

    mod valid_conversions {
        use super::*;

        const TEST_AMOUNTS: [AmountDenominationTestCase; 5] = [
            AmountDenominationTestCase {
                zatoshi: 0,
                zcash: 0,
            },
            AmountDenominationTestCase {
                zatoshi: 100000000,
                zcash: 1,
            },
            AmountDenominationTestCase {
                zatoshi: 100000000000,
                zcash: 1000,
            },
            AmountDenominationTestCase {
                zatoshi: 123456700000000,
                zcash: 1234567,
            },
            AmountDenominationTestCase {
                zatoshi: 2100000000000000,
                zcash: 21000000,
            },
        ];

        #[test]
        fn test_zatoshi_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_zatoshi(amounts.zatoshi, ZcashAmount(amounts.zatoshi)));
        }

        #[test]
        fn test_zec_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_zec(amounts.zcash, ZcashAmount(amounts.zatoshi)));
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
                    zatoshi: 2100000100000000,
                    zcash: 21000001,
                },
                AmountDenominationTestCase {
                    zatoshi: -2100000100000000,
                    zcash: -21000001,
                },
                AmountDenominationTestCase {
                    zatoshi: 1000000000000000000,
                    zcash: 10000000000,
                },
                AmountDenominationTestCase {
                    zatoshi: -1000000000000000000,
                    zcash: -10000000000,
                },
            ];

            #[should_panic(expected = "AmountOutOfBounds")]
            #[test]
            fn test_invalid_zatoshi_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_zatoshi(amounts.zatoshi, ZcashAmount(amounts.zatoshi)));
            }

            #[should_panic(expected = "AmountOutOfBounds")]
            #[test]
            fn test_invalid_zec_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_zec(amounts.zcash, ZcashAmount(amounts.zatoshi)));
            }
        }

        mod test_invalid_conversion {
            use super::*;

            const INVALID_TEST_AMOUNTS: [AmountDenominationTestCase; 4] = [
                AmountDenominationTestCase {
                    zatoshi: 1,
                    zcash: 1,
                },
                AmountDenominationTestCase {
                    zatoshi: 1,
                    zcash: 100000000,
                },
                AmountDenominationTestCase {
                    zatoshi: 123456789,
                    zcash: 1,
                },
                AmountDenominationTestCase {
                    zatoshi: 2100000000000000,
                    zcash: 20999999,
                },
            ];

            #[should_panic]
            #[test]
            fn test_invalid_zec_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_zec(amounts.zcash, ZcashAmount(amounts.zatoshi)));
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
