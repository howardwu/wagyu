use wagyu_model::Amount;

use serde::Serialize;
use std::fmt;

// Number of piconeros (base unit) per Monero
const COIN: i128 = 1_0000_0000_000;

/// Represents the amount of Monero in piconeros
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MoneroAmount(i128);

pub enum Denomination {
    Piconero,
    Nanonero,
    Micronero,
    Millinero,
    Centinero,
    Decinero,
    Monero,
}

impl Denomination {
    /// The number of decimal places more than a piconero.
    fn precision(self) -> u32 {
        match self {
            Denomination::Piconero => 0,
            Denomination::Nanonero => 3,
            Denomination::Micronero => 6,
            Denomination::Millinero => 9,
            Denomination::Centinero => 10,
            Denomination::Decinero => 11,
            Denomination::Monero => 12,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::Piconero => "piconero",
                Denomination::Nanonero => "nanonero",
                Denomination::Micronero => "micronero",
                Denomination::Millinero => "millinero",
                Denomination::Centinero => "centinero",
                Denomination::Decinero => "decinero",
                Denomination::Monero => "monero",
            }
        )
    }
}

impl Amount for MoneroAmount {}

impl MoneroAmount {
    /// The zero amount.
    pub const ZERO: MoneroAmount = MoneroAmount(0);
    /// Exactly one piconero.
    pub const ONE_SAT: MoneroAmount = MoneroAmount(1);
    /// Exactly one monero.
    pub const ONE_BTC: MoneroAmount = MoneroAmount(COIN);

    pub fn from_piconero(piconero_value: i128) -> Self {
        MoneroAmount(piconero_value)
    }

    pub fn from_nanonero(nanonero_value: i128) -> Self {
        let piconeros = nanonero_value * 10_i128.pow(Denomination::Nanonero.precision());

        Self::from_piconero(piconeros)
    }

    pub fn from_micronero(micronero_value: i128) -> Self {
        let piconeros = micronero_value * 10_i128.pow(Denomination::Micronero.precision());

        Self::from_piconero(piconeros)
    }

    pub fn from_millinero(millinero_value: i128) -> Self {
        let piconeros = millinero_value * 10_i128.pow(Denomination::Millinero.precision());

        Self::from_piconero(piconeros)
    }

    pub fn from_centinero(centinero_value: i128) -> Self {
        let piconeros = centinero_value * 10_i128.pow(Denomination::Centinero.precision());

        Self::from_piconero(piconeros)
    }

    pub fn from_decinero(decinero_value: i128) -> Self {
        let piconeros = decinero_value * 10_i128.pow(Denomination::Decinero.precision());

        Self::from_piconero(piconeros)
    }

    pub fn from_monero(monero_value: i128) -> Self {
        let piconeros = monero_value * 10_i128.pow(Denomination::Monero.precision());

        Self::from_piconero(piconeros)
    }

    pub fn add(self, b: Self) -> Self {
        Self::from_piconero(self.0 + b.0)
    }

    pub fn sub(self, b: Self) -> Self {
        Self::from_piconero(self.0 - b.0)
    }
}

impl fmt::Display for MoneroAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_from_piconero(sat_value: i128, expected_amount: MoneroAmount) {
        let amount = MoneroAmount::from_piconero(sat_value);
        assert_eq!(expected_amount, amount)
    }

    fn test_from_nanonero(nanonero_value: i128, expected_amount: MoneroAmount) {
        let amount = MoneroAmount::from_nanonero(nanonero_value);
        assert_eq!(expected_amount, amount)
    }

    fn test_from_micronero(micronero_value: i128, expected_amount: MoneroAmount) {
        let amount = MoneroAmount::from_micronero(micronero_value);
        assert_eq!(expected_amount, amount)
    }

    fn test_from_millinero(millinero_value: i128, expected_amount: MoneroAmount) {
        let amount = MoneroAmount::from_millinero(millinero_value);
        assert_eq!(expected_amount, amount)
    }

    fn test_from_centinero(centinero_value: i128, expected_amount: MoneroAmount) {
        let amount = MoneroAmount::from_centinero(centinero_value);
        assert_eq!(expected_amount, amount)
    }

    fn test_from_decinero(decinero_value: i128, expected_amount: MoneroAmount) {
        let amount = MoneroAmount::from_decinero(decinero_value);
        assert_eq!(expected_amount, amount)
    }

    fn test_from_monero(monero_value: i128, expected_amount: MoneroAmount) {
        let amount = MoneroAmount::from_monero(monero_value);
        assert_eq!(expected_amount, amount)
    }

    fn test_addition(a: &i128, b: &i128, result: &i128) {
        let a = MoneroAmount::from_piconero(*a);
        let b = MoneroAmount::from_piconero(*b);
        let result = MoneroAmount::from_piconero(*result);

        assert_eq!(result, a.add(b));
    }

    fn test_subtraction(a: &i128, b: &i128, result: &i128) {
        let a = MoneroAmount::from_piconero(*a);
        let b = MoneroAmount::from_piconero(*b);
        let result = MoneroAmount::from_piconero(*result);

        assert_eq!(result, a.sub(b));
    }

    pub struct AmountDenominationTestCase {
        piconero: i128,
        nanonero: i128,
        micronero: i128,
        millinero: i128,
        centinero: i128,
        decinero: i128,
        monero: i128,
    }

    mod valid_conversions {
        use super::*;

        const TEST_AMOUNTS: [AmountDenominationTestCase; 5] = [
            AmountDenominationTestCase {
                piconero: 0,
                nanonero: 0,
                micronero: 0,
                millinero: 0,
                centinero: 0,
                decinero: 0,
                monero: 0,
            },
            AmountDenominationTestCase {
                piconero: 1000000000000,
                nanonero: 1000000000,
                micronero: 1000000,
                millinero: 1000,
                centinero: 100,
                decinero: 10,
                monero: 1,
            },
            AmountDenominationTestCase {
                piconero: 1000000000000000,
                nanonero: 1000000000000,
                micronero: 1000000000,
                millinero: 1000000,
                centinero: 100000,
                decinero: 10000,
                monero: 1000,
            },
            AmountDenominationTestCase {
                piconero: 12345000000000000,
                nanonero: 12345000000000,
                micronero: 12345000000,
                millinero: 12345000,
                centinero: 1234500,
                decinero: 123450,
                monero: 12345,
            },
            AmountDenominationTestCase {
                piconero: 50000000000000000000,
                nanonero: 50000000000000000,
                micronero: 50000000000000,
                millinero: 50000000000,
                centinero: 5000000000,
                decinero: 500000000,
                monero: 50000000,
            },
        ];

        #[test]
        fn test_piconero_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_piconero(amounts.piconero, MoneroAmount(amounts.piconero)));
        }

        #[test]
        fn test_nanonero_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_nanonero(amounts.nanonero, MoneroAmount(amounts.piconero)));
        }

        #[test]
        fn test_micronero_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_micronero(amounts.micronero, MoneroAmount(amounts.piconero)));
        }

        #[test]
        fn test_millinero_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_millinero(amounts.millinero, MoneroAmount(amounts.piconero)));
        }

        #[test]
        fn test_centinero_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_centinero(amounts.centinero, MoneroAmount(amounts.piconero)));
        }

        #[test]
        fn test_decinero_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_decinero(amounts.decinero, MoneroAmount(amounts.piconero)));
        }

        #[test]
        fn test_btc_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_monero(amounts.monero, MoneroAmount(amounts.piconero)));
        }
    }

    mod valid_arithmetic {
        use super::*;

        const TEST_VALUES: [(i128, i128, i128); 7] = [
            (0, 0, 0),
            (1, 2, 3),
            (100000, 0, 100000),
            (123456789, 987654321, 1111111110),
            (10000000000000000, 100000000000000000, 110000000000000000),
            (-10000000000000000, -10000000000000000, -20000000000000000),
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

        mod test_invalid_conversion {
            use super::*;

            const INVALID_TEST_AMOUNTS: [AmountDenominationTestCase; 4] = [
                AmountDenominationTestCase {
                    piconero: 1,
                    nanonero: 1,
                    micronero: 1,
                    millinero: 1,
                    centinero: 1,
                    decinero: 1,
                    monero: 1,
                },
                AmountDenominationTestCase {
                    piconero: 1,
                    nanonero: 10,
                    micronero: 100,
                    millinero: 1000,
                    centinero: 1000000,
                    decinero: 1000000000,
                    monero: 1000000000000,
                },
                AmountDenominationTestCase {
                    piconero: 1234567891234,
                    nanonero: 1234567891,
                    micronero: 1234567,
                    millinero: 1234,
                    centinero: 123,
                    decinero: 12,
                    monero: 1,
                },
                AmountDenominationTestCase {
                    piconero: 1000000000000001,
                    nanonero: 1000000000002,
                    micronero: 1000000003,
                    millinero: 1000004,
                    centinero: 100005,
                    decinero: 10006,
                    monero: 1007,
                },
            ];

            #[should_panic]
            #[test]
            fn test_invalid_nanonero_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_nanonero(amounts.nanonero, MoneroAmount(amounts.piconero)));
            }

            #[should_panic]
            #[test]
            fn test_invalid_micronero_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_micronero(amounts.micronero, MoneroAmount(amounts.piconero)));
            }

            #[should_panic]
            #[test]
            fn test_invalid_millinero_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_millinero(amounts.millinero, MoneroAmount(amounts.piconero)));
            }

            #[should_panic]
            #[test]
            fn test_invalid_centinero_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_centinero(amounts.centinero, MoneroAmount(amounts.piconero)));
            }

            #[should_panic]
            #[test]
            fn test_invalid_decinero_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_decinero(amounts.decinero, MoneroAmount(amounts.piconero)));
            }

            #[should_panic]
            #[test]
            fn test_invalid_monero_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_monero(amounts.monero, MoneroAmount(amounts.piconero)));
            }
        }

        mod invalid_arithmetic {
            use super::*;

            const TEST_VALUES: [(i128, i128, i128); 8] = [
                (0, 0, 1),
                (1, 2, 5),
                (100000, 1, 100000),
                (123456789, 123456789, 123456789),
                (-1000, -1000, 2000),
                (10000000000000000, 100000000000000000, 110000000000000001),
                (-10000000000000000, -10000000000000000, 0),
                (-1, 100000000000000000, 100000000000000001),
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
