use wagyu_model::{Amount, AmountError};

use ethereum_types::U256;
use std::fmt;

/// Represents the amount of Ethereum in wei
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumAmount(pub U256);

pub enum Denomination {
    Wei,
    Kwei,
    Mwei,
    Gwei,
    Szabo,
    Finney,
    Ether,
}

impl Denomination {
    /// The number of decimal places more than a wei.
    fn precision(self) -> u32 {
        match self {
            Denomination::Wei => 0,
            Denomination::Kwei => 3,
            Denomination::Mwei => 6,
            Denomination::Gwei => 9,
            Denomination::Szabo => 12,
            Denomination::Finney => 15,
            Denomination::Ether => 18,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::Wei => "wei",
                Denomination::Kwei => "kwei",
                Denomination::Mwei => "mwei",
                Denomination::Gwei => "gwei",
                Denomination::Szabo => "szabo",
                Denomination::Finney => "finney",
                Denomination::Ether => "ETH",
            }
        )
    }
}

impl Amount for EthereumAmount {}

impl EthereumAmount {
    pub fn u256_from_str(val: &str) -> Result<U256, AmountError> {
        match U256::from_dec_str(val) {
            Ok(wei) => Ok(wei),
            Err(error) => return Err(AmountError::Crate("uint", format!("{:?}", error))),
        }
    }

    pub fn from_u256(wei: U256) -> Self {
        Self(wei)
    }

    pub fn from_wei(wei_value: &str) -> Result<Self, AmountError> {
        let wei = Self::u256_from_str(wei_value)?;

        Ok(Self::from_u256(wei))
    }

    pub fn from_kwei(kwei_value: &str) -> Result<Self, AmountError> {
        let wei = Self::u256_from_str(kwei_value)? * 10_i64.pow(Denomination::Kwei.precision());

        Ok(Self::from_u256(wei))
    }

    pub fn from_mwei(mwei_value: &str) -> Result<Self, AmountError> {
        let wei = Self::u256_from_str(mwei_value)? * 10_i64.pow(Denomination::Mwei.precision());

        Ok(Self::from_u256(wei))
    }

    pub fn from_gwei(gwei_value: &str) -> Result<Self, AmountError> {
        let wei = Self::u256_from_str(gwei_value)? * 10_i64.pow(Denomination::Gwei.precision());

        Ok(Self::from_u256(wei))
    }

    pub fn from_szabo(szabo_value: &str) -> Result<Self, AmountError> {
        let wei = Self::u256_from_str(szabo_value)? * 10_i64.pow(Denomination::Szabo.precision());

        Ok(Self::from_u256(wei))
    }

    pub fn from_finney(finney_value: &str) -> Result<Self, AmountError> {
        let wei = Self::u256_from_str(finney_value)? * 10_i64.pow(Denomination::Finney.precision());

        Ok(Self::from_u256(wei))
    }

    pub fn from_eth(eth_value: &str) -> Result<Self, AmountError> {
        let wei = Self::u256_from_str(eth_value)? * 10_i64.pow(Denomination::Ether.precision());

        Ok(Self::from_u256(wei))
    }

    pub fn add(self, b: Self) -> Self {
        Self::from_u256(self.0 + b.0)
    }

    pub fn sub(self, b: Self) -> Self {
        Self::from_u256(self.0 - b.0)
    }
}

impl fmt::Display for EthereumAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_from_wei(wei_value: &str, expected_amount: &str) {
        let amount = EthereumAmount::from_wei(wei_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_finney(finney_value: &str, expected_amount: &str) {
        let amount = EthereumAmount::from_finney(finney_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_szabo(szabo_value: &str, expected_amount: &str) {
        let amount = EthereumAmount::from_szabo(szabo_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_gwei(gwei_value: &str, expected_amount: &str) {
        let amount = EthereumAmount::from_gwei(gwei_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_mwei(mwei_value: &str, expected_amount: &str) {
        let amount = EthereumAmount::from_mwei(mwei_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_kwei(kwei_value: &str, expected_amount: &str) {
        let amount = EthereumAmount::from_kwei(kwei_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_eth(eth_value: &str, expected_amount: &str) {
        let amount = EthereumAmount::from_eth(eth_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_addition(a: &str, b: &str, result: &str) {
        let a = EthereumAmount::from_wei(a).unwrap();
        let b = EthereumAmount::from_wei(b).unwrap();
        let result = EthereumAmount::from_wei(result).unwrap();

        assert_eq!(result, a.add(b));
    }

    fn test_subtraction(a: &str, b: &str, result: &str) {
        let a = EthereumAmount::from_wei(a).unwrap();
        let b = EthereumAmount::from_wei(b).unwrap();
        let result = EthereumAmount::from_wei(result).unwrap();

        assert_eq!(result, a.sub(b));
    }

    pub struct AmountDenominationTestCase {
        wei: &'static str,
        kwei: &'static str,
        mwei: &'static str,
        gwei: &'static str,
        szabo: &'static str,
        finney: &'static str,
        ether: &'static str,
    }

    mod valid_conversions {
        use super::*;

        const TEST_AMOUNTS: [AmountDenominationTestCase; 5] = [
            AmountDenominationTestCase {
                wei: "0",
                kwei: "0",
                mwei: "0",
                gwei: "0",
                szabo: "0",
                finney: "0",
                ether: "0",
            },
            AmountDenominationTestCase {
                wei: "1000000000000000000",
                kwei: "1000000000000000",
                mwei: "1000000000000",
                gwei: "1000000000",
                szabo: "1000000",
                finney: "1000",
                ether: "1",
            },
            AmountDenominationTestCase {
                wei: "1000000000000000000000",
                kwei: "1000000000000000000",
                mwei: "1000000000000000",
                gwei: "1000000000000",
                szabo: "1000000000",
                finney: "1000000",
                ether: "1000",
            },
            AmountDenominationTestCase {
                wei: "1234567000000000000000000",
                kwei: "1234567000000000000000",
                mwei: "1234567000000000000",
                gwei: "1234567000000000",
                szabo: "1234567000000",
                finney: "1234567000",
                ether: "1234567",
            },
            AmountDenominationTestCase {
                wei: "100000000000000000000000000",
                kwei: "100000000000000000000000",
                mwei: "100000000000000000000",
                gwei: "100000000000000000",
                szabo: "100000000000000",
                finney: "100000000000",
                ether: "100000000",
            },
        ];

        #[test]
        fn test_wei_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_wei(amounts.wei, amounts.wei));
        }

        #[test]
        fn test_finney_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_finney(amounts.finney, amounts.wei));
        }

        #[test]
        fn test_szabo_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_szabo(amounts.szabo, amounts.wei));
        }

        #[test]
        fn test_gwei_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_gwei(amounts.gwei, amounts.wei));
        }

        #[test]
        fn test_mwei_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_mwei(amounts.mwei, amounts.wei));
        }

        #[test]
        fn test_kwei_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_kwei(amounts.kwei, amounts.wei));
        }

        #[test]
        fn test_eth_conversion() {
            TEST_AMOUNTS
                .iter()
                .for_each(|amounts| test_from_eth(amounts.ether, amounts.wei));
        }
    }

    mod valid_arithmetic {
        use super::*;

        const TEST_VALUES: [(&str, &str, &str); 7] = [
            ("0", "0", "0"),
            ("1", "2", "3"),
            ("100000", "0", "100000"),
            ("123456789", "987654321", "1111111110"),
            ("1000000000000000", "2000000000000000", "3000000000000000"),
            (
                "10000000000000000000001",
                "20000000000000000000002",
                "30000000000000000000003",
            ),
            (
                "1000000000000000000000000",
                "1000000000000000000000000",
                "2000000000000000000000000",
            ),
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
                    wei: "1",
                    kwei: "1",
                    mwei: "1",
                    gwei: "1",
                    szabo: "1",
                    finney: "1",
                    ether: "1",
                },
                AmountDenominationTestCase {
                    wei: "1",
                    kwei: "1000",
                    mwei: "1000000",
                    gwei: "1000000000",
                    szabo: "1000000000000",
                    finney: "1000000000000000",
                    ether: "1000000000000000000",
                },
                AmountDenominationTestCase {
                    wei: "1234567891234567891",
                    kwei: "1234567891234567",
                    mwei: "1234567891234",
                    gwei: "1234567891",
                    szabo: "1234567",
                    finney: "1234",
                    ether: "1",
                },
                AmountDenominationTestCase {
                    wei: "1000000000000000000000000",
                    kwei: "1000000000000000000000",
                    mwei: "1000000000000000000",
                    gwei: "1000000000000000",
                    szabo: "1000000000000",
                    finney: "1000000000",
                    ether: "1000001",
                },
            ];

            #[should_panic]
            #[test]
            fn test_invalid_finney_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_finney(amounts.finney, amounts.wei));
            }

            #[should_panic]
            #[test]
            fn test_invalid_szabo_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_szabo(amounts.szabo, amounts.wei));
            }

            #[should_panic]
            #[test]
            fn test_invalid_gwei_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_gwei(amounts.gwei, amounts.wei));
            }

            #[should_panic]
            #[test]
            fn test_invalid_mwei_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_mwei(amounts.mwei, amounts.wei));
            }

            #[should_panic]
            #[test]
            fn test_invalid_kwei_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_kwei(amounts.kwei, amounts.wei));
            }

            #[should_panic]
            #[test]
            fn test_invalid_eth_conversion() {
                INVALID_TEST_AMOUNTS
                    .iter()
                    .for_each(|amounts| test_from_eth(amounts.ether, amounts.wei));
            }
        }
    }
}
