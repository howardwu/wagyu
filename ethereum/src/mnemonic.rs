use crate::address::EthereumAddress;
use crate::extended_private_key::EthereumExtendedPrivateKey;
use crate::extended_public_key::EthereumExtendedPublicKey;
use crate::format::EthereumFormat;
use crate::network::EthereumNetwork;
use crate::private_key::EthereumPrivateKey;
use crate::public_key::EthereumPublicKey;
use crate::wordlist::EthereumWordlist;
use wagyu_model::{ExtendedPrivateKey, Mnemonic, MnemonicCount, MnemonicError, MnemonicExtended};

use bitvec::prelude::*;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use std::{fmt, marker::PhantomData, ops::Div, str, str::FromStr};

const PBKDF2_ROUNDS: usize = 2048;
const PBKDF2_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Represents an Ethereum mnemonic
pub struct EthereumMnemonic<N: EthereumNetwork, W: EthereumWordlist> {
    /// Initial entropy in multiples of 32 bits
    entropy: Vec<u8>,
    /// PhantomData
    _network: PhantomData<N>,
    /// PhantomData
    _wordlist: PhantomData<W>,
}

impl<N: EthereumNetwork, W: EthereumWordlist> MnemonicCount for EthereumMnemonic<N, W> {
    /// Returns a new mnemonic given the word count.
    fn new_with_count<R: Rng>(rng: &mut R, word_count: u8) -> Result<Self, MnemonicError> {
        let length: usize = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            wc => return Err(MnemonicError::InvalidWordCount(wc)),
        };

        let entropy: [u8; 32] = rng.gen();

        Ok(Self {
            entropy: entropy[0..length].to_vec(),
            _network: PhantomData,
            _wordlist: PhantomData,
        })
    }
}

impl<N: EthereumNetwork, W: EthereumWordlist> Mnemonic for EthereumMnemonic<N, W> {
    type Address = EthereumAddress;
    type Format = EthereumFormat;
    type PrivateKey = EthereumPrivateKey;
    type PublicKey = EthereumPublicKey;

    /// Returns a new mnemonic.
    fn new<R: Rng>(rng: &mut R) -> Result<Self, MnemonicError> {
        let entropy: [u8; 16] = rng.gen();
        Ok(Self {
            entropy: entropy.to_vec(),
            _network: PhantomData,
            _wordlist: PhantomData,
        })
    }

    /// Returns the mnemonic for the given phrase.
    fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        let mnemonic = phrase.split(" ").collect::<Vec<&str>>();

        let length = match mnemonic.len() {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            wc => return Err(MnemonicError::InvalidWordCount(wc as u8)),
        };

        let mut entropy: BitVec<Msb0, u8> = BitVec::new();

        for word in mnemonic {
            let index = W::get_index(word)?;
            let index_u8: [u8; 2] = (index as u16).to_be_bytes();
            let index_slice = &BitVec::from_slice(&index_u8)[5..];

            entropy.append(&mut BitVec::<Msb0, u8>::from_bitslice(index_slice));
        }

        let mnemonic = Self {
            entropy: entropy[..length].as_slice().to_vec(),
            _network: PhantomData,
            _wordlist: PhantomData,
        };

        // Ensures the checksum word matches the checksum word in the given phrase.
        match phrase == mnemonic.to_phrase()? {
            true => Ok(mnemonic),
            false => Err(MnemonicError::InvalidPhrase(phrase.into())),
        }
    }

    /// Returns the phrase of the corresponding mnemonic.
    fn to_phrase(&self) -> Result<String, MnemonicError> {
        let length: i32 = match self.entropy.len() {
            16 => 12,
            20 => 15,
            24 => 18,
            28 => 21,
            32 => 24,
            entropy_len => return Err(MnemonicError::InvalidEntropyLength(entropy_len)),
        };

        // Compute the checksum by taking the first ENT / 32 bits of the SHA256 hash
        let mut sha256 = Sha256::new();
        sha256.input(self.entropy.as_slice());

        let hash = sha256.result();
        let hash_0 = BitVec::<Msb0, u8>::from_element(hash[0]);
        let (checksum, _) = hash_0.split_at(length.div(3) as usize);

        // Convert the entropy bytes into bits and append the checksum
        let mut encoding = BitVec::<Msb0, u8>::from_vec(self.entropy.clone());
        encoding.append(&mut checksum.to_vec());

        // Compute the phrase in 11 bit chunks which encode an index into the word list
        let wordlist = W::get_all();
        let phrase = encoding
            .chunks(11)
            .map(|index| {
                // Convert a vector of 11 bits into a u11 number.
                let index = index
                    .iter()
                    .enumerate()
                    .map(|(i, &bit)| (bit as u16) * 2u16.pow(10 - i as u32))
                    .sum::<u16>();

                wordlist[index as usize]
            })
            .collect::<Vec<&str>>();

        Ok(phrase.join(" "))
    }

    /// Returns the private key of the corresponding mnemonic.
    fn to_private_key(&self, password: Option<&str>) -> Result<Self::PrivateKey, MnemonicError> {
        Ok(self.to_extended_private_key(password)?.to_private_key())
    }

    /// Returns the public key of the corresponding mnemonic.
    fn to_public_key(&self, password: Option<&str>) -> Result<Self::PublicKey, MnemonicError> {
        Ok(self.to_extended_private_key(password)?.to_public_key())
    }

    /// Returns the address of the corresponding mnemonic.
    fn to_address(&self, password: Option<&str>, format: &Self::Format) -> Result<Self::Address, MnemonicError> {
        Ok(self.to_extended_private_key(password)?.to_address(format)?)
    }
}

impl<N: EthereumNetwork, W: EthereumWordlist> MnemonicExtended for EthereumMnemonic<N, W> {
    type ExtendedPrivateKey = EthereumExtendedPrivateKey<N>;
    type ExtendedPublicKey = EthereumExtendedPublicKey<N>;

    /// Returns the extended private key of the corresponding mnemonic.
    fn to_extended_private_key(&self, password: Option<&str>) -> Result<Self::ExtendedPrivateKey, MnemonicError> {
        Ok(Self::ExtendedPrivateKey::new_master(
            self.to_seed(password)?.as_slice(),
            &EthereumFormat::Standard,
        )?)
    }

    /// Returns the extended public key of the corresponding mnemonic.
    fn to_extended_public_key(&self, password: Option<&str>) -> Result<Self::ExtendedPublicKey, MnemonicError> {
        Ok(self.to_extended_private_key(password)?.to_extended_public_key())
    }
}

impl<N: EthereumNetwork, W: EthereumWordlist> EthereumMnemonic<N, W> {
    /// Compares the given phrase against the phrase extracted from its entropy.
    pub fn verify_phrase(phrase: &str) -> bool {
        Self::from_phrase(phrase).is_ok()
    }

    /// Returns a seed using the given password and mnemonic.
    fn to_seed(&self, password: Option<&str>) -> Result<Vec<u8>, MnemonicError> {
        let mut seed = vec![0u8; PBKDF2_BYTES];
        let salt = format!("mnemonic{}", password.unwrap_or(""));
        pbkdf2::<Hmac<Sha512>>(&self.to_phrase()?.as_bytes(), salt.as_bytes(), PBKDF2_ROUNDS, &mut seed);
        Ok(seed)
    }
}

impl<N: EthereumNetwork, W: EthereumWordlist> FromStr for EthereumMnemonic<N, W> {
    type Err = MnemonicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_phrase(s)
    }
}

impl<N: EthereumNetwork, W: EthereumWordlist> fmt::Display for EthereumMnemonic<N, W> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self.to_phrase() {
                Ok(phrase) => phrase,
                _ => return Err(fmt::Error),
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;
    use crate::wordlist::*;

    use hex;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    fn test_new_with_count<N: EthereumNetwork, W: EthereumWordlist>(word_count: u8) {
        let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);
        let mnemonic = EthereumMnemonic::<N, W>::new_with_count(rng, word_count).unwrap();
        test_from_phrase::<N, W>(&mnemonic.entropy, &mnemonic.to_phrase().unwrap());
    }

    fn test_from_phrase<N: EthereumNetwork, W: EthereumWordlist>(expected_entropy: &Vec<u8>, phrase: &str) {
        let mnemonic = EthereumMnemonic::<N, W>::from_phrase(phrase).unwrap();
        assert_eq!(&expected_entropy[..], &mnemonic.entropy[..]);
        assert_eq!(phrase, mnemonic.to_phrase().unwrap());
    }

    fn test_to_phrase<N: EthereumNetwork, W: EthereumWordlist>(expected_phrase: &str, entropy: &Vec<u8>) {
        let mnemonic = EthereumMnemonic::<N, W> {
            entropy: entropy.clone(),
            _network: PhantomData,
            _wordlist: PhantomData,
        };
        assert_eq!(&entropy[..], &mnemonic.entropy[..]);
        assert_eq!(expected_phrase, mnemonic.to_phrase().unwrap());
    }

    fn test_verify_phrase<N: EthereumNetwork, W: EthereumWordlist>(phrase: &str) {
        assert!(EthereumMnemonic::<N, W>::verify_phrase(phrase));
    }

    fn test_to_seed<N: EthereumNetwork, W: EthereumWordlist>(
        expected_seed: &str,
        password: Option<&str>,
        mnemonic: EthereumMnemonic<N, W>,
    ) {
        assert_eq!(expected_seed, &hex::encode(mnemonic.to_seed(password).unwrap()))
    }

    fn test_to_extended_private_key<N: EthereumNetwork, W: EthereumWordlist>(
        expected_extended_private_key: &str,
        password: Option<&str>,
        phrase: &str,
    ) {
        let mnemonic = EthereumMnemonic::<N, W>::from_phrase(phrase).unwrap();
        let extended_private_key = mnemonic.to_extended_private_key(password).unwrap();
        assert_eq!(expected_extended_private_key, extended_private_key.to_string());
    }

    /// Test vectors from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    mod english {
        use super::*;

        type N = Mainnet;
        type W = English;

        const PASSWORD: &str = "TREZOR";
        const NO_PASSWORD_STR: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

        // (entropy, phrase, seed, extended_private_key)
        const KEYPAIRS: [(&str, &str, &str, &str); 26] = [
            (
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
                "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq"
            ),
            (
                "80808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
                "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq"
            ),
            (
                "ffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
                "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
            ),
            (
                "000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
                "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
                "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU"
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
                "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
                "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7"
            ),
            (
                "808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
                "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
                "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae"
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
                "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
                "xprv9s21ZrQH143K36Ao5jHRVhFGDbLP6FCx8BEEmpru77ef3bmA928BxsqvVM27WnvvyfWywiFN8K6yToqMaGYfzS6Db1EHAXT5TuyCLBXUfdm"
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
                "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM"
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
                "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
                "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU"
            ),
            (
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
                "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
                "xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo"
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
                "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
                "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB"
            ),
            (
                "9e885d952ad362caeb4efe34a8e91bd2",
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
                "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
                "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH"
            ),
            (
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
                "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
                "xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK"
            ),
            (
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
                "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
                "xprv9s21ZrQH143K2XTAhys3pMNcGn261Fi5Ta2Pw8PwaVPhg3D8DWkzWQwjTJfskj8ofb81i9NP2cUNKxwjueJHHMQAnxtivTA75uUFqPFeWzk"
            ),
            (
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "scheme spot photo card baby mountain device kick cradle pact join borrow",
                "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
                "xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6"
            ),
            (
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
                "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
                "xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt"
            ),
            (
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
                "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
                "xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems"
            ),
            (
                "23db8160a31d3e0dca3688ed941adbf3",
                "cat swing flag economy stadium alone churn speed unique patch report train",
                "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
                "xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ"
            ),
            (
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
                "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
                "xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh"
            ),
            (
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
                "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
                "xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm"
            ),
            (
                "f30f8c1da665478f49b001d94c5fc452",
                "vessel ladder alter error federal sibling chat ability sun glass valve picture",
                "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
                "xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps"
            ),
            (
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
                "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
                "xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYaPUZJhJx8S5j6puX"
            ),
            (
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
                "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
                "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"
            ),
            (
                "d292b36884b647974ff2167649e8255c8226a942",
                "spoon night surface annual good slight divert drift iron exercise announce ribbon carbon feed answer",
                "1c662e030a65b8e943a7f7fb304a1ecf415dcd1c99bfd587efae245ca9270058e853df0070abe61af152756c63a0b67ed74bf6e916b112289499e6052ccacc19",
                "xprv9s21ZrQH143K3pskpuVw5DMEBZ1hWZnVxwTpPc4QqjCPHbinjx5dyosHqPubQbGRoKdPci6hYRdr2QNDc2GwhCpSEAtKMrsjiBbYJJLfFj9"
            ),
            (
                "608945c274e181d9376c651255db6481ccb525532554eaea611cbbd1",
                "gauge enforce identify truth blossom uncle tank million banner put summer adjust slender naive erode pride turtle fantasy elbow jeans bar",
                "79da8e9aaeea7b28f9045fb0e4763fef5a7aae300b34c9f32aa8bb9a4aacd99896943beb22bbf9b50646658fd72cdf993b16a7cb5b7a77d1b443cf41f5183067",
                "xprv9s21ZrQH143K2Cy1ePyrB2tRcm97F6YFMzDZkhy9QS6PeCDtiDuZLrtt9WBfWhXEz8W5KbSnF7nWBKFzStfs8UPeyzbrCPPbHLC25HB8aFe"
            )
        ];

        #[test]
        fn new() {
            let word_counts: [u8; 5] = [12, 15, 18, 21, 24];
            word_counts.iter().for_each(|word_count| {
                test_new_with_count::<N, W>(*word_count);
            })
        }

        #[test]
        fn from_phrase() {
            KEYPAIRS.iter().for_each(|(entropy_str, phrase, _, _)| {
                let entropy: Vec<u8> = Vec::from(hex::decode(entropy_str).unwrap());
                test_from_phrase::<N, W>(&entropy, phrase);
            })
        }

        #[test]
        fn to_phrase() {
            KEYPAIRS.iter().for_each(|(entropy_str, phrase, _, _)| {
                let entropy: Vec<u8> = Vec::from(hex::decode(entropy_str).unwrap());
                test_to_phrase::<N, W>(phrase, &entropy);
            })
        }

        #[test]
        fn verify_phrase() {
            KEYPAIRS.iter().for_each(|(_, phrase, _, _)| {
                test_verify_phrase::<N, W>(phrase);
            });
        }

        #[test]
        fn to_seed() {
            KEYPAIRS.iter().for_each(|(entropy_str, _, expected_seed, _)| {
                let entropy: Vec<u8> = Vec::from(hex::decode(entropy_str).unwrap());
                let mnemonic = EthereumMnemonic::<N, W> {
                    entropy,
                    _network: PhantomData,
                    _wordlist: PhantomData,
                };
                test_to_seed::<N, W>(expected_seed, Some(PASSWORD), mnemonic);
            });
        }

        #[test]
        fn to_seed_no_password() {
            let (entropy_str, _, _, _) = KEYPAIRS[0];
            let entropy: Vec<u8> = Vec::from(hex::decode(entropy_str).unwrap());
            let mnemonic = EthereumMnemonic::<N, W> {
                entropy,
                _network: PhantomData,
                _wordlist: PhantomData,
            };
            test_to_seed::<N, W>(NO_PASSWORD_STR, None, mnemonic);
        }

        #[test]
        fn to_extended_private_key() {
            KEYPAIRS
                .iter()
                .for_each(|(_, phrase, _, expected_extended_private_key)| {
                    test_to_extended_private_key::<N, W>(expected_extended_private_key, Some(PASSWORD), phrase);
                });
        }
    }

    mod test_invalid {
        use super::*;

        type N = Mainnet;
        type W = English;

        const INVALID_WORD_COUNT: u8 = 11;
        const INVALID_PHRASE_LENGTH: &str =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        const INVALID_PHRASE_WORD: &str =
            "abandoz abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        const INVALID_PHRASE_CHECKSUM: &str =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

        #[test]
        #[should_panic(expected = "InvalidWordCount(11)")]
        fn new_invalid_word_count() {
            let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);
            let _mnemonic = EthereumMnemonic::<N, W>::new_with_count(rng, INVALID_WORD_COUNT).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidWord(\"abandoz\")")]
        fn from_phrase_invalid_word() {
            let _mnemonic = EthereumMnemonic::<N, W>::from_phrase(INVALID_PHRASE_WORD).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidWordCount(13)")]
        fn from_phrase_invalid_length() {
            let _mnemonic = EthereumMnemonic::<N, W>::from_phrase(INVALID_PHRASE_LENGTH).unwrap();
        }

        #[test]
        #[should_panic(
            expected = "InvalidPhrase(\"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon\")"
        )]
        fn from_phrase_invalid_checksum() {
            let _mnemonic = EthereumMnemonic::<N, W>::from_phrase(INVALID_PHRASE_CHECKSUM).unwrap();
        }

        #[test]
        fn verify_invalid_phrase() {
            assert!(!EthereumMnemonic::<N, W>::verify_phrase(INVALID_PHRASE_LENGTH));
        }
    }
}
