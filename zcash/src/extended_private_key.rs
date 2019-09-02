use crate::address::ZcashAddress;
use crate::derivation_path::ZcashDerivationPath;
use crate::extended_public_key::ZcashExtendedPublicKey;
use crate::format::ZcashFormat;
use crate::librustzcash::zip32::ExtendedSpendingKey;
use crate::network::ZcashNetwork;
use crate::private_key::{SaplingSpendingKey, ZcashPrivateKey};
use crate::public_key::ZcashPublicKey;
use wagyu_model::{
    Address, AddressError, ChildIndex, DerivationPath, ExtendedPrivateKey, ExtendedPrivateKeyError, ExtendedPublicKey,
    PublicKey,
};

use bech32::{Bech32, FromBase32, ToBase32};
use std::{cmp::Ordering, fmt, fmt::Display, marker::PhantomData, str::FromStr};

/// Represents a Zcash extended private key
#[derive(Debug, Clone)]
pub struct ZcashExtendedPrivateKey<N: ZcashNetwork> {
    /// The extended spending key
    extended_spending_key: ExtendedSpendingKey<N>,
}

impl<N: ZcashNetwork> ExtendedPrivateKey for ZcashExtendedPrivateKey<N> {
    type Address = ZcashAddress<N>;
    type DerivationPath = ZcashDerivationPath<N>;
    type ExtendedPublicKey = ZcashExtendedPublicKey<N>;
    type Format = ZcashFormat;
    type PrivateKey = ZcashPrivateKey<N>;
    type PublicKey = ZcashPublicKey<N>;

    /// Returns a new Zcash extended private key.
    fn new(seed: &[u8], _format: &Self::Format, path: &Self::DerivationPath) -> Result<Self, ExtendedPrivateKeyError> {
        Ok(Self::new_master(seed, _format)?.derive(path)?)
    }

    /// Returns a new Zcash extended private key.
    fn new_master(seed: &[u8], _: &Self::Format) -> Result<Self, ExtendedPrivateKeyError> {
        Ok(Self {
            extended_spending_key: ExtendedSpendingKey::master(seed),
        })
    }

    /// Returns the extended private key of the given derivation path.
    fn derive(&self, path: &Self::DerivationPath) -> Result<Self, ExtendedPrivateKeyError> {
        let mut extended_private_key = self.clone();
        for index in path.to_vec()?.into_iter() {
            extended_private_key = Self {
                extended_spending_key: extended_private_key
                    .extended_spending_key
                    .derive_child(ChildIndex::from(index.to_index())),
            };
        }
        Ok(extended_private_key)
    }

    /// Returns the extended public key of the corresponding extended private key.
    fn to_extended_public_key(&self) -> Self::ExtendedPublicKey {
        Self::ExtendedPublicKey::from_extended_private_key(self)
    }

    /// Returns the private key of the corresponding extended private key.
    fn to_private_key(&self) -> Self::PrivateKey {
        ZcashPrivateKey::<N>::Sapling(SaplingSpendingKey {
            spending_key: None,
            ask: self.extended_spending_key.expsk.ask,
            nsk: self.extended_spending_key.expsk.nsk,
            ovk: self.extended_spending_key.expsk.ovk,
            _network: PhantomData,
        })
    }

    /// Returns the public key of the corresponding extended private key.
    fn to_public_key(&self) -> Self::PublicKey {
        Self::PublicKey::from_private_key(&self.to_private_key())
    }

    /// Returns the address of the corresponding extended private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_private_key(&self.to_private_key(), format)
    }
}

impl<N: ZcashNetwork> ZcashExtendedPrivateKey<N> {
    /// Returns the extended spending key of the Zcash extended private key.
    pub fn to_extended_spending_key(&self) -> ExtendedSpendingKey<N> {
        self.extended_spending_key.clone()
    }
}

impl<N: ZcashNetwork> FromStr for ZcashExtendedPrivateKey<N> {
    type Err = ExtendedPrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bech32 = Bech32::from_str(s)?;
        // Check that the network prefix is correct
        let _ = N::from_extended_private_key_prefix(bech32.hrp())?;

        let data: Vec<u8> = FromBase32::from_base32(bech32.data())?;
        match ExtendedSpendingKey::read(data.as_slice()) {
            Ok(extended_spending_key) => Ok(Self { extended_spending_key }),
            Err(error) => Err(ExtendedPrivateKeyError::Message(error.to_string())),
        }
    }
}

impl<N: ZcashNetwork> Display for ZcashExtendedPrivateKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut data = vec![];
        match self.extended_spending_key.write(&mut data) {
            Ok(_) => (),
            Err(_) => return Err(fmt::Error),
        };
        match Bech32::new(N::to_extended_private_key_prefix(), data.to_base32()) {
            Ok(key) => write!(f, "{}", key),
            _ => Err(fmt::Error),
        }
    }
}

impl<N: ZcashNetwork> PartialEq for ZcashExtendedPrivateKey<N> {
    fn eq(&self, other: &Self) -> bool {
        self.extended_spending_key == other.extended_spending_key
    }
}

impl<N: ZcashNetwork> Eq for ZcashExtendedPrivateKey<N> {}

impl<N: ZcashNetwork> PartialOrd for ZcashExtendedPrivateKey<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.to_string().cmp(&other.to_string()))
    }
}

impl<N: ZcashNetwork> Ord for ZcashExtendedPrivateKey<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;

    use hex;

    fn test_new<N: ZcashNetwork>(expected_extended_private_key: &str, seed: &str, path: &str) {
        let seed = hex::decode(seed).unwrap();
        let path = ZcashDerivationPath::from_str(path).unwrap();
        let extended_private_key =
            ZcashExtendedPrivateKey::<N>::new(&seed, &ZcashFormat::Sapling(None), &path).unwrap();
        assert_eq!(expected_extended_private_key, extended_private_key.to_string());
    }

    fn test_to_extended_public_key<N: ZcashNetwork>(expected_extended_public_key: &str, seed: &str, path: &str) {
        let seed = hex::decode(seed).unwrap();
        let path = ZcashDerivationPath::from_str(path).unwrap();
        let extended_private_key =
            ZcashExtendedPrivateKey::<N>::new(&seed, &ZcashFormat::Sapling(None), &path).unwrap();
        let extended_public_key = extended_private_key.to_extended_public_key();
        assert_eq!(expected_extended_public_key, extended_public_key.to_string());
    }

    fn test_to_address<N: ZcashNetwork>(expected_address: &str, seed: &str, path: &str) {
        let seed = hex::decode(seed).unwrap();
        let path = ZcashDerivationPath::from_str(path).unwrap();
        let extended_private_key =
            ZcashExtendedPrivateKey::<N>::new(&seed, &ZcashFormat::Sapling(None), &path).unwrap();
        let format = &ZcashFormat::Sapling(Some(ZcashAddress::<N>::get_diversifier(expected_address).unwrap()));
        let address = extended_private_key.to_address(&format).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_str<N: ZcashNetwork>(expected_extended_private_key: &str) {
        let extended_private_key = ZcashExtendedPrivateKey::<N>::from_str(&expected_extended_private_key).unwrap();
        assert_eq!(expected_extended_private_key, extended_private_key.to_string());
    }

    fn test_to_string<N: ZcashNetwork>(expected_extended_private_key: &str, seed: &str, path: &str) {
        let seed = hex::decode(seed).unwrap();
        let path = ZcashDerivationPath::from_str(path).unwrap();
        let extended_private_key =
            ZcashExtendedPrivateKey::<N>::new(&seed, &ZcashFormat::Sapling(None), &path).unwrap();
        assert_eq!(expected_extended_private_key, extended_private_key.to_string());
    }

    mod sapling_mainnet {
        use super::*;

        type N = Mainnet;

        // (derivation_path, seed, extended_private_key, extended_public_key, address)
        const KEYPAIRS: [(&str, &str, &str, &str, &str); 5] = [
            (
                "m/32'/133'/0'",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "secret-extended-key-main1qvmjmz6rqqqqpqzwtfucl5xld0ptzguvaate2mhn255ts7jtym9ram4j3vgg4g9wj2xetfdh8gepzmg3utfe96se4r0zhx6c02dpn9w46l75scpx6m6sh8ulfrf8j7yqkjk8vqcq279chxw9wpt2r2js8x4pqvn5j7dpc9sv3m5ze9p4fr2wx0605vr64dqupvzg2x3pmw7pty5gddk63vkxhekc7lq8lgdzmtcsehsn0ml404v0ztclm8utupzcvujfk4ylqk5sqsqplg80g",
                "zviews1qvmjmz6rqqqqpqzwtfucl5xld0ptzguvaate2mhn255ts7jtym9ram4j3vgg4g9wjgca9sw392zzfkn62uvctjgspy86atg2myma0yrgvfa04cv3dnwvrmkrw24zgqkwwfs3l3ejua8rr8z92tfsjxlpe0fws4vnxkuq0s943m5ze9p4fr2wx0605vr64dqupvzg2x3pmw7pty5gddk63vkxhekc7lq8lgdzmtcsehsn0ml404v0ztclm8utupzcvujfk4ylqk5sqsqtgueax",
                "zs1mrhc9y7jdh5r9ece8u5khgvj9kg0zgkxzdduyv0whkg7lkcrkx5xqem3e48avjq9wn2rukydkwn",
            ),
            (
                "m/32'/133'/1'",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "secret-extended-key-main1qvmjmz6rqyqqpqpe689xtr2ltlzpk6cwcla2df93lh7mljzprhwy2m2lurkjw394suv43l9px5qu045unzepdk4vwhdac4w0a39hny8an5f96t6lnmtqxfytsjcvgeq2k5hmak9hyc7gtwk4nnch2p4ra4uvn35r6lndu7qq9f4lzxuudu8znhjz2cwdu85er02upqfjdpy2m85xl2ayp9gvkn4dpsf6dqcckdmzan5fq7p0elwt2luas4pf7vtw7gqrmaty79rm9zsjla3s5",
                "zviews1qvmjmz6rqyqqpqpe689xtr2ltlzpk6cwcla2df93lh7mljzprhwy2m2lurkjw394slfe26kmqrdrz2kgcffmpgw5sxmj2jsdq4snmtmdyfpce9nth9u5ugemq337ygchv9m2drjnpjltgcsf6j9uvhyld535hmqwyeefe50r9f4lzxuudu8znhjz2cwdu85er02upqfjdpy2m85xl2ayp9gvkn4dpsf6dqcckdmzan5fq7p0elwt2luas4pf7vtw7gqrmaty79rm9zsket6md",
                "zs1nahqh7g2rr7qhxur460j8t2rtpjgvwzg9dw7lzt4vddkdlv2wzpnt7frtgccdmq0qvlcgarqada",
            ),
            (
                "m/32'/133'/2'",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "secret-extended-key-main1qvmjmz6rqgqqpqxzjrsqsh65a04krp4k0enw50r5fqeke6vr4r5hy9nxvwy5hwp73gydw6vrnj7fekehpljpjpaw56tvtnxq9la4meant53359l7xzysfcu8gdg70gtumtwu9enjzw8md0tzlcagwhfqcr4e4yl8gsfqaxqxgwq76fa9qqh202wgwvuav6apge6707qxm9vqktn3cngkds2jgwjhkt8znvwyg8aks56dupzpuht4ctdzgennwtv6umdkea3kj06ympsff7rd0",
                "zviews1qvmjmz6rqgqqpqxzjrsqsh65a04krp4k0enw50r5fqeke6vr4r5hy9nxvwy5hwp73g87cjj92w772cu0l9avycnrthwwflgsaxu7akem72mq5n9szucwr9cakhgfyxng50jd0qmeqah507ex8z9gwjskc9xay89vls83g367gwq76fa9qqh202wgwvuav6apge6707qxm9vqktn3cngkds2jgwjhkt8znvwyg8aks56dupzpuht4ctdzgennwtv6umdkea3kj06ympsx6p4vv",
                "zs13pfncwv2f8p9z0wg293t7gs2ht68mjvr798fprw64fej9kapv5cmcch0uag0u46u352fk5cmp2h",
            ),
            (
                "m/32'/133'/3'",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "secret-extended-key-main1qvmjmz6rqvqqpqr0e0n75aysuuw3rmtqard3g536jmq6qvj07cd5sp0edhelkha7cf3fxc7q00q0laqsdshygdh8thhfspsrsvxsnpcntg8m2asqxfdqrd9q7guzt6qp9xnpun48xp8kdfs4hm8axxzvgn4gc7zhww2y5cctc6tsgzs0qry53mewzyxtpxlwjzj206lyyjc93myajunjl820n458mghcnsspcm6l52k857lh8m3jx3x384hcn6ykq3fxzvsjl6vdpnqk9efsa",
                "zviews1qvmjmz6rqvqqpqr0e0n75aysuuw3rmtqard3g536jmq6qvj07cd5sp0edhelkha7cfg8e3c9934gpd20q84cl7m2a48r6hkv2re5gurkvyklxsfdpxp9dtrhv77hc7e7vuzmcwwgdg3gqrnke4grykxel28m3v5twx0fsd3tc6tsgzs0qry53mewzyxtpxlwjzj206lyyjc93myajunjl820n458mghcnsspcm6l52k857lh8m3jx3x384hcn6ykq3fxzvsjl6vdpnqaspl85",
                "zs12t7k4m00haqpvv7zu3fj290te72mes45hrjdvakl44lp0yjudhacvu09y4zdct9qwh3xzhr7pp5",
            ),
            (
                "m/32'/133'/4'",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "secret-extended-key-main1qvmjmz6rqsqqpqzl47k8dzwav0pll77y7sfvhvz2yft0h4lc2l0zr4n43k6t32s5v8844vrzuuus8r2vzc6g40s9serjqstmhas56l27vzlva4tvf9qsfadzj8afz0cncdlg5lvgpx4ss8kzhkqkscp77l267snmdepanlq9lnnead982y9nh6tkr8xtafh7jkv88gvn376l8letdmv7sjwfd5papq2x9qgpf6azdffxgllr3cwegmuep386tjhly7ace66hv43v2hgqdlhla",
                "zviews1qvmjmz6rqsqqpqzl47k8dzwav0pll77y7sfvhvz2yft0h4lc2l0zr4n43k6t32s5v9e4ey5qlfqe7pyxra7y0am5rwp94ujgnqt7q447u8yfjnujee89mh3ysu29d9nwyj3vphnp9250ez6dsl73569eynexnqw94acmqv74lnnead982y9nh6tkr8xtafh7jkv88gvn376l8letdmv7sjwfd5papq2x9qgpf6azdffxgllr3cwegmuep386tjhly7ace66hv43v2hg0z7h3s",
                "zs1vjfnfr52acgj4pl4lfj7r3tsvk4dx62qrczapk4fdc9umz0x00ceh6e6cax4n8v5tpdxs2tcwz3",
            ),
        ];

        #[test]
        fn new() {
            KEYPAIRS.iter().for_each(|(path, seed, extended_private_key, _, _)| {
                test_new::<N>(extended_private_key, seed, path);
            });
        }

        #[test]
        fn to_extended_public_key() {
            KEYPAIRS.iter().for_each(|(path, seed, _, extended_public_key, _)| {
                test_to_extended_public_key::<N>(extended_public_key, seed, path);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(path, seed, _, _, address)| {
                test_to_address::<N>(address, seed, path);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, _, extended_private_key, _, _)| {
                test_from_str::<N>(extended_private_key);
            });
        }

        #[test]
        fn to_string() {
            KEYPAIRS.iter().for_each(|(path, seed, extended_private_key, _, _)| {
                test_to_string::<N>(extended_private_key, seed, path);
            });
        }
    }

    mod sapling_testnet {
        use super::*;

        type N = Testnet;

        // (derivation_path, seed, extended_private_key, extended_public_key, address)
        const KEYPAIRS: [(&str, &str, &str, &str, &str); 5] = [
            (
                "m/32'/1'/0'",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "secret-extended-key-test1qwsr5qydqqqqpqpnrk0cm9lpz7t962vcmk9j4kzg9klc2n7xd7scxe2h4q3rermc984wu6vp80vn6y7ndakz0qwqvwt9aqe2dgjmrd423quaq8mll4vqumnv8u8w5yj7zphcys9g6vmwh5yzdyxu40xgmeta8yn6t9k3v3qxac5f28zxyuqmqf990y3vc7r3am2p4nkd7xzd96uve9y58qmcj9rqcjf0520yq8tc0wzhurc92refdm7pw5k74nyfehhwmczgawap2agtcmrue",
                "zviewtestsapling1qwsr5qydqqqqpqpnrk0cm9lpz7t962vcmk9j4kzg9klc2n7xd7scxe2h4q3rermc9yg0machcn8ug75zvynd3hekrhjmqrl8jwuhfghaf4w6er7u30ay8mfh6jwwmtz3ps7p2x3cldyjqz7a8m4ueaclg946xndymv696gn3ac5f28zxyuqmqf990y3vc7r3am2p4nkd7xzd96uve9y58qmcj9rqcjf0520yq8tc0wzhurc92refdm7pw5k74nyfehhwmczgawap2ages8ete",
                "ztestsapling1wtcy0nkfjr95rge54hewtezgghqdzgw9c3mvfwh5vy4rw97ktl3h4uxgrmrydny089qaq0shgkz",
            ),
            (
                "m/32'/1'/1'",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "secret-extended-key-test1qwsr5qydqyqqpqzqk5l0t4c9xuuq5e2dssc0zujdhwq0gd4azcj7fr8024e26h6vsc53e68y7sazz6tumf8tksxjyuwlwsd5c5ujds7w0t94703cssysemslfqyy836j3jvs06vztp8dy992h94vxwylc8vy30f2p4y93rqry6hqalvf5cptwsm4c7e33pkcgcnvqa49zjtqj6t42wz5zk9g5uux9xx86w4fyzqm0hr2vegkmskp6pwm2mtgakuh304hs5fnejfwwgq0qr9s5",
                "zviewtestsapling1qwsr5qydqyqqpqzqk5l0t4c9xuuq5e2dssc0zujdhwq0gd4azcj7fr8024e26h6vseu93468xwdt90n2450yz83jja00jw0yuguu923w0knf3j063q4rnjwvx3edc7qmtqljm5yx5txl2jzgqs29smafafxnjrppkqlym9gmy6hqalvf5cptwsm4c7e33pkcgcnvqa49zjtqj6t42wz5zk9g5uux9xx86w4fyzqm0hr2vegkmskp6pwm2mtgakuh304hs5fnejfwwgq6qyuru",
                "ztestsapling1jpzye7n502gsvqwf2fhzs4fr2963e2dd20vt2knwa79vv78jjwda7evhd2dz4dnecawkwaj6wme",
            ),
            (
                "m/32'/1'/2'",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "secret-extended-key-test1qwsr5qydqgqqpqpnj2axw5t3ljqdlvzst6kuyvvpjahddddjmpcvdrshj8m55d4sksntwnnufm2r585flk2k0xp9eqqwej88z8da0zajy8zt2k2cqtqskkhs43u6x8h3zk6prlggvj8lw9h92ewz843v4py4962tvhv5q3qfddfergen3tw2dzlvsxlqq6fl9geu669726eawuul7hu7hu77h3yn9lvrueff7x4aqydnttlg3sjxw276kkdzmzg0tu4evf7faca7l9g532qyf",
                "zviewtestsapling1qwsr5qydqgqqpqpnj2axw5t3ljqdlvzst6kuyvvpjahddddjmpcvdrshj8m55d4skj60d0lxq7hhttkaecrxtnhkpfdz82cqklxrrqg7a8d4y2hqzj0xf9waqzg7jc23uegmqkktswttrpx3u6dvhrmwfchz9d5m0yykuhkwddfergen3tw2dzlvsxlqq6fl9geu669726eawuul7hu7hu77h3yn9lvrueff7x4aqydnttlg3sjxw276kkdzmzg0tu4evf7faca7l9gstav8h",
                "ztestsapling1459mywfxnfjpa54t8kgst5hlel8nt0u7dccfqearfygxma5rw6wjmmkex602kxw4dfk255uh8f8",
            ),
            (
                "m/32'/1'/3'",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "secret-extended-key-test1qwsr5qydqvqqpqr7wwttap33wmy8pc749ecxvawhuvuypz98dh45qkflv2h92hak9r42yt9aa7vzpql0uj5a3wn83ggjt3apsm5np4zl7up65fkyw6lq2n7rvdqxtz04qm3638k6x8q7xmyxke8gjsqywlktx5elpmp07tqd4lfrfur5nqqzsgmg0umqwqy40sfvrwhzegf26skfzw4thnfsknv0xk50jupw8v2qk2xjylyjendjsq4kyqvcppqerythg0lsltd67qqgwts6w",
                "zviewtestsapling1qwsr5qydqvqqpqr7wwttap33wmy8pc749ecxvawhuvuypz98dh45qkflv2h92hak9zw5ert05snkvcn4d70rhf8pn5dnh94ynjna36qd3fms6zqf4fs3xcywdqjtznjl6ldphwgp3prxgj82h954ns0kdsd7kdkwa2uw5knv4lfrfur5nqqzsgmg0umqwqy40sfvrwhzegf26skfzw4thnfsknv0xk50jupw8v2qk2xjylyjendjsq4kyqvcppqerythg0lsltd67qq4nr537",
                "ztestsapling1grhzc33e6myh7nas0tnkpqvyyy8nrhadlkdtn50fjjzhvfz7tvqr6tgnd6zyvgjttz8c5yqt8m9",
            ),
            (
                "m/32'/1'/4'",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "secret-extended-key-test1qwsr5qydqsqqpq8eawxfv5pm52vdummt4h5tmxvtkyv4ngkppwh66h8skftx3dxr6qu57y0l2mnph528hamqa6vz7cq69cgsfxwjkz42g4d7pzuvsu4qe79quh7ew2kal9yydfdvdprtvh0aq5hr92vg2cp4zycel9t5x8srcnvvfs6lxuvndkek0g732wevn6gynkj7mdjdz4etx3uf88xft9hleeujmydnn3kxcyn5xyjln5tp0kj3fxqrxdzlckgn9hd3v5t4hqq2dgn3r",
                "zviewtestsapling1qwsr5qydqsqqpq8eawxfv5pm52vdummt4h5tmxvtkyv4ngkppwh66h8skftx3dxr6r296ps23af4vmc2jqflm9wx7sxt8zkn2mtw6y28lcrrz29culvt8pk3s4392v8p8h4k3rmputnnjnrn2kzt7yr978e4wq6j3952y5dxcnvvfs6lxuvndkek0g732wevn6gynkj7mdjdz4etx3uf88xft9hleeujmydnn3kxcyn5xyjln5tp0kj3fxqrxdzlckgn9hd3v5t4hqqphp2ga",
                "ztestsapling1zxtaper8nwpd2jx3utel0x6kgx40fh22ky386hxyrtyh7c6t5q04nseel2huxen37e3j2lfad57",
            ),
        ];

        #[test]
        fn new() {
            KEYPAIRS.iter().for_each(|(path, seed, extended_private_key, _, _)| {
                test_new::<N>(extended_private_key, seed, path);
            });
        }

        #[test]
        fn to_extended_public_key() {
            KEYPAIRS.iter().for_each(|(path, seed, _, extended_public_key, _)| {
                test_to_extended_public_key::<N>(extended_public_key, seed, path);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(path, seed, _, _, address)| {
                test_to_address::<N>(address, seed, path);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, _, extended_private_key, _, _)| {
                test_from_str::<N>(extended_private_key);
            });
        }

        #[test]
        fn to_string() {
            KEYPAIRS.iter().for_each(|(path, seed, extended_private_key, _, _)| {
                test_to_string::<N>(extended_private_key, seed, path);
            });
        }
    }
}
