#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::address::{MoneroAddress, Format};
use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;

use libc::c_char;
use serde::{Deserialize, Serialize};
use serde::export::PhantomData;
use serde_json;
use std::ffi::CStr;
use std::ffi::CString;
use std::str;
use wagyu_model::{TransactionError, Transaction};

/// Represents a Monero transaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MoneroTransaction<N: MoneroNetwork> {
    tx_must_be_reconstructed: bool,
    serialized_signed_tx: String,
    tx_hash: String,
    tx_key: String,
    tx_pub_key: String,
    _network: PhantomData<N>,
}

impl<N: MoneroNetwork> Transaction for MoneroTransaction<N> {
    type Address = MoneroAddress<N>;
    type Format = Format;
    type PrivateKey = MoneroPrivateKey<N>;
    type PublicKey = MoneroPublicKey<N>;
}

/// External C methods from mymonero-core-cpp library
#[link(name = "mymonero-core-cpp", kind = "static")]
extern "C" {
    fn extern_decode_address(arg_arr: *const c_char) -> *const c_char;

    fn extern_send_step1(arg_arr: *const c_char) -> *const c_char;

    fn extern_send_step2(arg_arr: *const c_char) -> *const c_char;
}

#[derive(Serialize, Deserialize)]
pub struct UnspentOutput {
    amount: u64,
    index: u64,
    global_index: u64,
    public_key: String,
    rct: Option<String>,
    tx_pub_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct MixAmountAndOuts {
    amount: u64,
    outputs: Vec<MixOut>,
}

#[derive(Serialize, Deserialize)]
pub struct MixOut {
    global_index: u64,
    public_key: String,
    rct: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionParameters {
    change_amount: u64,
    final_total_wo_fee: u64,
    mixin: u32,
    using_fee: u64,
    using_outs: Vec<UnspentOutput>,
}

#[derive(Serialize, Deserialize)]
struct PrepareTransaction {
    is_sweeping: String,
    fee_mask: String,
    fee_per_b: String,
    fork_version: String,
    sending_amount: String,
    priority: String,
    unspent_outs: Vec<UnspentOutput>,

    #[serde(skip_serializing_if = "String::is_empty")]
    payment_id_string: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    passedIn_attemptAt_fee: String,
}

impl Default for PrepareTransaction {
    fn default() -> Self {
        Self {
            is_sweeping: String::new(),
            fee_mask: String::new(),
            fee_per_b: String::new(),
            fork_version: String::new(),
            sending_amount: String::new(),
            priority: String::new(),
            unspent_outs: Vec::<UnspentOutput>::new(),
            payment_id_string: String::new(),
            passedIn_attemptAt_fee: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CreateTransaction {
    change_amount: String,
    fee_amount: String,
    fee_mask: String,
    fee_per_b: String,
    final_total_wo_fee: String,
    fork_version: String,
    from_address_string: String,
    mix_outs: Vec<MixAmountAndOuts>,
    nettype_string: String,
    priority: String,
    sec_spendKey_string: String,
    sec_viewKey_string: String,
    to_address_string: String,
    unlock_time: String,
    using_outs: Vec<UnspentOutput>,

    #[serde(skip_serializing_if = "String::is_empty")]
    payment_id_string: String,
}

impl Default for CreateTransaction {
    fn default() -> Self {
        Self {
            change_amount: String::new(),
            fee_amount: String::new(),
            fee_mask: String::new(),
            fee_per_b: String::new(),
            final_total_wo_fee: String::new(),
            fork_version: String::new(),
            from_address_string: String::new(),
            mix_outs: Vec::<MixAmountAndOuts>::new(),
            nettype_string: String::new(),
            priority: String::new(),
            sec_spendKey_string: String::new(),
            sec_viewKey_string: String::new(),
            to_address_string: String::new(),
            unlock_time: String::new(),
            using_outs: Vec::<UnspentOutput>::new(),
            payment_id_string: String::new(),
        }
    }
}

impl<N: MoneroNetwork> MoneroTransaction<N> {

    // Call into mymonero-core-cpp library json interface functions to send transaction

    /// Returns Monero transaction fee parameters and decoy outputs
    /// calls https://github.com/mymonero/mymonero-core-cpp/blob/20b6cbabf230ae4ebe01d05c859aad397741cf8f/src/serial_bridge_index.cpp#L445
    pub fn prepare_transaction(
        is_sweeping: bool,
        fee_mask: u64,
        fee_per_b: u64,
        fork_version: u8,
        sending_amount: u64,
        passed_in_attempt_at_fee: String,
        payment_id_string: String,
        priority: u32,
        unspent_outs: Vec<UnspentOutput>,
    ) -> Result<TransactionParameters, TransactionError> {
        let args_value = PrepareTransaction {
            is_sweeping: is_sweeping.to_string(),
            fee_mask: fee_mask.to_string(),
            fee_per_b: fee_per_b.to_string(),
            fork_version: fork_version.to_string(),
            sending_amount: sending_amount.to_string(),
            priority: priority.to_string(),
            unspent_outs,
            passedIn_attemptAt_fee: passed_in_attempt_at_fee.to_string(),
            payment_id_string: payment_id_string.to_string(),
        };
//        println!("sending step 1: {}", args_value.to_string());

        let response = call_extern_function(
            &serde_json::to_string(&args_value)?,
            extern_send_step1,
        );

//        println!("received step 1: {}", response);

        #[derive(Serialize, Deserialize)]
        struct Step1ResultString {
            change_amount: String,
            final_total_wo_fee: String,
            mixin: String,
            using_fee: String,
            using_outs: Vec<UnspentOutputString>,
        }

        #[derive(Serialize, Deserialize)]
        struct UnspentOutputString {
            amount: String,
            index: String,
            global_index: String,
            public_key: String,
            rct: Option<String>,
            tx_pub_key: String,
        }

        let result: Step1ResultString = match serde_json::from_str(&response) {
            Ok(res) => res,
            Err(_) => return Err(TransactionError::Message(response)),
        };

        let mut using_outs = Vec::<UnspentOutput>::new();
        for unspent_output_string in result.using_outs {
            using_outs.push(UnspentOutput {
                amount: unspent_output_string.amount.parse::<u64>()?,
                index: unspent_output_string.index.parse::<u64>()?,
                global_index: unspent_output_string.global_index.parse::<u64>()?,
                public_key: unspent_output_string.public_key.into(),
                rct: unspent_output_string.rct.into(),
                tx_pub_key: unspent_output_string.tx_pub_key.into(),
            })
        }

        Ok(TransactionParameters {
            change_amount: result.change_amount.parse::<u64>()?,
            final_total_wo_fee: result.final_total_wo_fee.parse::<u64>()?,
            mixin: result.mixin.parse::<u32>()?,
            using_fee: result.using_fee.parse::<u64>()?,
            using_outs,
        })
    }

    /// Returns Monero transaction
    /// calls https://github.com/mymonero/mymonero-core-cpp/blob/20b6cbabf230ae4ebe01d05c859aad397741cf8f/src/serial_bridge_index.cpp#L529
    pub fn create_transaction(
        change_amount: u64,
        fee_amount: u64,
        fee_mask: u64,
        fee_per_b: u64,
        final_total_wo_fee: u64,
        fork_version: u8,
        from_address_string: String,
        mix_outs: Vec<MixAmountAndOuts>,
        nettype_string: String,
        payment_id_string: String,
        priority: u32,
        sec_spend_key_string: String,
        sec_view_key_string: String,
        to_address_string: String,
        unlock_time: u64,
        using_outs: Vec<UnspentOutput>,
    ) -> Result<Self, TransactionError> {
        let args_value = CreateTransaction {
            change_amount: change_amount.to_string(),
            fee_amount: fee_amount.to_string(),
            fee_mask: fee_mask.to_string(),
            fee_per_b: fee_per_b.to_string(),
            fork_version: fork_version.to_string(),
            final_total_wo_fee: final_total_wo_fee.to_string(),
            from_address_string,
            mix_outs,
            nettype_string,
            payment_id_string: payment_id_string.to_string(),
            priority: priority.to_string(),
            sec_spendKey_string: sec_spend_key_string.to_string(),
            sec_viewKey_string: sec_view_key_string.to_string(),
            to_address_string,
            unlock_time: unlock_time.to_string(),
            using_outs,
        };

//        println!("sending step 2: {}", args_value.to_string());

        let response = call_extern_function(
            &serde_json::to_string(&args_value)?,
            extern_send_step2);

//        println!("received step 2: {}", response);

        #[derive(Serialize, Deserialize)]
        struct Step2Result {
            tx_must_be_reconstructed: String,
            serialized_signed_tx: String,
            tx_hash: String,
            tx_key: String,
            tx_pub_key: String,
        }

        let result: Step2Result = match serde_json::from_str(&response) {
            Ok(res) => res,
            Err(_) => return Err(TransactionError::Message(response)),
        };

        Ok(Self {
            tx_must_be_reconstructed: result.tx_must_be_reconstructed.parse::<bool>()?,
            serialized_signed_tx: result.serialized_signed_tx.into(),
            tx_hash: result.tx_hash.into(),
            tx_key: result.tx_key.into(),
            tx_pub_key: result.tx_pub_key.into(),
            _network: PhantomData,
        })
    }
}

/// Make an unsafe external call to a C function
/// the C function should take a character array argument and return a character array
pub fn call_extern_function(
    arg_str: &str,
    function: unsafe extern "C" fn(*const c_char) -> *const c_char,
) -> String {
    // 1. create C string (ends with the zero byte and can't contain one inside)
    let str_arr: CString = CString::new(arg_str).unwrap();

    // 2. make unsafe call to C method (extern "C" method in C++)
    let c_buf: *const c_char = unsafe { function(str_arr.as_ptr()) };

    // 3. make unsafe conversion from pointer to c character array into pointer to rust CStr (i8) type
    // this method is unsafe because from_ptr returns a CStr with an arbitrary lifetime parameter
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };

    // 4. convert to rust string slice
    let str_slice: &str = c_str.to_str().unwrap();

    str_slice.into()
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mainnet;

    type N = Mainnet;

    mod mainnet {
        use super::*;

        #[test]
        fn test_decode_address() {
            let address = "{\"nettype_string\":\"MAINNET\", \"address\":\"43tXwm6UNNvSyMdHU4Jfeg4GRgU7KEVAfHo3B5RrXYMjZMRaowr68y12HSo14wv2qcYqqpG1U5AHrJtBdFHKPDEA9UxK6Hy\"}";
            let str_slice = call_extern_function(address, extern_decode_address);
            println!("result from c++ {:?}", str_slice);
        }

        #[test]
        fn test_prepare_transaction() {
            let unspent_outs_string = "[{\"amount\":3000000000,\"public_key\":\"41be1978f58cabf69a9bed5b6cb3c8d588621ef9b67602328da42a213ee42271\",\"index\":1,\"global_index\":7611174,\"rct\":\"86a2c9f1f8e66848cd99bfda7a14d4ac6c3525d06947e21e4e55fe42a368507eb5b234ccdd70beca8b1fc8de4f2ceb1374e0f1fd8810849e7f11316c2cc063060008ffa5ac9827b776993468df21af8c963d12148622354f950cbe1369a92a0c\",\"tx_id\":5334971,\"tx_hash\":\"9d37c7fdeab91abfd1e7e120f5c49eac17b7ac04a97a0c93b51c172115df21ea\",\"tx_pub_key\":\"bd703d7f37995cc7071fb4d2929594b5e2a4c27d2b7c68a9064500ca7bc638b8\"}]";

            let is_sweeping = false;
            let fee_mask = 10000u64;
            let fee_per_b = 24658u64;
            let fork_version = 10u8;
            let passed_in_attempt_at_fee = "".into();
            let payment_id_string = "d2f602b240fbe624".into();
            let sending_amount = 200000000u64;
            let priority = 1u32;
            let unspent_outs: Vec<UnspentOutput> = serde_json::from_str(unspent_outs_string).unwrap();

            let transaction_parameters = MoneroTransaction::<N>::prepare_transaction(
                is_sweeping,
                fee_mask,
                fee_per_b,
                fork_version,
                sending_amount,
                passed_in_attempt_at_fee,
                payment_id_string,
                priority,
                unspent_outs,
            ).unwrap();

            println!();
            println!("step 1 received");
            println!("mixin: {:?}", transaction_parameters.mixin);
            println!("using fee: {:?}", transaction_parameters.using_fee);
            println!("final_total_wo_fee: {:?}", transaction_parameters.final_total_wo_fee);
            println!("change_amount: {:?}", transaction_parameters.change_amount);
            println!();
        }

        // https://github.com/mymonero/mymonero-core-cpp/blob/20b6cbabf230ae4ebe01d05c859aad397741cf8f/test/test_all.cpp#L347
        #[test]
        fn test_create_transaction() {
            let unspent_outs_string = "[{\"amount\":3000000000,\"public_key\":\"41be1978f58cabf69a9bed5b6cb3c8d588621ef9b67602328da42a213ee42271\",\"index\":1,\"global_index\":7611174,\"rct\":\"86a2c9f1f8e66848cd99bfda7a14d4ac6c3525d06947e21e4e55fe42a368507eb5b234ccdd70beca8b1fc8de4f2ceb1374e0f1fd8810849e7f11316c2cc063060008ffa5ac9827b776993468df21af8c963d12148622354f950cbe1369a92a0c\",\"tx_id\":5334971,\"tx_hash\":\"9d37c7fdeab91abfd1e7e120f5c49eac17b7ac04a97a0c93b51c172115df21ea\",\"tx_pub_key\":\"bd703d7f37995cc7071fb4d2929594b5e2a4c27d2b7c68a9064500ca7bc638b8\"}]";
            let mix_outs_string = "[{\"amount\":0,\"outputs\":[{\"global_index\":7453099,\"public_key\":\"31f3a7fec0f6f09067e826b6c2904fd4b1684d7893dcf08c5b5d22e317e148bb\",\"rct\":\"ea6bcb193a25ce2787dd6abaaeef1ee0c924b323c6a5873db1406261e86145fc\"},{\"global_index\":7500097,\"public_key\":\"f9d923500671da05a1bf44b932b872f0c4a3c88e6b3d4bf774c8be915e25f42b\",\"rct\":\"dcae4267a6c382bcd71fd1af4d2cbceb3749d576d7a3acc473dd579ea9231a52\"},{\"global_index\":7548483,\"public_key\":\"839cbbb73685654b93e824c4843e745e8d5f7742e83494932307bf300641c480\",\"rct\":\"aa99d492f1d6f1b20dcd95b8fff8f67a219043d0d94b4551759016b4888573e7\"},{\"global_index\":7554755,\"public_key\":\"b8860f0697988c8cefd7b4285fbb8bec463f136c2b9a9cadb3e57cebee10717f\",\"rct\":\"327f9b07bee9c4c25b5a990123cd2444228e5704ebe32016cd632866710279b5\"},{\"global_index\":7561477,\"public_key\":\"561d734cb90bc4a64d49d37f85ea85575243e2ed749a3d6dcb4d27aa6bec6e88\",\"rct\":\"b5393e038df95b94bfda62b44a29141cac9e356127270af97193460d51949841\"},{\"global_index\":7567062,\"public_key\":\"db1024ef67e7e73608ef8afab62f49e2402c8da3dc3197008e3ba720ad3c94a8\",\"rct\":\"1fedf95621881b77f823a70aa83ece26aef62974976d2b8cd87ed4862a4ec92c\"},{\"global_index\":7567508,\"public_key\":\"6283f3cd2f050bba90276443fe04f6076ad2ad46a515bf07b84d424a3ba43d27\",\"rct\":\"10e16bb8a8b7b0c8a4b193467b010976b962809c9f3e6c047335dba09daa351f\"},{\"global_index\":7568716,\"public_key\":\"7a7deb4eef81c1f5ce9cbd0552891cb19f1014a03a5863d549630824c7c7c0d3\",\"rct\":\"735d059dc3526334ac705ddc44c4316bb8805d2426dcea9544cde50cf6c7a850\"},{\"global_index\":7571196,\"public_key\":\"535208e354cae530ed7ce752935e555d630cf2edd7f91525024ed9c332b2a347\",\"rct\":\"c3cf838faa14e993536c5581ca582fb0d96b70f713cf88f7f15c89336e5853ec\"},{\"global_index\":7571333,\"public_key\":\"e73f27b7eb001aa7eac13df82814cda65b42ceeb6ef36227c25d5cbf82f6a5e4\",\"rct\":\"5f45f33c6800cdae202b37abe6d87b53d6873e7b30f3527161f44fa8db3104b6\"},{\"global_index\":7571335,\"public_key\":\"fce982dbz8e7a6b71a1e632c7de8c5cbf54e8bacdfbf250f1ffc2a8d2f7055ce3\",\"rct\":\"407bdcc48e70eb3ef2cc22cefee6c6b5a3c59fd17bde12fda5f1a44a0fb39d14\"}]}]";

            let is_sweeping = false;
            let fee_mask = 10000u64;
            let fee_per_b = 24658u64;
            let fork_version = 10u8;
            let passed_in_attempt_at_fee = "".into();
            let payment_id_string = "d2f602b240fbe624".into();
            let sending_amount = 200000000u64;
            let priority = 1u32;
            let unspent_outs: Vec<UnspentOutput> = serde_json::from_str(unspent_outs_string).unwrap();

            let transaction_parameters = MoneroTransaction::<N>::prepare_transaction(
                is_sweeping,
                fee_mask,
                fee_per_b,
                fork_version,
                sending_amount,
                passed_in_attempt_at_fee,
                payment_id_string,
                priority,
                unspent_outs,
            ).unwrap();

            println!();
            println!("step 1 received");
            println!("mixin: {:?}", transaction_parameters.mixin);
            println!("using fee: {:?}", transaction_parameters.using_fee);
            println!("final_total_wo_fee: {:?}", transaction_parameters.final_total_wo_fee);
            println!("change_amount: {:?}", transaction_parameters.change_amount);
            println!();

            let change_amount = transaction_parameters.change_amount;
            let fee_amount = transaction_parameters.using_fee;
            let fee_mask = 10000u64;
            let fee_per_b = 24658u64;
            let final_total_wo_fee = transaction_parameters.final_total_wo_fee;
            let fork_version = 10u8;
            let from_address_string = "43zxvpcj5Xv9SEkNXbMCG7LPQStHMpFCQCmkmR4u5nzjWwq5Xkv5VmGgYEsHXg4ja2FGRD5wMWbBVMijDTqmmVqm93wHGkg".into();
            let mix_outs: Vec<MixAmountAndOuts> = serde_json::from_str(mix_outs_string).unwrap();
            let nettype_string = "MAINNET".into();
            let payment_id_string = "d2f602b240fbe624".into();
            let priority = 1u32;
            let sec_spend_key_string = "4e6d43cd03812b803c6f3206689f5fcc910005fc7e91d50d79b0776dbefcd803".into();
            let sec_view_key_string = "7bea1907940afdd480eff7c4bcadb478a0fbb626df9e3ed74ae801e18f53e104".into();
            let to_address_string = "4APbcAKxZ2KPVPMnqa5cPtJK25tr7maE7LrJe67vzumiCtWwjDBvYnHZr18wFexJpih71Mxsjv8b7EpQftpB9NjPPXmZxHN".into();
            let unlock_time = 0u64;
            let using_outs: Vec<UnspentOutput> = transaction_parameters.using_outs;


            let transaction_result = MoneroTransaction::<N>::create_transaction(
                change_amount,
                fee_amount,
                fee_mask,
                fee_per_b,
                final_total_wo_fee,
                fork_version,
                from_address_string,
                mix_outs,
                nettype_string,
                payment_id_string,
                priority,
                sec_spend_key_string,
                sec_view_key_string,
                to_address_string,
                unlock_time,
                using_outs,
            ).unwrap();

            println!();
            println!("step 2 received");
            println!("tx must be reconstructed {:?}", transaction_result.tx_must_be_reconstructed);
            println!();
            println!("serialized tx {:?}", transaction_result.serialized_signed_tx);
            println!();
            println!("tx hash {:?}", transaction_result.tx_hash);
            println!("tx key {:?}", transaction_result.tx_key);
            println!("tx pub key {:?}", transaction_result.tx_pub_key);
            println!();
        }
    }

    mod stagenet {
        use super::*;

        #[test]
        fn test_decode_address() {
            let address = "{\"nettype_string\":\"STAGENET\", \"address\":\"593u2VupBMzERSQSvwqzwnCSXSYGV28FcYkfcdXEfFyY2UoUfKtFACMYsoRxy1U7B7iwwUsoievaEY8THxzWitdfMsam7uM\"}";
            let str_slice = call_extern_function(address, extern_decode_address);
            println!("result from c++ {:?}", str_slice);
        }

        #[test]
        fn test_prepare_transaction() {
            let unspent_outs_string = "[{\"amount\":9996522470000,\"public_key\":\"dd397dea109a2b94056fd5e236eada6f57c60ab4de5563469a4245e7394f8f65\",\"index\":0,\"global_index\":1745616,\"rct\":\"c32e27e0f773d08efc3a651cbabbbd563a60fb230ccd3ebf5320ae825ab05e86da36753b8b5957c4\",\"tx_id\":802,\"tx_hash\":\"902e4e9661cff7acc9b4d8de7a902b0e8c0a90b5fded6ad4ce6fb5633d1e01c3\",\"tx_pub_key\":\"0ee98e87f68a2526393ed487495f2d3dba6e90e860537d0aae1d5fad5d492f21\"}, {\"amount\":10000000000000,\"public_key\":\"a916a631a0cb830c2203536492542a08e893158e131ce13bb78d6057ae649476\",\"index\":1,\"global_index\":1745603,\"rct\":\"5ed44e17993122468916e0aaea3690e19bf983c2ceaf9f2f9463565589f7b089df331eaea305890e\",\"tx_id\":801,\"tx_hash\":\"d62dfe7ff500b40ca60b0ec1b4e01988f1486bf094054a9a098b3a6f5f3ecb9a\",\"tx_pub_key\":\"ea8232f7d80c9a98e3e7a06c37b0b9d813542657e7e7962fd94cf49cafb58252\"}]";

            let is_sweeping = false;
            let fee_mask = 100000u64;
            let fee_per_b = 246580u64;
            let fork_version = 10u8;
            let passed_in_attempt_at_fee = "".into();
            let payment_id_string = "".into();
            let sending_amount = 200000000u64;
            let priority = 1u32;
            let unspent_outs: Vec<UnspentOutput> = serde_json::from_str(unspent_outs_string).unwrap();

            let transaction_parameters = MoneroTransaction::<N>::prepare_transaction(
                is_sweeping,
                fee_mask,
                fee_per_b,
                fork_version,
                sending_amount,
                passed_in_attempt_at_fee,
                payment_id_string,
                priority,
                unspent_outs,
            ).unwrap();

            println!();
            println!("step 1 received");
            println!("mixin: {:?}", transaction_parameters.mixin);
            println!("using fee: {:?}", transaction_parameters.using_fee);
            println!("final_total_wo_fee: {:?}", transaction_parameters.final_total_wo_fee);
            println!("change_amount: {:?}", transaction_parameters.change_amount);
            println!();
        }

        #[test]
        fn test_create_transaction() {
            let unspent_outs_string = "[{\"amount\":9996522470000,\"public_key\":\"dd397dea109a2b94056fd5e236eada6f57c60ab4de5563469a4245e7394f8f65\",\"index\":0,\"global_index\":1745616,\"rct\":\"c32e27e0f773d08efc3a651cbabbbd563a60fb230ccd3ebf5320ae825ab05e86da36753b8b5957c4\",\"tx_id\":802,\"tx_hash\":\"902e4e9661cff7acc9b4d8de7a902b0e8c0a90b5fded6ad4ce6fb5633d1e01c3\",\"tx_pub_key\":\"0ee98e87f68a2526393ed487495f2d3dba6e90e860537d0aae1d5fad5d492f21\"}, {\"amount\":10000000000000,\"public_key\":\"a916a631a0cb830c2203536492542a08e893158e131ce13bb78d6057ae649476\",\"index\":1,\"global_index\":1745603,\"rct\":\"5ed44e17993122468916e0aaea3690e19bf983c2ceaf9f2f9463565589f7b089df331eaea305890e\",\"tx_id\":801,\"tx_hash\":\"d62dfe7ff500b40ca60b0ec1b4e01988f1486bf094054a9a098b3a6f5f3ecb9a\",\"tx_pub_key\":\"ea8232f7d80c9a98e3e7a06c37b0b9d813542657e7e7962fd94cf49cafb58252\"}]";
            let mix_outs_string = "[{\"amount\":0,\"outputs\":[{\"global_index\":1522098,\"public_key\":\"4c72fa2bef04dca799f1b8821f3f5e53d14e30dd143e73426c473995c7fac5e7\",\"rct\":\"b76844a6b8ae138a319198efb3bba88406e2b717cb2bd6a1c5675f5c040f4cb600000000000000000000000000000000000000000000000000000000000000001a9c1b4ec57e1362000000000000000000000000000000000000000000000000\"},{\"global_index\":1314128,\"public_key\":\"99b7f212b56fa75260ee7c83535922561e4a3072447bb96cb4e07beb29152220\",\"rct\":\"13a42eca66f12becc3538aa3ee3da6cab24100079f4bc280b5ea38ec372f64ab00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"},{\"global_index\":1455703,\"public_key\":\"ae29e674c69363a6d3f0ab5e1648375cafb3b7e6088747781959a4248a706549\",\"rct\":\"8f49acf1046ceb5c0aec067623ac6ab30d20d10d5a4b73d0562150dbab20f4070000000000000000000000000000000000000000000000000000000000000000825b0e78dc68428e000000000000000000000000000000000000000000000000\"},{\"global_index\":640952,\"public_key\":\"8d6038a16684a251b19a7684fc91345a468a87b1f90c87492c57a6939f69dbac\",\"rct\":\"fc6a95dd6bafdce7ffba40ef6282351f82e4580cc439f4325b2b8df0388eac5400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"},{\"global_index\":834344,\"public_key\":\"0ab50a508bbbd3cac1c7203a19c30c4cad5dc8aa0c24b824c8283281eaec961e\",\"rct\":\"9af4f716993de3afd02062339aecd3197356226ed7baca56329a7a3e330041c8ed3c4ad84a4f5974564a7939de6457d989f6f7fae0a578a0a68084444bc30403081b6b568a4379723fb3817b41aad7881d40c2abd8770e1de698ffee2d2c2206\"},{\"global_index\":1214508,\"public_key\":\"53c94ea948205b1c582b82d63e3f90c11d293baffab8d6d1662b8f45d1053464\",\"rct\":\"4ddb5c7348878df1c30bb1f5d6f65697043f4aae4d62c76adfc630d34580ef3600000000000000000000000000000000000000000000000000000000000000003c171473b3c5ee70000000000000000000000000000000000000000000000000\"},{\"global_index\":1617396,\"public_key\":\"24ad1a4ff3fc39e5b9473f09506041f7ede9605ddf633410a3353be1a2b8b259\",\"rct\":\"7720631e160804759223ca4dfbb0c66329f102c855c17c12adc6f560d5597f9300000000000000000000000000000000000000000000000000000000000000007d1fff73a88e2caf000000000000000000000000000000000000000000000000\"},{\"global_index\":321717,\"public_key\":\"77b0ff37990913b62a081fe3e98a25be633cf58593194b97fb13ff59e6e4d405\",\"rct\":\"9883d971e67f14b39f11d4862fa31e6b0849f320f96c687400327dfca43b9b139b633364db9ce0d949d1675c4136e19c24de4ef3a331893d57f6b033bda1760beec0335ea02e8295886e2f0b7c8066ab0649468c812b080fc53e6ee723df720b\"},{\"global_index\":1501374,\"public_key\":\"3bb106d2f8de03523cc201123f768b5670da942130c0360dee70c017ad2a4159\",\"rct\":\"a0229ea3c1aef3a7570f3834e6f536749fd9aa52198d614134c7d798b5bd15c80000000000000000000000000000000000000000000000000000000000000000631b748cfde1645e000000000000000000000000000000000000000000000000\"},{\"global_index\":491964,\"public_key\":\"d968a59e48c40ff79b4fb47eb08b630184ddbb1f3bc043b1a4797aa87d5d07d8\",\"rct\":\"d4ac039c43c99460b818cd8daca5468ee78d53e3017b90e6a6a64fd0de79e072a582ce2c8a2b471f51be15c4ca5218748e520c759f07581ae0c0d297668b5c0562adc3999444d40dc11388ac5f2fca05b2f42ed91e3b7c11537213d09d925003\"}]}]";

            let is_sweeping = false;
            let fee_mask = 100000u64;
            let fee_per_b = 246580u64;
            let fork_version = 10u8;
            let passed_in_attempt_at_fee = "".into();
            let payment_id_string = "".into();
            let sending_amount = 200000000u64;
            let priority = 1u32;
            let unspent_outs: Vec<UnspentOutput> = serde_json::from_str(unspent_outs_string).unwrap();

            let transaction_parameters = MoneroTransaction::<N>::prepare_transaction(
                is_sweeping,
                fee_mask,
                fee_per_b,
                fork_version,
                sending_amount,
                passed_in_attempt_at_fee,
                payment_id_string,
                priority,
                unspent_outs,
            ).unwrap();

            println!();
            println!("step 1 received");
            println!("mixin: {:?}", transaction_parameters.mixin);
            println!("using fee: {:?}", transaction_parameters.using_fee);
            println!("final_total_wo_fee: {:?}", transaction_parameters.final_total_wo_fee);
            println!("change_amount: {:?}", transaction_parameters.change_amount);
            println!();

            let change_amount = transaction_parameters.change_amount;
            let fee_amount = transaction_parameters.using_fee;
            let fee_mask = 100000u64;
            let fee_per_b = 246580u64;
            let final_total_wo_fee = transaction_parameters.final_total_wo_fee;
            let fork_version = 10u8;
            let from_address_string = "593u2VupBMzERSQSvwqzwnCSXSYGV28FcYkfcdXEfFyY2UoUfKtFACMYsoRxy1U7B7iwwUsoievaEY8THxzWitdfMsam7uM".into();
            let mix_outs: Vec<MixAmountAndOuts> = serde_json::from_str(mix_outs_string).unwrap();
            let nettype_string = "STAGENET".into();
            let payment_id_string = "".into();
            let priority = 1u32;
            let sec_spend_key_string = "0cf0c38429e00fa4abecb98296cb15dec209c0a7e6ea34ed86d32429498e4700".into();
            let sec_view_key_string = "55c5b2fa94b2c5ee387eb9dd71b197a6358a5a90ed5eb5acdfa088583125a40a".into();
            let to_address_string = "59McWTPGc745SRWrSMoh8oTjoXoQq6sPUgKZ66dQWXuKFQ2q19h9gvhJNZcFTizcnT12r63NFgHiGd6gBCjabzmzHAMoyD6".into();
            let unlock_time = 0u64;
            let using_outs: Vec<UnspentOutput> = transaction_parameters.using_outs;


            let transaction_result = MoneroTransaction::<N>::create_transaction(
                change_amount,
                fee_amount,
                fee_mask,
                fee_per_b,
                final_total_wo_fee,
                fork_version,
                from_address_string,
                mix_outs,
                nettype_string,
                payment_id_string,
                priority,
                sec_spend_key_string,
                sec_view_key_string,
                to_address_string,
                unlock_time,
                using_outs,
            ).unwrap();

            println!();
            println!("step 2 received");
            println!("tx must be reconstructed {:?}", transaction_result.tx_must_be_reconstructed);
            println!();
            println!("serialized tx {:?}", transaction_result.serialized_signed_tx);
            println!();
            println!("tx hash {:?}", transaction_result.tx_hash);
            println!("tx key {:?}", transaction_result.tx_key);
            println!("tx pub key {:?}", transaction_result.tx_pub_key);
            println!();
        }
    }

//    mod testnet {
//        use super::*;
//
//        #[test]
//        fn test_decode_address() {
//            let address = "{\"nettype_string\":\"TESTNET\", \"address\":\"9vn9WFawdiY9sL8ZjPHvXGBCES5HxLJSuXWeHEQmybaCbXTLbvif72a42uJ2PfWNL7SG6rKPyopmfjGAUwcCBcDa45AAdAc\"}";
//            let str_slice = call_extern_function(address, extern_decode_address);
//            println!("result from c++ {:?}", str_slice);
//        }
//
//        #[test]
//        fn test_prepare_transaction() {
//            let unspent_outs_string = "[{\"amount\":3000000000,\"public_key\":\"41be1978f58cabf69a9bed5b6cb3c8d588621ef9b67602328da42a213ee42271\",\"index\":1,\"global_index\":7611174,\"rct\":\"86a2c9f1f8e66848cd99bfda7a14d4ac6c3525d06947e21e4e55fe42a368507eb5b234ccdd70beca8b1fc8de4f2ceb1374e0f1fd8810849e7f11316c2cc063060008ffa5ac9827b776993468df21af8c963d12148622354f950cbe1369a92a0c\",\"tx_id\":5334971,\"tx_hash\":\"9d37c7fdeab91abfd1e7e120f5c49eac17b7ac04a97a0c93b51c172115df21ea\",\"tx_pub_key\":\"bd703d7f37995cc7071fb4d2929594b5e2a4c27d2b7c68a9064500ca7bc638b8\"}]";
//
//            let is_sweeping = false;
//            let fee_mask = 10000u64;
//            let fee_per_b = 24658u64;
//            let fork_version = 10u8;
//            let passed_in_attempt_at_fee = "".into();
//            let payment_id_string = "".into();
//            let sending_amount = 200000000u64;
//            let priority = 1u32;
//            let unspent_outs: Vec<UnspentOutput> = serde_json::from_str(unspent_outs_string).unwrap();
//
//            let transaction_parameters = MoneroTransaction::<N>::prepare_transaction(
//                is_sweeping,
//                fee_mask,
//                fee_per_b,
//                fork_version,
//                sending_amount,
//                passed_in_attempt_at_fee,
//                payment_id_string,
//                priority,
//                unspent_outs,
//            ).unwrap();
//
//            println!();
//            println!("step 1 received");
//            println!("mixin: {:?}", transaction_parameters.mixin);
//            println!("using fee: {:?}", transaction_parameters.using_fee);
//            println!("final_total_wo_fee: {:?}", transaction_parameters.final_total_wo_fee);
//            println!("change_amount: {:?}", transaction_parameters.change_amount);
//            println!();
//        }
//
//        #[test]
//        fn test_create_transaction() {
//            let unspent_outs_string = "[{\"amount\":3000000000,\"public_key\":\"41be1978f58cabf69a9bed5b6cb3c8d588621ef9b67602328da42a213ee42271\",\"index\":1,\"global_index\":7611174,\"rct\":\"86a2c9f1f8e66848cd99bfda7a14d4ac6c3525d06947e21e4e55fe42a368507eb5b234ccdd70beca8b1fc8de4f2ceb1374e0f1fd8810849e7f11316c2cc063060008ffa5ac9827b776993468df21af8c963d12148622354f950cbe1369a92a0c\",\"tx_id\":5334971,\"tx_hash\":\"9d37c7fdeab91abfd1e7e120f5c49eac17b7ac04a97a0c93b51c172115df21ea\",\"tx_pub_key\":\"bd703d7f37995cc7071fb4d2929594b5e2a4c27d2b7c68a9064500ca7bc638b8\"}]";
//            let mix_outs_string = "[{\"amount\":0,\"outputs\":[{\"global_index\":7453099,\"public_key\":\"31f3a7fec0f6f09067e826b6c2904fd4b1684d7893dcf08c5b5d22e317e148bb\",\"rct\":\"ea6bcb193a25ce2787dd6abaaeef1ee0c924b323c6a5873db1406261e86145fc\"},{\"global_index\":7500097,\"public_key\":\"f9d923500671da05a1bf44b932b872f0c4a3c88e6b3d4bf774c8be915e25f42b\",\"rct\":\"dcae4267a6c382bcd71fd1af4d2cbceb3749d576d7a3acc473dd579ea9231a52\"},{\"global_index\":7548483,\"public_key\":\"839cbbb73685654b93e824c4843e745e8d5f7742e83494932307bf300641c480\",\"rct\":\"aa99d492f1d6f1b20dcd95b8fff8f67a219043d0d94b4551759016b4888573e7\"},{\"global_index\":7554755,\"public_key\":\"b8860f0697988c8cefd7b4285fbb8bec463f136c2b9a9cadb3e57cebee10717f\",\"rct\":\"327f9b07bee9c4c25b5a990123cd2444228e5704ebe32016cd632866710279b5\"},{\"global_index\":7561477,\"public_key\":\"561d734cb90bc4a64d49d37f85ea85575243e2ed749a3d6dcb4d27aa6bec6e88\",\"rct\":\"b5393e038df95b94bfda62b44a29141cac9e356127270af97193460d51949841\"},{\"global_index\":7567062,\"public_key\":\"db1024ef67e7e73608ef8afab62f49e2402c8da3dc3197008e3ba720ad3c94a8\",\"rct\":\"1fedf95621881b77f823a70aa83ece26aef62974976d2b8cd87ed4862a4ec92c\"},{\"global_index\":7567508,\"public_key\":\"6283f3cd2f050bba90276443fe04f6076ad2ad46a515bf07b84d424a3ba43d27\",\"rct\":\"10e16bb8a8b7b0c8a4b193467b010976b962809c9f3e6c047335dba09daa351f\"},{\"global_index\":7568716,\"public_key\":\"7a7deb4eef81c1f5ce9cbd0552891cb19f1014a03a5863d549630824c7c7c0d3\",\"rct\":\"735d059dc3526334ac705ddc44c4316bb8805d2426dcea9544cde50cf6c7a850\"},{\"global_index\":7571196,\"public_key\":\"535208e354cae530ed7ce752935e555d630cf2edd7f91525024ed9c332b2a347\",\"rct\":\"c3cf838faa14e993536c5581ca582fb0d96b70f713cf88f7f15c89336e5853ec\"},{\"global_index\":7571333,\"public_key\":\"e73f27b7eb001aa7eac13df82814cda65b42ceeb6ef36227c25d5cbf82f6a5e4\",\"rct\":\"5f45f33c6800cdae202b37abe6d87b53d6873e7b30f3527161f44fa8db3104b6\"},{\"global_index\":7571335,\"public_key\":\"fce982dbz8e7a6b71a1e632c7de8c5cbf54e8bacdfbf250f1ffc2a8d2f7055ce3\",\"rct\":\"407bdcc48e70eb3ef2cc22cefee6c6b5a3c59fd17bde12fda5f1a44a0fb39d14\"}]}]";
//
//            let is_sweeping = false;
//            let fee_mask = 10000u64;
//            let fee_per_b = 24658u64;
//            let fork_version = 10u8;
//            let passed_in_attempt_at_fee = "".into();
//            let payment_id_string = "".into();
//            let sending_amount = 1u64;
//            let priority = 1u32;
//            let unspent_outs: Vec<UnspentOutput> = serde_json::from_str(unspent_outs_string).unwrap();
//
//            let transaction_parameters = MoneroTransaction::<N>::prepare_transaction(
//                is_sweeping,
//                fee_mask,
//                fee_per_b,
//                fork_version,
//                sending_amount,
//                passed_in_attempt_at_fee,
//                payment_id_string,
//                priority,
//                unspent_outs,
//            ).unwrap();
//
//            println!();
//            println!("step 1 received");
//            println!("mixin: {:?}", transaction_parameters.mixin);
//            println!("using fee: {:?}", transaction_parameters.using_fee);
//            println!("final_total_wo_fee: {:?}", transaction_parameters.final_total_wo_fee);
//            println!("change_amount: {:?}", transaction_parameters.change_amount);
//            println!();
//
//            let change_amount = transaction_parameters.change_amount;
//            let fee_amount = transaction_parameters.using_fee;
//            let fee_mask = 10000u64;
//            let fee_per_b = 24658u64;
//            let final_total_wo_fee = transaction_parameters.final_total_wo_fee;
//            let fork_version = 10u8;
//            let from_address_string = "9vn9WFawdiY9sL8ZjPHvXGBCES5HxLJSuXWeHEQmybaCbXTLbvif72a42uJ2PfWNL7SG6rKPyopmfjGAUwcCBcDa45AAdAc".into();
//            let mix_outs: Vec<MixAmountAndOuts> = serde_json::from_str(mix_outs_string).unwrap();
//            let nettype_string = "TESTNET".into();
//            let payment_id_string = "".into();
//            let priority = 1u32;
//            let sec_spend_key_string = "e76110547ec2dd70dea07afa184fd033457eff9946f9b233dcf993b5b30f2905".into();
//            let sec_view_key_string = "09b78ce37bf902ffb238b91b0ad8bd6b879d6852cf91c8ddfaad1f377aa9410e".into();
//            let to_address_string = "BbWkaGxgCZhNUB5fMq1hPEP7iG1gdK2DeSgxPBEZsKwk6FK2ViHnaPjEXBRyVhv5w1dQypAmbLgMUKzSAM5ynUqa4k3Xobu".into();
//            let unlock_time = 0u64;
//            let using_outs: Vec<UnspentOutput> = transaction_parameters.using_outs;
//
//
//            let transaction_result = MoneroTransaction::<N>::create_transaction(
//                change_amount,
//                fee_amount,
//                fee_mask,
//                fee_per_b,
//                final_total_wo_fee,
//                fork_version,
//                from_address_string,
//                mix_outs,
//                nettype_string,
//                payment_id_string,
//                priority,
//                sec_spend_key_string,
//                sec_view_key_string,
//                to_address_string,
//                unlock_time,
//                using_outs,
//            ).unwrap();
//
//            println!();
//            println!("step 2 received");
//            println!("tx must be reconstructed {:?}", transaction_result.tx_must_be_reconstructed);
//            println!();
//            println!("serialized tx {:?}", transaction_result.serialized_signed_tx);
//            println!();
//            println!("tx hash {:?}", transaction_result.tx_hash);
//            println!("tx key {:?}", transaction_result.tx_key);
//            println!("tx pub key {:?}", transaction_result.tx_pub_key);
//            println!();
//        }
//    }
}
