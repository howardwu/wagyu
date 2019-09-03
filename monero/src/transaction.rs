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


// Structs mirrored from https://github.com/mymonero/mymonero-core-cpp
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
struct PrepareTransactionArguments {
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

impl Default for PrepareTransactionArguments {
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
struct CreateTransactionArguments {
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

impl Default for CreateTransactionArguments {
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
    // https://github.com/mymonero/mymonero-core-cpp/blob/master/src/serial_bridge_index.cpp

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

        let args_value = PrepareTransactionArguments {
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
            extern_send_step1
        );

        println!("received step 1: {}", response);

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

        let result: Step1ResultString = serde_json::from_str(&response)?;

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

        let args_value = CreateTransactionArguments {
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

        let result: Step2Result = serde_json::from_str(&response)?;

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

    #[test]
    fn test_decode_address() {
        let address = "{\"nettype_string\":\"MAINNET\", \"address\":\"43tXwm6UNNvSyMdHU4Jfeg4GRgU7KEVAfHo3B5RrXYMjZMRaowr68y12HSo14wv2qcYqqpG1U5AHrJtBdFHKPDEA9UxK6Hy\"}";
        let str_slice = call_extern_function(address, extern_decode_address);
        println!("result from c++ {:?}", str_slice);
    }

    // https://github.com/mymonero/mymonero-core-cpp/blob/20b6cbabf230ae4ebe01d05c859aad397741cf8f/test/test_all.cpp#L347
    #[test]
    fn test_bridge_transfers_send_amount() {
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
        println!("tx_must be reconstructed {:?}", transaction_result.tx_must_be_reconstructed);
        println!();
        println!("serialized tx {:?}", transaction_result.serialized_signed_tx);
        println!();
        println!("tx hash {:?}", transaction_result.tx_hash);
        println!();
        println!("tx key {:?}", transaction_result.tx_key);
        println!();
        println!("tx pub key {:?}", transaction_result.tx_pub_key);
        println!();
    }
}
