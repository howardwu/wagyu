use model::to_hex_string;

use tiny_keccak::keccak256;

pub fn to_checksum_address(addr: &str) -> String {
    let hash = keccak256(addr.as_bytes());

    let mut address_bytes = [0u8; 32];
    address_bytes.copy_from_slice(&hash[..]);

    let address = to_hex_string(&address_bytes);
    let mut final_address = String::from("0x");
    for x in 0..40 {
        let temp_char = &address[x..=x];
        match temp_char {
            "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" => {
                final_address.push_str(&addr[x..=x].to_lowercase())
            }
            _ => final_address.push_str(&addr[x..=x].to_uppercase()),
        }
    }
    final_address
}
