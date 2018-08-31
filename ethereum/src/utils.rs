use tiny_keccak::keccak256;

pub fn to_hex_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join("")
}

pub fn to_checksum_address(addr: &String) -> String {
        let hash2 = keccak256(addr.as_bytes());
            let mut new_address_bytes = [0u8; 32];
            new_address_bytes.copy_from_slice(&hash2[..]);
            let new_address = to_hex_string(&new_address_bytes);
            let mut final_address = String::from("");
            for x in 0..40 {
                let temp_char = &new_address[x..(x+1)];
                if temp_char == "8" || temp_char == "2" || temp_char == "3" 
                || temp_char == "4" || temp_char == "5" || temp_char == "6" || temp_char == "7" {
                    final_address.push_str(&addr[x..(x+1)].to_lowercase());
                } else {
                    final_address.push_str(&addr[x..(x+1)].to_uppercase());
                }
            }
        final_address
    }