use tiny_keccak::keccak256;

pub fn to_hex_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join("")
}

pub fn to_checksum_address(addr: &str) -> String {
    let hash2 = keccak256(addr.as_bytes());
    let mut new_address_bytes = [0u8; 32];
    new_address_bytes.copy_from_slice(&hash2[..]);
    let new_address = to_hex_string(&new_address_bytes);
    let mut final_address = String::from("");
    for x in 0..40 {
        let temp_char = &new_address[x..(x + 1)];
        match temp_char {
            "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" => {
                final_address.push_str(&addr[x..(x + 1)].to_lowercase())
            }
            _ => final_address.push_str(&addr[x..(x + 1)].to_uppercase()),
        }
    }
    final_address
}
