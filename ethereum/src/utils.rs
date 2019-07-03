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
    let mut final_address = String::from("0x");
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


#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn test_to_hex_string(bytes: &[u8], expected: &str) {
        assert_eq!(to_hex_string(bytes), expected);
    }

    fn test_to_checksum_address(addr: &str, expected: &str) {
        assert_eq!(to_checksum_address(addr), expected);
    }

    #[test]
    fn test_functionality_hex_string() {
        test_to_hex_string(
            &hex::decode("001d3f1ef827552ae1114027bd3ecf1f086ba0f9").unwrap(),
            "001D3F1EF827552AE1114027BD3ECF1F086BA0F9"
        )
    }

    #[test]
    fn test_functionality_checksum_address() {
        test_to_checksum_address(
            "001d3f1ef827552ae1114027bd3ecf1f086ba0f9",
            "0x001d3F1ef827552Ae1114027BD3ECF1f086bA0F9"
        )
    }
}
