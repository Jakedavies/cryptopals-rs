const BASE64_CHAR_MAP: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', // 0-7
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 8-15
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 16-23
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', // 24-31
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', // 32-39
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', // 40-47
    'w', 'x', 'y', 'z', '0', '1', '2', '3', // 48-55
    '4', '5', '6', '7', '8', '9', '+', '/'  // 56-63
];

pub trait Xor<T> {
    fn xor(&mut self, other: &T) -> &mut Self;
}

pub trait Hex {
    fn from_hex(str: &str) -> Self;
    fn to_hex(&self) -> String;
}

impl Hex for Vec<u8> {
    fn from_hex(str: &str) -> Self {
        let mut bytes: Vec<u8> = Vec::new();
        let mut chars = str.chars();

        // chunk over self.0
        for _ in 0..str.len() / 2 {
            let nibble1 = chars.next().unwrap();
            let nibble2 = chars.next().expect("Invalid hex, odd number of characters");
            if let (Some(n1), Some(n2)) = (nibble1.to_digit(16), nibble2.to_digit(16)) {
                bytes.push((n1 << 4 | n2) as u8);
            } else {
                panic!("Invalid hex, non-hex character");
            }
        }
        bytes
    }

    fn to_hex(&self) -> String {
        let mut str = String::new();
        for byte in self.clone().iter() {
            str.push_str(&format!("{:02x}", byte));
        }
        str
    }
}

pub trait Base64 {
    fn to_base64(&self) -> String;
}

impl Base64 for Vec<u8> {
    fn to_base64(&self) -> String {
        // read 3 bytes at a time
        // convert to 4 base64 chars
        // pad with '=' if necessary
        // return String
        let mut result = String::new();
        let mut bytes = self.iter();
        while let (Some(b1), Some(b2), Some(b3)) = (bytes.next(), bytes.next(), bytes.next()) {
            let mut index = (b1 & 0b11111100) >> 2;
            result.push(BASE64_CHAR_MAP[index as usize]);
            index = (b1 & 0b00000011) << 4 | (b2 & 0b11110000) >> 4;
            result.push(BASE64_CHAR_MAP[index as usize]);
            index = (b2 & 0b00001111) << 2 | (b3 & 0b11000000) >> 6;
            result.push(BASE64_CHAR_MAP[index as usize]);
            index = b3 & 0b00111111;
            result.push(BASE64_CHAR_MAP[index as usize]);
        }
        result
    }
}

impl Xor<Vec<u8>> for Vec<u8> {
    fn xor(&mut self, other: &Vec<u8>) -> &mut Self {
        for (i, byte) in self.iter_mut().enumerate() {
            *byte ^= other[i];
        }
        self
    }
}

impl Xor<u8> for Vec<u8> {
    fn xor(&mut self, other: &u8) -> &mut Self {
        for byte in &mut self.iter_mut() {
            *byte ^= other;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let mut hex1 = Vec::<u8>::from_hex("1c0111001f010100061a024b53535009181c");
        let hex2 = Vec::<u8>::from_hex("686974207468652062756c6c277320657965");
        hex1.xor(&hex2);

        assert_eq!(hex1, Vec::<u8>::from_hex("746865206b696420646f6e277420706c6179"));
    }

    #[test]
    fn test_hex_to_base64() {
        let hex = Vec::<u8>::from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        assert_eq!(hex.to_base64(), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    }
}
