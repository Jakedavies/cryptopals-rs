use base64::{engine::general_purpose, Engine as _};
use itertools::Itertools;
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};

pub trait Xor<T> {
    fn xor(self, other: &T) -> Self;
}

pub trait RepeatingKeyXor {
    fn encrypt_repeating_key_xor(self, key: &[u8]) -> Vec<u8>;
}

pub trait Hex {
    fn from_hex(str: &str) -> Self;
    fn to_hex(&self) -> String;
}

pub trait DetectDuplicate {
    fn contains_duplicates(&self, blocksize: u32) -> bool;
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
    fn from_base64(str: &str) -> Self;
}

impl Base64 for Vec<u8> {
    fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self)
    }

    fn from_base64(str: &str) -> Self {
        general_purpose::STANDARD.decode(str).unwrap()
    }
}

impl Xor<Vec<u8>> for &mut [u8] {
    fn xor(self, other: &Vec<u8>) -> Self {
        for (i, byte) in self.iter_mut().enumerate() {
            *byte ^= other[i % other.len()];
        }
        self
    }
}

impl Xor<u8> for &mut [u8] {
    fn xor(self, other: &u8) -> Self {
        for byte in &mut self.iter_mut() {
            *byte ^= other;
        }
        self
    }
}

impl RepeatingKeyXor for &[u8] {
    fn encrypt_repeating_key_xor(self, key: &[u8]) -> Vec<u8> {
        self.iter()
            .enumerate()
            .fold(Vec::new(), |mut out, (i, byte)| {
                out.push(byte ^ key[i % key.len()]);
                out
            })
    }
}

impl DetectDuplicate for &[u8] {
    fn contains_duplicates(&self, blocksize: u32) -> bool {
        let chunks = self.chunks(blocksize as usize);
        chunks.len() > chunks.into_iter().unique().collect_vec().len()
    }
}

pub fn decrypt_aes_128(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = vec![];
    let key = GenericArray::clone_from_slice(key);
    (0..input.len()).step_by(16).for_each(|block| {
        let mut chunk = GenericArray::clone_from_slice(&input[block..block + 16]);
        let cipher = Aes128::new(&key);
        cipher.decrypt_block(&mut chunk);
        output.extend_from_slice(&chunk);
    });
    output
}

pub fn encrypt_aes_128(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = vec![];
    let key = GenericArray::clone_from_slice(key);
    (0..input.len()).step_by(16).for_each(|block| {
        let mut chunk = GenericArray::clone_from_slice(&input[block..block + 16]);
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(&mut chunk);
        output.extend_from_slice(&chunk);
    });
    output

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let mut hex1 = Vec::<u8>::from_hex("1c0111001f010100061a024b53535009181c");
        let hex2 = Vec::<u8>::from_hex("686974207468652062756c6c277320657965");
        hex1 = hex1.xor(&hex2).into();

        assert_eq!(
            hex1,
            Vec::<u8>::from_hex("746865206b696420646f6e277420706c6179")
        );
    }

    #[test]
    fn test_hex_to_base64() {
        let hex = Vec::<u8>::from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        assert_eq!(
            hex.to_base64(),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn repeating_key_xor() {
        let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"
            .as_bytes();
        let key = "ICE";
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623\
                    d63343c2a26226324272765272a282b2f20430a652e2c652a31\
                    24333a653e2b2027630c692b20283165286326302e27282f";

        let xored = input.encrypt_repeating_key_xor(key.as_bytes());
        assert_eq!(xored.to_hex(), expected);
    }
}
