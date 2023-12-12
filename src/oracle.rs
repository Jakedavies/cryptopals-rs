use std::str::from_utf8;
use log::info;

use crate::utils::{random_key, encrypt_aes_128, padded_encrypt_aes_128, Base64, Hex};


pub struct Oracle {
    key: Vec<u8>,
}

const MAGIC_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

impl Oracle {
    pub fn new() -> Self {
        let key = random_key(16);
        //let key = Vec::<u8>::from_hex("65582b210e550f064039646021533269");
        //let key = "0123456789abcdef".as_bytes().to_vec();
        println!("key: {:?}", key.to_vec().to_hex());
        Self {
            key,
        }

    }

    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let mut input = input.to_vec();
        input.extend_from_slice(Vec::<u8>::from_base64(MAGIC_STRING).as_slice());
        padded_encrypt_aes_128(&input, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle() {
        let oracle = Oracle::new();
        let known = "Roll";
        let a = oracle.encrypt("AAAAAAAAAAAA".as_bytes());
        let b = oracle.encrypt("AAAAAAAAAAAARoll".as_bytes());
        assert_eq!(a[0..16], b[0..16]);
    }

    fn test_oracle_2() {
        let oracle = Oracle::new();
        let known = "Rol";
        let a = oracle.encrypt("AAAAAAAAAAAA".as_bytes());
        let b = oracle.encrypt("AAAAAAAAAAAARoll".as_bytes());
        assert_eq!(a[0..16], b[0..16]);
    }
}

