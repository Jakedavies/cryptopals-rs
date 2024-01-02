use std::str::from_utf8;
use log::info;

use crate::utils::{random_key, encrypt_aes_128, padded_encrypt_aes_128, Base64, Hex, decrypt_aes_128, decrypt_aes_128_padded};


pub struct StaticOracle {
    key: Vec<u8>,
    suffix: Vec<u8>,
}

pub trait Oracle {
    fn encrypt(&self, input: &[u8]) -> Vec<u8>;
}


impl StaticOracle {
    pub fn new() -> Self {
        let key = random_key(16);
        //let key = Vec::<u8>::from_hex("65582b210e550f064039646021533269");
        //let key = "0123456789abcdef".as_bytes().to_vec();
        println!("key: {:?}", key.to_vec().to_hex());
        Self {
            key,
            suffix: vec![],
        }

    }

    pub fn with_prefix(mut self, suffix: &[u8]) -> Self {
        self.suffix.extend_from_slice(suffix);
        self
    }

    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let mut input = input.to_vec();
        input.extend_from_slice(&self.suffix[..]);
        padded_encrypt_aes_128(&input, &self.key)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        decrypt_aes_128_padded(ciphertext, &self.key)
    }
}

impl Oracle for StaticOracle {
    fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        self.encrypt(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle() {
        let oracle = StaticOracle::new();
        let known = "Roll";
        let a = oracle.encrypt("AAAAAAAAAAAA".as_bytes());
        let b = oracle.encrypt("AAAAAAAAAAAARoll".as_bytes());
        assert_eq!(a[0..16], b[0..16]);
    }

    fn test_oracle_2() {
        let oracle = StaticOracle::new();
        let known = "Rol";
        let a = oracle.encrypt("AAAAAAAAAAAA".as_bytes());
        let b = oracle.encrypt("AAAAAAAAAAAARoll".as_bytes());
        assert_eq!(a[0..16], b[0..16]);
    }
}

