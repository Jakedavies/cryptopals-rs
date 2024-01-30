use std::str::from_utf8;
use log::info;

use crate::utils::{random_key, encrypt_aes_128, padded_encrypt_aes_128, Base64, Hex, decrypt_aes_128, decrypt_aes_128_padded};


pub struct StaticOracle {
    key: Vec<u8>,
    suffix: Vec<u8>,
    prefix: Vec<u8>,
}

pub trait Oracle {
    fn encrypt(&self, input: &[u8]) -> Vec<u8>;
}


impl StaticOracle {
    pub fn new() -> Self {
        let key = random_key(16);
        //let key = Vec::<u8>::from_hex("65582b210e550f064039646021533269");
        //let key = "0123456789abcdef".as_bytes().to_vec();
        Self {
            key,
            prefix: vec![],
            suffix: vec![],
        }

    }

    pub fn with_suffix(mut self, suffix: &[u8]) -> Self {
        self.suffix.extend_from_slice(suffix);
        self
    }

    pub fn with_prefix(mut self, prefix: &[u8]) -> Self {
        self.prefix.extend_from_slice(prefix);
        self
    }

    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let mut i = "".as_bytes().to_vec();
        i.extend_from_slice(&self.prefix[..]);
        i.extend_from_slice(input);
        i.extend_from_slice(&self.suffix[..]);
        padded_encrypt_aes_128(&i, &self.key)
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

