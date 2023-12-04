use log::info;

use crate::utils::{random_key, encrypt_aes_128, padded_encrypt_aes_128, Base64};


pub struct Oracle {
    key: Vec<u8>,
}

const MAGIC_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

impl Oracle {
    pub fn new() -> Self {
        let key = random_key(16);
        println!("key: {:?}", key);
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
