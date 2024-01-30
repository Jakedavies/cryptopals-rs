use crate::{
    cbc::{cbc_encrypt, cbc_decrypt},
    oracle::Oracle,
    pkcs7::{self, strip_padding},
    utils::{padded_encrypt_aes_128, random_key, Hex, Base64},
};

const INPUTS: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

const BLOCK_SIZE: usize = 16;

pub struct Challenge17 {
    key: Vec<u8>,
}

impl Challenge17 {
    pub fn new() -> Challenge17 {
        Self {
            key: random_key(BLOCK_SIZE),
        }
    }
    
    pub fn new_with_key(key: &[u8]) -> Challenge17 {
        Self {
            key: key.to_vec(),
        }
    }

    pub fn encrypt_random_input(&self) -> (Vec<u8>, Vec<u8>) {
        // select one of the input strings
        let input = Vec::<u8>::from_base64(INPUTS[rand::random::<usize>() % INPUTS.len()]);
        println!("input: {:?}", std::str::from_utf8(&input).unwrap());
        let iv = random_key(BLOCK_SIZE);
        let encrypted = cbc_encrypt(&input, &self.key, &iv);
        (iv, encrypted)
    }

    pub fn encrypt(&self, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // select one of the input strings
        let iv = random_key(BLOCK_SIZE);
        let encrypted = cbc_encrypt(input, &self.key, &iv);
        (iv, encrypted)
    }


    pub fn is_valid_padding(&self, iv: &[u8], encrypted: &[u8]) -> bool {
        let decrypted = cbc_decrypt(encrypted.to_vec(), &self.key, iv);
        let strip_padding_result = strip_padding(decrypted);
        strip_padding_result.is_ok()
    }

}

