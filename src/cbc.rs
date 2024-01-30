use log::info;

use crate::{pkcs7, utils::{Xor, decrypt_aes_128, encrypt_aes_128, Hex}};

const BLOCKSIZE: usize = 16;

pub fn cbc_encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut padded = pkcs7::pad_to_blocksize(input.to_vec(), BLOCKSIZE);
    info!("last char: {}", padded.last().unwrap());
    let chunks = padded.chunks_mut(BLOCKSIZE);
    let mut previous_ct = iv.to_vec();

    let mut output = Vec::new();
    for chunk in chunks {
        let chunk_ived = chunk.xor(&previous_ct.to_vec());
        previous_ct = encrypt_aes_128(chunk_ived, key);
        output.extend_from_slice(&previous_ct);
    }
    output
}

pub fn cbc_decrypt(mut cipher: Vec<u8>, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let chunks = cipher.chunks_mut(BLOCKSIZE);
    let mut previous_ct = iv.to_vec();

    let mut output = Vec::new();
    for chunk in chunks {
        let mut chunk_ived = decrypt_aes_128(chunk, key);
        output.extend_from_slice(chunk_ived.xor(&previous_ct.to_vec()));
        previous_ct = chunk.to_vec();
    }
    output
}

#[cfg(test)]
mod tests {
    use log::info;

    use super::*;

    #[test]
    fn test_cbc_encrypt() {
        let input = "0123456789abcdef";
        let key = "YELLOW SUBMARINE";
        let iv = [0; 16];

        let encrypt = cbc_encrypt(input.as_bytes(), key.as_bytes(), &iv);
        println!("encrypt: {}", encrypt.to_hex());
    }
}
