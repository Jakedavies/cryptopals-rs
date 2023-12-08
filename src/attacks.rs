use std::{collections::HashMap, error::Error, str::from_utf8};

use crate::{oracle::Oracle, utils::DetectDuplicate, utils::Xor};
use log::info;

pub fn score_character(char: &char) -> u32 {
    match char {
        'a' => 8,
        'b' => 1,
        'c' => 3,
        'd' => 4,
        'e' => 13,
        'f' => 2,
        'g' => 2,
        'h' => 6,
        'i' => 7,
        'j' => 0,
        'k' => 1,
        'l' => 4,
        'm' => 2,
        'n' => 7,
        'o' => 8,
        'p' => 2,
        'q' => 0,
        'r' => 6,
        's' => 6,
        't' => 9,
        'u' => 3,
        'v' => 1,
        'w' => 2,
        'x' => 0,
        'y' => 2,
        'z' => 0,
        ' ' => 10,
        _ => 0,
    }
}

pub struct DecryptCipherResult {
    pub key: u8,
    pub score: u32,
    pub decoded: Vec<u8>,
}

impl DecryptCipherResult {
    pub fn new() -> Self {
        DecryptCipherResult {
            key: 0,
            score: 0,
            decoded: Vec::new(),
        }
    }
    pub fn max(self, other: Self) -> Self {
        if self.score > other.score {
            self
        } else {
            other
        }
    }
}

impl Default for DecryptCipherResult {
    fn default() -> Self {
        DecryptCipherResult::new()
    }
}

fn score_character_frequency(input: &[u8]) -> u32 {
    input
        .iter()
        .fold(0, |acc, byte| acc + score_character(&(*byte as char)))
}

pub fn attack_single_character_xor(ciphertext: Vec<u8>) -> DecryptCipherResult {
    (0..=255).fold(DecryptCipherResult::new(), |acc, key| {
        let ciphertext = ciphertext.clone().xor(&key).to_owned();
        let score = score_character_frequency(ciphertext.as_slice());
        match score.cmp(&acc.score) {
            std::cmp::Ordering::Greater => DecryptCipherResult {
                key,
                score,
                decoded: ciphertext,
            },
            _ => acc,
        }
    })
}

fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .fold(0, |acc, (a, b)| acc + (a ^ b).count_ones())
}

pub fn keysize_edit_distance(ciphertext: &[u8], keysize: usize) -> f32 {
    let max_chunks = ciphertext.len() / keysize;
    // take 16 keysize chunks to compare
    let mut chunks = ciphertext[0..(keysize * 16).min(max_chunks)].chunks(keysize);
    let mut total_distance = 0.;
    let mut total_comparisons = 0;
    while let (Some(a), Some(b)) = (chunks.next(), chunks.next()) {
        total_distance += hamming_distance(a, b) as f32 / keysize as f32;
        total_comparisons += 1;
    }
    total_distance / total_comparisons as f32
}

pub fn attack_repeating_key_xor(ciphertext: &[u8]) -> Vec<u8> {
    let (keysize, _score) = (2..40)
        .map(|keysize| (keysize, keysize_edit_distance(ciphertext, keysize)))
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap();

    info!("Keysize: {}", keysize);

    let mut transposed_blocks = vec![Vec::new(); keysize];
    for (i, val) in ciphertext.iter().enumerate() {
        transposed_blocks[i % keysize].push(*val);
    }

    transposed_blocks
        .into_iter()
        .map(|block| attack_single_character_xor(block).key)
        .collect::<Vec<_>>()
}

pub fn attack_ecb(oracle: Oracle) -> Vec<u8> {
    let mut block_size = None;
    let mut input = "".to_string();
    let mut length = oracle.encrypt(input.as_bytes()).len();
    let mut first_increment = None;
    for i in 1..1024 {
        input.push('A');
        // determine block size
        let cipher = oracle.encrypt(input.as_bytes());
        if cipher.len() != length {
            if let Some(_first_increment) = first_increment {
                block_size = Some((i - _first_increment) as usize);
                break;
            } else {
                length = cipher.len();
                first_increment = Some(i);
            }
        }
    }

    if block_size.is_none() {
        panic!("Unable to determine block size");
    }
    info!("Block size: {}", block_size.unwrap());
    let block_size = block_size.unwrap();

    let is_ecb = oracle
        .encrypt("X".repeat(block_size * 3).as_bytes())
        .as_slice()
        .contains_duplicates(block_size as u32);

    if !is_ecb {
        panic!("Not ECB");
    }

    let mut output = vec![];
    // each time we find a character, we rebuild the encryption map using 1 less padding char and
    // that new known character
    let mut chunk_index = 0;
    let total_chunks = length / block_size;
    while chunk_index < total_chunks {
        let mut known: Vec<u8> = vec![];
        let offset = chunk_index * block_size;
        for i in (0..block_size).rev() {
            info!("Attacking index {}", i);
            let mut last_byte_decryption_map: HashMap<u8, u8> = HashMap::new();
            let mut attack_prefix = "A".repeat(i).as_bytes().to_vec();
            attack_prefix.extend_from_slice(output.as_slice());
            attack_prefix.extend_from_slice(known.as_slice());
            // for each possible character at this block position, encrypt the attack prefix + that and
            // build a map of the encrypted byte -> unencrypted byte
            for char in 0..=255 {
                let mut attack = attack_prefix.clone();
                attack.push(char);
                let cipher = oracle.encrypt(&attack);
                let encrypted_byte = cipher[i + offset];
                last_byte_decryption_map.insert(encrypted_byte, char);
            }

            // build a string of
            let mut attack_string = "A".repeat(i).as_bytes().to_vec();
            attack_string.extend_from_slice(output.as_slice());
            let cipher = oracle.encrypt(&attack_string);
            let encrypted_byte = cipher[i + offset];
            // figure out what the last byte is
            if let Some(decrypted_byte) = last_byte_decryption_map.get(&encrypted_byte) {
                println!("Encrypted byte: {} => {}", encrypted_byte, decrypted_byte);
                known.push(*decrypted_byte);
            } else {
                panic!("Unable to decrypt byte");
            }
        }
        chunk_index += 1;
        output.extend_from_slice(known.as_slice());
    }

    output
}

#[cfg(test)]
mod tests {
    use crate::attacks::*;

    #[test]
    fn test_hamming_distance() {
        let a = "this is a test".as_bytes();
        let b = "wokka wokka!!!".as_bytes();
        assert_eq!(hamming_distance(a, b), 37);
    }
}
