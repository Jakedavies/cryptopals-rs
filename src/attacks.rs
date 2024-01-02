use std::{collections::HashMap, error::Error, str::from_utf8};

use crate::{
    oracle::{Oracle, StaticOracle},
    utils::Xor,
    utils::{DetectDuplicate, Hex},
};
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

pub fn get_prefix_length(block_size: usize, oracle: &impl Oracle) -> usize {
    let mut prefix_padding = 0;
    let test_string = "B".repeat(block_size * 2);
    while prefix_padding <= block_size {
        // if we can detect two identical blocks, then this must be the correct prefix padding
        // step 1 block at a time
        let mut prefix = "A".repeat(prefix_padding).as_bytes().to_vec();
        prefix.extend_from_slice(test_string.as_bytes());
        let cipher = oracle.encrypt(&prefix);
        let blocks = cipher.chunks(block_size).collect::<Vec<_>>();
        for i in 1..blocks.len() {
            if blocks[i - 1] == blocks[i] {
                return (i-1) * block_size - prefix_padding;
            }
        }
        prefix_padding += 1;
    }
    panic!("Unable to determine prefix length");
}

pub fn attack_ecb(oracle: impl Oracle) -> Vec<u8> {
    let mut block_size = None;
    // first determine the prefix length and pad it out
    let encrypted_secret = oracle.encrypt(&[]);

    let mut input = "".to_string();

    let mut first_increment = None;
    let mut tmp_length = encrypted_secret.len();
    for i in 1..1024 {
        input.push('A');
        // determine block size
        let cipher = oracle.encrypt(input.as_bytes());
        if tmp_length != cipher.len() {
            if let Some(_first_increment) = first_increment {
                block_size = Some((i - _first_increment) as usize);
                break;
            } else {
                tmp_length = cipher.len();
                first_increment = Some(i);
            }
        }
    }

    if block_size.is_none() {
        panic!("Unable to determine block size");
    }

    let block_size = block_size.unwrap();

    let prefix_length = get_prefix_length(block_size, &oracle);

    // skip forward to the next whole block starting index
    let mut prefix_padding = block_size - (prefix_length % block_size);
    if prefix_padding == block_size {
        prefix_padding = 0;
    }
    let skip_length = prefix_length + prefix_padding;

    let constant_prefix = "B".repeat(prefix_padding);

    let is_ecb = oracle
        .encrypt("X".repeat(block_size * 3).as_bytes())
        .as_slice()
        .contains_duplicates(block_size as u32);

    if !is_ecb {
        panic!("Not ECB");
    }

    let mut output = vec![];
    let mut offset = skip_length;
    while offset < encrypted_secret.len() + 16 {
        for i in (0..block_size).rev() {
            // don't try to decrypt padding
            let mut attack_prefix: Vec<u8> = "".as_bytes().to_vec();
            attack_prefix.extend_from_slice(constant_prefix.clone().as_bytes());
            attack_prefix.extend_from_slice("A".repeat(i).as_bytes());
            let encrypted = oracle.encrypt(&attack_prefix);
            attack_prefix.extend_from_slice(&output[..]);
            attack_prefix.push(0);
            let char = (0u8..=255).find(|c| {
                let len = attack_prefix.len();
                attack_prefix[len - 1] = c.clone();
                let cipher = oracle.encrypt(&attack_prefix);
                cipher[offset..offset + block_size] == encrypted[offset..offset + block_size]
            });

            if let Some(c) = char {
                output.push(c);
            } else {
                return output;
            }
        }
        offset += block_size;
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

    #[test]
    fn test_get_prefix_length() {
        let oracle = StaticOracle::new().with_prefix("SUBMARINE SUBMARINE".as_bytes());
        assert_eq!(get_prefix_length(16, &oracle), 19);
    }
}
