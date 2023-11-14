use std::{error::Error, str::from_utf8};

use crate::utils::Xor;
use itertools::Itertools;
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
    // take 16 keysize chunks to compare
    let mut chunks = ciphertext[0..keysize * 16].chunks(keysize);
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
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap()).unwrap();

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
