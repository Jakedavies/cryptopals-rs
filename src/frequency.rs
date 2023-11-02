use crate::utils::Xor;

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
    pub fn max_score(self, other: Self) -> Self{
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
    input.iter().fold(0, |acc, byte| {
        acc + score_character(&(*byte as char))
    })
}

pub fn decrypt_single_character_xor(ciphertext: Vec<u8>) -> DecryptCipherResult {
    (0..=255).fold(DecryptCipherResult::new(), |acc, key| {
        let ciphertext = ciphertext.clone().xor(&key).to_owned();
        let score = score_character_frequency(ciphertext.as_slice());
        match score.cmp(&acc.score)  {
            std::cmp::Ordering::Greater => DecryptCipherResult {
                key,
                score,
                decoded: ciphertext,
            },
            _ => acc,
        }
    })
}
