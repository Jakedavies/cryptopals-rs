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
    pub plaintext: Vec<u8>,
}

impl DecryptCipherResult {
    pub fn new() -> Self {
        DecryptCipherResult {
            key: 0,
            score: 0,
            plaintext: Vec::new(),
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

pub fn decrypt_single_character_xor(ciphertext: &Vec<u8>) -> DecryptCipherResult {
    let mut best_score: u32 = 0;
    let mut best_key: Option<u8> = None;

    for key in 0..=255 {
        let score = ciphertext.clone().xor(&key).iter()
            .fold(0, |acc, byte| {
            acc + score_character(&(*byte as char))
        });
        if score > best_score {
            best_score = score;
            best_key = Some(key);
        }
    }

    let plaintext = ciphertext.clone().xor(&best_key.expect("No decryption key found"));
    
    DecryptCipherResult {
        key: best_key.expect("No decryption key found"),
        score: best_score,
        plaintext,
    }
}
