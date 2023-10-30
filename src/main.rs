use cryptopals::utils::*;
use log::{debug, error, info, log_enabled, Level};
use std::collections::HashMap;

fn set1_challenge_3() {
    // find the repeating xor
    let input =
        Vec::<u8>::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

    let word_frequency_scores: HashMap<char, u8> = [
        ('a', 8),
        ('b', 1),
        ('c', 3),
        ('d', 4),
        ('e', 13),
        ('f', 2),
        ('g', 2),
        ('h', 6),
        ('i', 7),
        ('j', 0),
        ('k', 1),
        ('l', 4),
        ('m', 2),
        ('n', 7),
        ('o', 8),
        ('p', 2),
        ('q', 0),
        ('r', 6),
        ('s', 6),
        ('t', 9),
        ('u', 3),
        ('v', 1),
        ('w', 2),
        ('x', 0),
        ('y', 2),
        ('z', 0),
        (' ', 10),
    ]
    .iter()
    .cloned()
    .collect();

    let mut best_score: u32 = 0;
    let mut winning_char: Option<u8> = None;

    for i in 0..=255_u8 {
        let mut input = input.clone();
        input.xor(&i);
        let mut score: u32 = 0;
        for byte in &input {
            score += *word_frequency_scores.get(&(*byte as char)).unwrap_or(&0) as u32;
        }
        if score > best_score {
            best_score += score;
            winning_char = Some(i);
        }
    }
    info!("1.3 Winning char: {:?}", winning_char);
    info!(
        "1.3 Resulting string: {:?}",
        String::from_utf8_lossy(input.clone().xor(&winning_char.unwrap()))
    );
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    set1_challenge_3();
}
