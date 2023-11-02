use cryptopals::utils::*;
use cryptopals::frequency::*;
use log::info;

fn set1_challenge_3() {
    // find the repeating xor
    let input =
        Vec::<u8>::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let decrypted = decrypt_single_character_xor(&input);

    info!("1.3 Resulting string: {}", std::str::from_utf8(&decrypted.plaintext).unwrap());
}

fn set1_challenge_4() {
    let input = std::fs::read_to_string("data/4.txt").expect("Unable to read file");

    // read input line by line
    let max = input.lines().fold(DecryptCipherResult::new(), |acc, line| {
        let ciphertext = Vec::<u8>::from_hex(line);
        acc.max_score(decrypt_single_character_xor(&ciphertext))
    });
   
    info!("1.4 Resulting string: {}", std::str::from_utf8(&max.plaintext).unwrap());
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("Set 1 Challenge 3");
    set1_challenge_3();

    info!("Set 1 Challenge 4");
    set1_challenge_4();
}
