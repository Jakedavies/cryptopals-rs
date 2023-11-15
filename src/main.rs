use cryptopals::utils::*;
use cryptopals::attacks::*;
use log::info;

fn set1_challenge_3() {
    let input =
        Vec::<u8>::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let decrypted = attack_single_character_xor(input);

    info!("1.3 Resulting string: {}", std::str::from_utf8(&decrypted.decoded).unwrap());
}

fn set1_challenge_4() {
    let input = std::fs::read_to_string("data/4.txt").expect("Unable to read file");

    // read input line by line
    let max = input.lines().fold(DecryptCipherResult::new(), |acc, line| {
        let ciphertext = Vec::<u8>::from_hex(line);
        acc.max(attack_single_character_xor(ciphertext))
    });
   
    info!("1.4 Resulting string: {}", std::str::from_utf8(&max.decoded).unwrap());
}

fn set1_challenge_5() {
    let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal".as_bytes();
    let key = "ICE";
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623\
                    d63343c2a26226324272765272a282b2f20430a652e2c652a31\
                    24333a653e2b2027630c692b20283165286326302e27282f";

    let xored = input.encrypt_repeating_key_xor(key.as_bytes());
    assert_eq!(xored.to_hex(), expected);
}


fn set1_challenge_6() {
    let mut input = std::fs::read_to_string("data/6.txt").expect("Unable to read file");
    input = input.replace('\n', "");

    let ciphertext = Vec::<u8>::from_base64(&input);
    let key = attack_repeating_key_xor(&ciphertext);
    info!("1.6 key: {}", std::str::from_utf8(&key).unwrap());
}

fn set1_challenge_7() {
    let mut input = std::fs::read_to_string("data/7.txt").expect("Unable to read file");
    input = input.replace('\n', "");
    let ciphertext = Vec::<u8>::from_base64(&input);
    let key = "YELLOW SUBMARINE";
    let decrypted = decrypt_aes_128(&ciphertext, key.as_bytes());
    info!("1.7 decrypted: \n {}", std::str::from_utf8(&decrypted).unwrap());
}


fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("Set 1 Challenge 3");
    set1_challenge_3();

    info!("Set 1 Challenge 4");
    set1_challenge_4();

    info!("Set 1 Challenge 5");
    set1_challenge_5();

    info!("Set 1 Challenge 6");
    set1_challenge_6();

    info!("Set 1 Challenge 7");
    set1_challenge_7();
}
