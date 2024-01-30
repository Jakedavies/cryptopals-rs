use std::str::from_utf8;

use cryptopals::attacks::*;
use cryptopals::cbc::cbc_decrypt;
use cryptopals::cbc::cbc_encrypt;
use cryptopals::challenge_17::Challenge17;
use cryptopals::oracle::Oracle;
use cryptopals::challenge_16;
use cryptopals::challenge_17;
use cryptopals::cookie::ProfileManager;
use cryptopals::oracle::StaticOracle;
use cryptopals::pkcs7;
use cryptopals::utils::*;
use itertools::Itertools;
use log::info;

fn set1_challenge_3() {
    let input =
        Vec::<u8>::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let decrypted = attack_single_character_xor(input);

    info!(
        "1.3 Resulting string: {}",
        std::str::from_utf8(&decrypted.decoded).unwrap()
    );
}

fn set1_challenge_4() {
    let input = std::fs::read_to_string("data/4.txt").expect("Unable to read file");

    // read input line by line
    let max = input.lines().fold(DecryptCipherResult::new(), |acc, line| {
        let ciphertext = Vec::<u8>::from_hex(line);
        acc.max(attack_single_character_xor(ciphertext))
    });

    info!(
        "1.4 Resulting string: {}",
        std::str::from_utf8(&max.decoded).unwrap()
    );
}

fn set1_challenge_5() {
    let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"
        .as_bytes();
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
    info!(
        "1.7 decrypted: \n {}",
        std::str::from_utf8(&decrypted).unwrap()
    );
}

fn set1_challenge_8() {
    let duplicates = std::fs::read_to_string("data/8.txt")
        .expect("Unable to read file")
        .lines()
        .map(Vec::<u8>::from_hex)
        .filter(|ciphertext| ciphertext.as_slice().contains_duplicates(16))
        .map(|ciphertext| ciphertext.to_hex())
        .collect_vec();

    let answer = duplicates.first().unwrap();

    info!("1.8 ciphertexts with duplicate blocks: {:?}", duplicates);
}

fn set2_challenge_9() {
    let input = "YELLOW SUBMARINE";
    let expected = "YELLOW SUBMARINE\x04\x04\x04\x04";
    let padded = pkcs7::pad_to_blocksize(input.as_bytes().to_vec(), 20);
    assert_eq!(std::str::from_utf8(&padded).unwrap(), expected);
    info!("2.9 padded: {}", std::str::from_utf8(&padded).unwrap());
}

fn set2_challenge_10() {
    let mut input = std::fs::read_to_string("data/10.txt").expect("Unable to read file");
    input = input.replace('\n', "");
    let ciphertext = Vec::<u8>::from_base64(&input);
    let key = "YELLOW SUBMARINE";
    let iv = [0; 16];
    let decrypted = cbc_decrypt(ciphertext, key.as_bytes(), &iv);
    info!(
        "2.10 decrypted: \n {}",
        std::str::from_utf8(&decrypted).unwrap()
    );
}

fn set2_challenge_11() {
    let input = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    for _ in 0..100 {
        let mut input = input.clone().as_bytes().to_vec();
        input.extend_from_slice(&random_key(rand::random::<usize>() % 6 + 5));
        let mut random_string = random_key(rand::random::<usize>() % 6 + 5);
        random_string.extend_from_slice(&input);

        let key = random_key(16);
        let mode = if rand::random::<bool>() {
            CipherMode::ECB
        } else {
            CipherMode::CBC
        };
        let cipher = match mode {
            CipherMode::ECB => padded_encrypt_aes_128(&random_string, &key),
            CipherMode::CBC => cbc_encrypt(&random_string, &key, &[0; 16]),
        };

        assert_eq!(detect_cbc_or_ecb(&cipher), mode);
    }
    info!("2.11 Success!");
}

fn set2_challenge_12() {
    const MAGIC_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let oracle = StaticOracle::new().with_suffix(&Vec::<u8>::from_base64(MAGIC_STRING)[..]);
    let secret = attack_ecb(oracle);
    info!("{}", std::str::from_utf8(&secret).unwrap());
    assert!(std::str::from_utf8(&secret).unwrap().contains("Rollin"));
}

fn set1_challenge_13() {
    let profile_manager = ProfileManager::new();
    let attack_block: Vec<u8> = pkcs7::pad_to_blocksize("admin".as_bytes().to_vec(), 16);
    let standard_string = "foooo@bar.com";
    let attack_string: String = ["foooo@bar.", from_utf8(&attack_block).unwrap(), ".com"].concat();
    let admin_ciphertext = profile_manager.create_profile(&attack_string);
    let normal_cipher = profile_manager.create_profile(standard_string);
    let elevated_cookie = [&normal_cipher[..32], &admin_ciphertext[16..32]].concat();
    // DO something to the cipher, making us an admin
    let cookie = profile_manager.decrypt_profile(&elevated_cookie);
    assert!(ProfileManager::is_admin(&cookie));
    info!("{:?}", cookie);
}

fn set1_challenge_14() {
    const TARGET: &str = "target-str";
    const PREFIX: &str = "prefix";
    let oracle = StaticOracle::new()
        .with_prefix(PREFIX.as_bytes())
        .with_suffix(TARGET.as_bytes());

    let secret = attack_ecb(oracle);
    info!("target: {}", std::str::from_utf8(&secret).unwrap());
    assert_eq!(&secret[0..TARGET.len()], TARGET.as_bytes());
}

fn set2_challenge_16() {
    let input = "A".repeat(16);
    let oracle = challenge_16::Challenge16::new();
    let test = oracle.encrypt(&input.as_bytes());
    assert!(!challenge_16::is_admin(&test));

    let input_string = "A".repeat(16) + "AadminAtrueAAAAA"; // 32 bytes, we need to flip bytes 32, 38, 43
    // version 1
    let mut ciphertext = challenge_16::encrypt(&input_string.as_bytes());

    // set this character to
    // by xoring its current value against the previous blocks cipher text
    // and the desired value

    //                 A         ;    old cipher result
    ciphertext[32] =  (0x41 ^ 0x3b) ^ ciphertext[32];
    ciphertext[38] =  (0x41 ^ 0x3d) ^ ciphertext[38];
    ciphertext[43] =  (0x41 ^ 0x3b) ^ ciphertext[43];

    assert!(challenge_16::is_admin(&ciphertext));
}

fn set3_challenge_17() {
    let oracle = Challenge17::new();
    let (iv, cipher) = oracle.encrypt_random_input();

    let result = oracle_padding_attack(&iv, &cipher, &oracle);
    info!("Challenge 17 result: {}", safe_string(&result));
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

    info!("Set 1 Challenge 8");
    set1_challenge_8();

    info!("Set 2 Challenge 9");
    set2_challenge_9();

    info!("Set 2 Challenge 10");
    set2_challenge_10();

    info!("Set 2 Challenge 11");
    set2_challenge_11();

    info!("Set 2 Challenge 12");
    set2_challenge_12();

    info!("Set 1 Challenge 13");
    set1_challenge_13();

    info!("Set 1 Challenge 14");
    set1_challenge_14();

    info!("Set 2 Challenge 16");
    set2_challenge_16();

    info!("Set 3 Challenge 17");
    set3_challenge_17();
}
