use crate::{utils::{encrypt_aes_128, Xor}, oracle::Oracle};
use byteorder::{BigEndian, ByteOrder, LittleEndian, WriteBytesExt};

fn aes_ctr(input: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    let blocks = input.chunks(16);

    for (counter, block) in blocks.enumerate() {
        // build a nonce block
        let mut nonce_counter = Vec::new();
        nonce_counter.extend_from_slice(&nonce[..]);
        nonce_counter.write_u64::<LittleEndian>(counter as u64).expect("Unable to write");

        // encrypt nonce block with key
        let mut block_keystream = encrypt_aes_128(&nonce_counter, key);

        // xor the result against the input block
        block_keystream.xor(&block.to_vec());
        // append the result to the output
        output.extend_from_slice(&block_keystream);
    }
    // trim the output to the length of the input
    output[..input.len()].to_vec()
}

pub struct CTROracle {
    key: Vec<u8>,
    nonce: [u8; 8],
}

impl CTROracle {
    pub fn new(nonce: [u8; 8]) -> Self {
        let key = crate::utils::random_key(16);
        CTROracle { key, nonce }
    }
}

impl Oracle for CTROracle {
    fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        return aes_ctr(input, &self.key, &self.nonce);
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::{Base64, Hex};

    use super::*;
    #[test]
    fn test_ctr_decrypt() {
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 8];
        let cipher = Vec::<u8>::from_base64(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        );
        let decrypted = aes_ctr(&cipher, key, &nonce);
        assert_eq!(
            decrypted.to_hex(),
            b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".to_vec().to_hex()
        );
    }

    #[test]
    fn test_ctr_encrypt() {
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 8];
        let plain = b"hello hello hello 123 123";
        let cipher = aes_ctr(plain, key, &nonce);
        assert_eq!(
            plain.to_vec(),
            aes_ctr(&cipher, key, &nonce)
        );
    }
}
