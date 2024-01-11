const KEY: &[u8] = b"YELLOW SUBMARINE";
const IV: &[u8] = b"0000000000000000";
use log::info;

use crate::cbc::cbc_encrypt;
use crate::cbc::cbc_decrypt;
use crate::oracle::Oracle;

pub struct Challenge16 {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl Challenge16 {
    pub fn new() -> Self {
        Challenge16 {
            key: KEY.to_vec(),
            iv: IV.to_vec(),
        }
    }

    pub fn is_admin(&self, input: &[u8]) -> bool {
        is_admin(input)
    }
}

impl Oracle for Challenge16 {
    fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        encrypt(input)
    }
}


pub fn encrypt(input: &[u8]) -> Vec<u8> {
    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
    
    let mut output = String::new();
    output.push_str(prefix);
    // convert input back to a string because my oracle trait is stupid and dont want to refactor
    let str = input.iter().map(|x| *x as char).collect::<String>();
    output.push_str(&str.replace(";", "%3b").replace("=", "%3d"));
    output.push_str(suffix);

    cbc_encrypt(&output.as_bytes(), &KEY, IV)
}

pub fn is_admin(input: &[u8]) -> bool {
    let d = cbc_decrypt(input.to_vec(), &KEY, IV);
    let a = d.iter().map(|x| *x as char).collect::<String>();
    info!("result: {}", a);
    a.contains(";admin=true;")
}
