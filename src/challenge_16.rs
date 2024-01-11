const KEY: &[u8] = b"YELLOW SUBMARINE";
const IV: &[u8] = b"0000000000000000";
use log::info;

use crate::cbc::cbc_encrypt;
use crate::cbc::cbc_decrypt;

pub fn encrypt(input: &str) -> Vec<u8> {
    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
    
    let mut output = String::new();
    output.push_str(prefix);
    output.push_str(&input.replace(";", "%3b").replace("=", "%3d"));
    output.push_str(suffix);

    cbc_encrypt(&output.as_bytes(), &KEY, IV)
}

pub fn is_admin(input: &[u8]) -> bool {
    let d = cbc_decrypt(input.to_vec(), &KEY, IV);
    let a = d.iter().map(|x| *x as char).collect::<String>();
    info!("result: {}", a);
    a.contains(";admin=true;")
}
