use std::{collections::HashMap, hash::Hash, str::from_utf8};

use itertools::Itertools;
use log::info;

use crate::oracle::{StaticOracle, Oracle};

#[derive(Debug, PartialEq)]
pub struct Cookie(pub HashMap<String, String>);

fn encode(s: Cookie) -> String {
    format!("email={}&uid={}&role={}", s.0["email"], s.0["uid"], s.0["role"])
} 

// foo=bar&baz=qux&zap=zazzle
fn decode(s: &str) -> Cookie {
    println!("s: {}", s);
    let c = s.split("&").fold(HashMap::new(), |mut result, pair| {
        let mut key_value = pair.split("=");
        let key = key_value.next().unwrap();
        let value = key_value.next().unwrap();
        result.insert(key.to_string(), value.to_string());
        result
    });
    Cookie(c)
}

fn profile_for(email: &str) -> Cookie {
    let mut map = HashMap::new();
    let sanitized_email = email.replace("&", "").replace("=", "");
    map.insert("email".to_string(), sanitized_email.to_string());
    map.insert("uid".to_string(), "10".to_string());
    map.insert("role".to_string(), "user".to_string());
    Cookie(map)
}

pub struct ProfileManager {
    oracle: StaticOracle,
}

impl ProfileManager {
    pub fn new() -> Self {
        ProfileManager {
            oracle: StaticOracle::new(),
        }
    }

    pub fn create_profile(&self, email: &str) -> Vec<u8> {
        let cookie = profile_for(email);
        let encoded = encode(cookie);
        self.oracle.encrypt(encoded.as_bytes())
    }

    pub fn decrypt_profile(&self, ciphertext: &[u8]) -> Cookie {
        let plaintext = self.oracle.decrypt(ciphertext);
        decode(&String::from_utf8(plaintext).unwrap())
    }

    pub fn is_admin(cookie: &Cookie) -> bool {
        cookie.0.get("role").unwrap() == "admin"
    }
}

impl Oracle for ProfileManager {
    fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        println!("input: {:?}", input);
        self.create_profile(from_utf8(input).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        let mut map = HashMap::new();
        map.insert("foo".to_string(), "bar".to_string());
        map.insert("baz".to_string(), "qux".to_string());
        map.insert("zap".to_string(), "zazzle".to_string());
        assert_eq!(encode(Cookie(map)), "baz=qux&foo=bar&zap=zazzle");
    }

    #[test]
    fn test_decode() {
        let mut map = HashMap::new();
        map.insert("foo".to_string(), "bar".to_string());
        map.insert("baz".to_string(), "qux".to_string());
        map.insert("zap".to_string(), "zazzle".to_string());
        assert_eq!(decode("foo=bar&baz=qux&zap=zazzle"), Cookie(map));
    }
}
