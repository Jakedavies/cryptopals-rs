use std::{collections::HashMap, hash::Hash};

use itertools::Itertools;

use crate::oracle::Oracle;

#[derive(Debug, PartialEq)]
pub struct Cookie(HashMap<String, String>);

fn encode(s: Cookie) -> String {
    s.0.iter()
        .sorted()
        .map(|(key, value)| {
        format!("{}={}", key, value)
    }).join("&")
} 

// foo=bar&baz=qux&zap=zazzle
fn decode(s: &str) -> Cookie {
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
    oracle: Oracle,
}

impl ProfileManager {
    pub fn new() -> Self {
        ProfileManager {
            oracle: Oracle::new(),
        }
    }

    pub fn create_profile(&self, email: &str) -> Vec<u8> {
        let cookie = profile_for(email);
        self.oracle.encrypt(&encode(cookie).as_bytes()[..])
    }

    pub fn decrypt_profile(&self, ciphertext: &[u8]) -> Cookie {
        let plaintext = self.oracle.decrypt(ciphertext);
        decode(&String::from_utf8(plaintext).unwrap())
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
