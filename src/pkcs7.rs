use crate::utils::Hex;


pub fn pad_to_blocksize(mut bytes: Vec<u8>, blocksize: usize) -> Vec<u8> {
    let mut padding_needed = blocksize - (bytes.len() % blocksize);
    if padding_needed == 0 {
        padding_needed = blocksize;
    }
    bytes.resize(bytes.len() + padding_needed, padding_needed as u8);
    bytes
}

#[derive(Debug)]
pub enum StripPaddingError {
    InvalidPadding,
}

pub fn strip_padding(mut bytes: Vec<u8>) -> Result<Vec<u8>, StripPaddingError> {
    let padding = bytes.pop().unwrap();
    // make sure all the last $padding bytes are equal to $padding
    for i in 0..padding-1 {
        if bytes[bytes.len() - 1 - i as usize] != padding {
            return Err(StripPaddingError::InvalidPadding);
        }
    }
    bytes.resize(bytes.len() - padding as usize + 1, 0);
    Ok(bytes)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_to_blocksize() {
        let input = Vec::<u8>::from_hex("F14ADBDA019D6DB7EFD91546E3FF84449BCB");
        let expected = Vec::<u8>::from_hex("F14ADBDA019D6DB7EFD91546E3FF84449BCB0E0E0E0E0E0E0E0E0E0E0E0E0E0E");
        let padded = pad_to_blocksize(input, 16);
        assert_eq!(padded, expected);
    }

     #[test]
    fn test_pad_to_blocksize_2() {
        let input = Vec::<u8>::from_hex("971ACD01C9C7ADEACC83257926F490FF");
        let expected = Vec::<u8>::from_hex("971ACD01C9C7ADEACC83257926F490FF10101010101010101010101010101010");
        let padded = pad_to_blocksize(input, 16);
        assert_eq!(padded, expected);
    }

}
