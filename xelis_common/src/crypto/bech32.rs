use std::string::FromUtf8Error;

use thiserror::Error;

const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const SEPARATOR: char = ':';

#[derive(Error, Debug)]
pub enum Bech32Error {
    #[error("Invalid data range: {}, max is {}", _0, _1)]
    InvalidDataRange(u16, u16), // data, from bits
    #[error("Illegal zero padding")]
    IllegalZeroPadding,
    #[error("Non zero padding")]
    NonZeroPadding,
    #[error("human readable part is empty")]
    HrpEmpty,
    #[error("Invalid character value in human readable part: {}", _0)]
    HrpInvalidCharacter(u8), // character as byte
    #[error("Mix case is not allowed in human readable part")]
    HrpMixCase,
    #[error("Invalid value: {}, max is {}", _0, _1)]
    InvalidValue(u8, usize), // value, max
    #[error("Separator not found")]
    SeparatorNotFound,
    #[error("Invalid separator position: {}", _0)]
    SeparatorInvalidPosition(usize), // position
    #[error(transparent)]
    InvalidUTF8Sequence(#[from] FromUtf8Error), // error returned by 'String::from_utf8'
    #[error("Invalid prefix, got: {}, expected: {}", _0, _1)]
    InvalidPrefix(String, String),
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Invalid index '{}': not found", _0)]
    InvalidIndex(usize)
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for value in values {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ *value as u32;
        for (i, item) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= item;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &String) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    for c in hrp.bytes() {
        result.push(c >> 5);
    }
    result.push(0);
    for c in hrp.bytes() {
        result.push(c & 31);
    }

    result
}

pub fn verify_checksum(hrp: &String, data: &[u8]) -> bool {
    let mut vec = hrp_expand(hrp);
    vec.extend(data);
    return polymod(&vec) == 1;
}

pub fn create_checksum(hrp: &String, data: &[u8]) -> [u8; 6] {
    let mut values: Vec<u8> = Vec::new();
    values.extend(hrp_expand(hrp));
    values.extend(data);
    let mut result: [u8; 6] = [0; 6];
    values.extend(&result);
    let polymod = polymod(&values) ^ 1;

    for i in 0..6 {
        result[i] = (polymod >> (5 * (5 - i)) & 31) as u8
    }

    result
}

pub fn convert_bits(data: &[u8], from: u16, to: u16, pad: bool) -> Result<Vec<u8>, Bech32Error> {
    let mut acc: u16 = 0;
    let mut bits: u16 = 0;
    let mut result: Vec<u8> = vec![];
    let max_value = (1 << to) - 1;
    for v in data {
        let value = *v as u16;

        if value >> from != 0 {
            return Err(Bech32Error::InvalidDataRange(value, from));
        }

        acc = (acc << from) | value;
        bits += from;
        while bits >= to {
            bits -= to;
            result.push(((acc >> bits) & max_value) as u8);
        }
    }

    if pad {
        if bits > 0 {
            result.push(((acc << (to - bits)) & max_value) as u8);
        }
    } else if bits >= from {
        return Err(Bech32Error::IllegalZeroPadding)
    } else if (acc << (to - bits)) & max_value != 0 {
        return Err(Bech32Error::NonZeroPadding)
    }

    Ok(result)
}

pub fn encode(mut hrp: String, data: &[u8]) -> Result<String, Bech32Error> {
    if hrp.len() == 0 {
        return Err(Bech32Error::HrpEmpty)
    }

    for value in hrp.bytes() {
        if value < 33 || value > 126 {
            return Err(Bech32Error::HrpInvalidCharacter(value))
        }
    }

    if hrp.to_uppercase() != hrp && hrp.to_lowercase() != hrp {
        return Err(Bech32Error::HrpMixCase)
    }

    hrp = hrp.to_lowercase();
    let mut combined: Vec<u8> = Vec::new();
    combined.extend(data);
    combined.extend(&create_checksum(&hrp, data));
    
    let mut result: Vec<u8> = Vec::new();
    result.extend(hrp.bytes());
    result.extend(SEPARATOR.to_string().bytes());

    for value in combined.iter() {
        if *value > CHARSET.len() as u8 {
            return Err(Bech32Error::InvalidValue(*value, CHARSET.len()))
        }

        result.push(CHARSET.bytes().nth(*value as usize).ok_or(Bech32Error::InvalidIndex(*value as usize))?);
    }

    let string = String::from_utf8(result)?;
    Ok(string)
}

pub fn decode(bech: &String) -> Result<(String, Vec<u8>), Bech32Error> {
    if bech.to_uppercase() != *bech && bech.to_lowercase() != *bech {
        return Err(Bech32Error::HrpMixCase)
    }

    let pos = bech.rfind(SEPARATOR).ok_or(Bech32Error::SeparatorNotFound)?;
    if pos < 1 || pos + 7 > bech.len() {
        return Err(Bech32Error::SeparatorInvalidPosition(pos))
    }

    let hrp = bech[0..pos].to_owned();
    for value in hrp.bytes() {
        if value < 33 || value > 126 {
            return Err(Bech32Error::HrpInvalidCharacter(value))
        }
    }

    let mut data: Vec<u8> = vec![];
    for i in pos + 1..bech.len() {
        let c = bech.chars().nth(i).ok_or(Bech32Error::InvalidIndex(i))?;
        let value = CHARSET.find(c).ok_or(Bech32Error::HrpInvalidCharacter(c as u8))?;

        data.push(value as u8);
    }

    if !verify_checksum(&hrp, &data) {
        return Err(Bech32Error::InvalidChecksum)
    }

    for _ in 0..6 {
        data.remove(data.len() - 1);
    }

    Ok((hrp, data))
}