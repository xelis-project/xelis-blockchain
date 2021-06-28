const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

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

pub fn convert_bits(data: &[u8], from: u16, to: u16, pad: bool) -> Vec<u8> {
    let mut acc: u16 = 0;
    let mut bits: u16 = 0;
    let mut result: Vec<u8> = vec![];
    let max_value = (1 << to) - 1;
    for v in data {
        let value = *v as u16;

        if value >> from != 0 {
            panic!("Invalid data range: data: {}, from bits: {}", value, from);
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
        panic!("Illegal zero padding");
    } else if (acc << (to - bits)) & max_value != 0 {
        panic!("Non zero padding");
    }

    result
}

pub fn encode(mut hrp: String, data: &[u8]) -> String { //TODO use Result
    if hrp.len() == 0 {
        panic!("hrp empty")
    }

    for value in hrp.bytes() {
        if value < 33 || value > 126 {
            panic!("Invalid character human readable part: {}", value);
        }
    }

    if hrp.to_uppercase() != hrp && hrp.to_lowercase() != hrp {
        panic!("Using mix case: {}", hrp);
    }

    hrp = hrp.to_lowercase();
    let mut combined: Vec<u8> = Vec::new();
    combined.extend(data);
    combined.extend(&create_checksum(&hrp, data));
    
    let mut result: Vec<u8> = Vec::new();
    result.extend(hrp.bytes());
    result.extend(b"1");

    for value in combined.iter() {
        if *value > CHARSET.len() as u8 {
            panic!("Invalid value: {}, max is {}", value, CHARSET.len());
        }

        result.push(CHARSET.bytes().nth(*value as usize).unwrap());
    }

    match String::from_utf8(result) {
        Ok(value) => value,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e)
    }
}

pub fn decode(bech: &String) -> (String, Vec<u8>) {
    if bech.to_uppercase() != *bech && bech.to_lowercase() != *bech {
        panic!("mix case not allowed: {}", bech);
    }

    let pos = match bech.rfind("1") {
        Some(v) => v,
        None => panic!("Separator '1' not found")
    };

    if pos < 1 || pos + 7 > bech.len() {
        panic!("Separator '1' at invalid position: {}", pos);
    }

    let hrp = bech[0..pos].to_owned();
    for value in hrp.bytes() {
        if value < 33 || value > 126 {
            panic!("invalid character human readable part: {}", value);
        }
    }

    let mut data: Vec<u8> = vec![]; //mon vec concerné
    for i in pos + 1..bech.len() {
        let c = bech.chars().nth(i).unwrap();
        let value = match CHARSET.find(c) {
            Some(v) => v,
            None => panic!("Invalid character part: {}", c)
        };

        data.push(value as u8);
    }

    if !verify_checksum(&hrp, &data) {
        panic!("Invalid checksum");
    }

    println!("size: {}", data.len());
    for _ in 0..6 {
        data.remove(data.len() - 1);
    }

    (hrp, data)
}

/*
pub fn segwit_address_encode(hrp: String, version: u8, program: &[u8]) -> String {
    if version > 16 {
        panic!("invalid witness version: {}", version);
    }
    if program.len() < 2 || program.len() > 40 {
        panic!("invalid program length: {}", program.len());
    }
    if version == 0 && program.len() != 20 && program.len() != 32 {
        panic!("invalid program length for witness version 0: {}", program.len());
    }

    let data = convert_bits(program, 8, 5, true);
    let mut combined = vec![];
    combined.push(version);
    combined.extend(data);

    encode(hrp, &combined)
}


pub fn segwit_address_decode(hrp: &String, address: &String) -> (u8, Vec<u8>) {
    let (decoded_hrp, data) = decode(address);
    if decoded_hrp != *hrp {
        panic!("Invalid human readable part: {} != {}", decoded_hrp, hrp);
    }
    if data.len() == 0 {
        panic!("Invalid decode data length: {}", data.len())
    }
    if data[0] > 16 {
        panic!("Invalid witness version: {}", data[0]);
    }
    let result = convert_bits(&data[1..], 5, 8, false);
    if result.len() < 2 || result.len() > 40 {
        panic!("Invalid convert bits length: {}", result.len());
    }
    if data[0] == 0 && result.len() != 20 && result.len() != 32 {
        panic!("Invalid program length for witness version 0: {}", result.len());
    }

    (data[0], result)
}*/