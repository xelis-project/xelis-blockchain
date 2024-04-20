pub mod languages;

use std::collections::HashMap;
use anyhow::{Result, Context, anyhow};
use lazy_static::lazy_static;
use log::debug;
use xelis_common::{
    crypto::PrivateKey,
    serializer::Serializer
};
use languages::*;

const KEY_SIZE: usize = 32;
const SEED_LENGTH: usize = 24;
const WORDS_LIST: usize = 1626;
const WORDS_LIST_U32: u32 = WORDS_LIST as u32;

lazy_static! {
    pub static ref LANGUAGES: Vec<Language<'static>> = vec![
        english::ENGLISH,
        french::FRENCH,
        italian::ITALIAN,
        spanish::SPANISH,
        portuguese::PORTUGUESE,
        japanese::JAPANESE,
        chinese_simplified::CHINESE_SIMPLIFIED,
        russian::RUSSIAN,
        esperanto::ESPERANTO,
        dutch::DUTCH,
        german::GERMAN
    ];
}

pub struct Language<'a> {
    name: &'a str,
    prefix_length: usize, // number of utf-8 chars to use for checksum
    words: [&'a str; WORDS_LIST]
}

fn calculate_checksum_index(words: &[String], prefix_len: usize) -> Result<u32> {
    if words.len() != SEED_LENGTH {
        return Err(anyhow!("Invalid number of words"));
    }

    let mut chars: Vec<char> = Vec::new();
    for word in words {
        let mut word_chars: Vec<char> = word.chars().collect();
        if word_chars.len() > prefix_len {
            word_chars.truncate(prefix_len);
        }

        chars.extend_from_slice(&word_chars);
    }
    let value: String = chars.into_iter().collect();
    let checksum = crc32fast::hash(value.as_bytes());
    Ok(checksum % SEED_LENGTH as u32)
}

fn verify_checksum(words: &Vec<String>, prefix_len: usize) -> Result<bool> {
    let checksum_index = calculate_checksum_index(&words[0..SEED_LENGTH], prefix_len)?;
    let checksum_word = words.get(checksum_index as usize).context("Invalid checksum index")?;
    let expected_checksum_word = words.get(SEED_LENGTH).context("Invalid checksum word")?;
    Ok(checksum_word == expected_checksum_word)
}

fn find_indices(words: &Vec<String>) -> Result<Option<(Vec<usize>, usize)>> {
    'main: for (i, language) in LANGUAGES.iter().enumerate() {
        // this map is used to store the indices of the words in the language
        let mut language_words: HashMap<&str, usize> = HashMap::with_capacity(WORDS_LIST);
        // build the map
        for (j, word) in language.words.iter().enumerate() {
            language_words.insert(word, j);
        }

        // find the indices of the words
        let mut indices = Vec::new();
        for word in words.iter() {
            if let Some(index) = language_words.get(word.as_str()) {
                indices.push(*index);
            } else {
                // incorrect language for this word, try the next one
                continue 'main;
            }
        }

        // we were able to build the indices, now verify checksum
        if !verify_checksum(&words, language.prefix_length)? {
            return Err(anyhow!("Invalid checksum for seed"));
        }

        return Ok(Some((indices, i)));
    }
    Ok(None)
}

// convert a words list to a Private Key (32 bytes)
pub fn words_to_key(words: &Vec<String>) -> Result<PrivateKey> {
    if words.len() != SEED_LENGTH + 1 {
        return Err(anyhow!("Invalid number of words"));
    }

    let (indices, language_index) = find_indices(words)?.context("No indices found")?;
    debug!("Language found: {}", LANGUAGES[language_index].name);

    let mut dest = Vec::with_capacity(KEY_SIZE);
    for i in (0..SEED_LENGTH).step_by(3) {
        let a = indices.get(i).context("Index out of bounds")?;
        let b = indices.get(i + 1).context("Index out of bounds")?;
        let c = indices.get(i + 2).context("Index out of bounds")?;

        let val = a + WORDS_LIST * (((WORDS_LIST - a) + b) % WORDS_LIST) + WORDS_LIST * WORDS_LIST * (((WORDS_LIST - b) + c) % WORDS_LIST);
        if val % WORDS_LIST != *a {
            return Err(anyhow::anyhow!("Word list sanity check error"))
        }

        let val = val as u32;
        dest.extend_from_slice(&val.to_le_bytes());
    }

    Ok(PrivateKey::from_bytes(&dest)?)
}

pub fn key_to_words(key: &PrivateKey, language_index: usize) -> Result<Vec<String>> {
    let language = LANGUAGES.get(language_index).context("Invalid language index")?;
    key_to_words_with_language(key, language)
}

pub fn key_to_words_with_language(key: &PrivateKey, language: &Language) -> Result<Vec<String>> {
    if language.words.len() != WORDS_LIST {
        return Err(anyhow!("Invalid word list length"));
    }

    let bytes = key.to_bytes();
    if bytes.len() != KEY_SIZE {
        return Err(anyhow!("Invalid key length"));
    }

    let mut words = Vec::with_capacity(SEED_LENGTH + 1);
    for i in (0..KEY_SIZE).step_by(4) {
        let val = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let a = val % WORDS_LIST_U32;
        let b = ((val / WORDS_LIST_U32) + a) % WORDS_LIST_U32;
        let c = ((val / WORDS_LIST_U32 / WORDS_LIST_U32) + b) % WORDS_LIST_U32;
        
        words.push(language.words[a as usize].to_owned());
        words.push(language.words[b as usize].to_owned());
        words.push(language.words[c as usize].to_owned());
    }

    let checksum = calculate_checksum_index(&words, language.prefix_length)?;
    words.push(words.get(checksum as usize).context("error no checksum calculation")?.clone());

    Ok(words)
}

#[cfg(test)]
mod tests {
    use xelis_common::crypto::KeyPair;

    #[test]
    fn test_languages() {
        let (_, key) = KeyPair::new().split();
        for language in super::LANGUAGES.iter() {
            let words = super::key_to_words_with_language(&key, language).unwrap();
            let nkey = super::words_to_key(&words).unwrap();
            assert_eq!(key.as_scalar(), nkey.as_scalar());

            let words2 = super::key_to_words_with_language(&nkey, language).unwrap();
            assert_eq!(words, words2);
        }
    }
}