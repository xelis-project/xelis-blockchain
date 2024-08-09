pub mod languages;

use thiserror::Error;
use std::collections::HashMap;
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

pub const LANGUAGES: [Language<'static>; 11] = [
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

#[derive(Debug, Error)]
pub enum MnemonicsError {
    #[error("Invalid words count")]
    InvalidWordsCount,
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Invalid checksum index")]
    InvalidChecksumIndex,
    #[error("Invalid language index")]
    InvalidLanguageIndex,
    #[error("Invalid language")]
    InvalidLanguage,
    #[error("Invalid key size")]
    InvalidKeySize,
    #[error("Invalid key from bytes")]
    InvalidKeyFromBytes,
    #[error("Invalid checksum calculation")]
    InvalidChecksumCalculation,
    #[error("No indices found")]
    NoIndicesFound,
    #[error("Word list sanity check error")]
    WordListSanityCheckError,
    #[error("Out of bounds")]
    OutOfBounds
}

pub struct Language<'a> {
    // Language name, like "English" or "French"
    name: &'a str,
    // Number of utf-8 chars to use for checksum
    prefix_length: usize,
    // List of words in the language
    words: [&'a str; WORDS_LIST]
}

// Calculate the checksum index for the seed based on the language prefix length
fn calculate_checksum_index(words: &[String], prefix_len: usize) -> Result<u32, MnemonicsError> {
    if words.len() != SEED_LENGTH {
        return Err(MnemonicsError::InvalidWordsCount);
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

// Verify the checksum of the seed based on the language prefix length and if the seed is composed of 25 words
fn verify_checksum(words: &Vec<String>, prefix_len: usize) -> Result<Option<bool>, MnemonicsError> {
    let checksum_index = calculate_checksum_index(&words[0..SEED_LENGTH], prefix_len)?;
    let checksum_word = words.get(checksum_index as usize).ok_or(MnemonicsError::InvalidChecksumIndex)?;
    Ok(words.get(SEED_LENGTH).map(|v| v == checksum_word))
}

// Find the indices of the words in the languages
fn find_indices(words: &Vec<String>) -> Result<Option<(Vec<usize>, usize)>, MnemonicsError> {
    'main: for (i, language) in LANGUAGES.iter().enumerate() {
        // This map is used to store the indices of the words in the language
        let mut language_words: HashMap<&str, usize> = HashMap::with_capacity(WORDS_LIST);
        // Build the map
        for (j, word) in language.words.iter().enumerate() {
            language_words.insert(word, j);
        }

        // Find the indices of the words
        let mut indices = Vec::new();
        for word in words.iter() {
            if let Some(index) = language_words.get(word.as_str()) {
                indices.push(*index);
            } else {
                // Incorrect language for this word, try the next one
                continue 'main;
            }
        }

        // We were able to build the indices, now verify checksum
        if !verify_checksum(&words, language.prefix_length)?.unwrap_or(true) {
            return Err(MnemonicsError::InvalidChecksum);
        }

        return Ok(Some((indices, i)));
    }
    Ok(None)
}

// Convert a words list to a Private Key (32 bytes)
pub fn words_to_key(words: &Vec<String>) -> Result<PrivateKey, MnemonicsError> {
    if !(words.len() == SEED_LENGTH + 1 || words.len() == SEED_LENGTH) {
        return Err(MnemonicsError::InvalidWordsCount);
    }

    let (indices, language_index) = find_indices(words)?.ok_or(MnemonicsError::NoIndicesFound)?;
    debug!("Language found: {}", LANGUAGES[language_index].name);

    let mut dest = Vec::with_capacity(KEY_SIZE);
    for i in (0..SEED_LENGTH).step_by(3) {
        let a = indices.get(i).ok_or(MnemonicsError::OutOfBounds)?;
        let b = indices.get(i + 1).ok_or(MnemonicsError::OutOfBounds)?;
        let c = indices.get(i + 2).ok_or(MnemonicsError::OutOfBounds)?;

        let val = a + WORDS_LIST * (((WORDS_LIST - a) + b) % WORDS_LIST) + WORDS_LIST * WORDS_LIST * (((WORDS_LIST - b) + c) % WORDS_LIST);
        if val % WORDS_LIST != *a {
            return Err(MnemonicsError::WordListSanityCheckError);
        }

        let val = val as u32;
        dest.extend_from_slice(&val.to_le_bytes());
    }

    Ok(PrivateKey::from_bytes(&dest).map_err(|_| MnemonicsError::InvalidKeyFromBytes)?)
}

// Transform a Private Key to a list of words based on the language index
pub fn key_to_words(key: &PrivateKey, language_index: usize) -> Result<Vec<String>, MnemonicsError> {
    let language = LANGUAGES.get(language_index).ok_or(MnemonicsError::InvalidLanguageIndex)?;
    key_to_words_with_language(key, language)
}

// Transform a Private Key to a list of words with a specific language
pub fn key_to_words_with_language(key: &PrivateKey, language: &Language) -> Result<Vec<String>, MnemonicsError> {
    if language.words.len() != WORDS_LIST {
        return Err(MnemonicsError::InvalidLanguage);
    }

    let bytes = key.to_bytes();
    if bytes.len() != KEY_SIZE {
        return Err(MnemonicsError::InvalidKeySize);
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
    words.push(words.get(checksum as usize).ok_or(MnemonicsError::InvalidChecksumCalculation)?.clone());

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

            let mut words2 = super::key_to_words_with_language(&nkey, language).unwrap();
            assert_eq!(words, words2);

            // Also test with 24 words only
            words2.pop();
            assert_eq!(words2.len(), 24);

            let nkey = super::words_to_key(&words2).unwrap();
            assert_eq!(key.as_scalar(), nkey.as_scalar());
        }
    }
}