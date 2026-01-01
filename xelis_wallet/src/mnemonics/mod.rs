pub mod languages;

use thiserror::Error;
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
    #[error("Unknown word: {0} at position {1}")]
    UnknownWord(String, usize),
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
    // number of utf-8 chars to use for checksum
    prefix_length: usize,
    // list of words in the language
    words: [&'a str; WORDS_LIST]
}

impl<'a> Language<'a> {
    pub fn get_name(&self) -> &str {
        self.name
    }

    pub fn get_words(&self) -> &[&str; WORDS_LIST] {
        &self.words
    }

    pub fn get_prefix_length(&self) -> usize {
        self.prefix_length
    }
}

// Calculate the checksum index for the seed based on the language prefix length
fn calculate_checksum_index(words: &[&str], prefix_len: usize) -> Result<u32, MnemonicsError> {
    if words.len() != SEED_LENGTH {
        return Err(MnemonicsError::InvalidWordsCount);
    }

    let mut chars: Vec<char> = Vec::new();
    for word in words {
        let mut word_chars: Vec<char> = word.chars()
            .map(|c| c.to_ascii_lowercase())
            .collect();

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
fn verify_checksum(words: &[&str], prefix_len: usize) -> Result<Option<bool>, MnemonicsError> {
    let checksum_index = calculate_checksum_index(&words[0..SEED_LENGTH], prefix_len)?;
    let checksum_word = words.get(checksum_index as usize).ok_or(MnemonicsError::InvalidChecksumIndex)?;
    Ok(words.get(SEED_LENGTH).map(|v| v.eq_ignore_ascii_case(checksum_word)))
}

// Check if at least one of the words is unique to a language
// This is used to report unknown words when converting mnemonics to key
fn has_unique_word_for_a_language<'a>(words: impl Iterator<Item = &'a str>) -> bool {
    'outer: for word in words {
        let mut count = 0;
        let word = word.trim().to_lowercase();
        for language in LANGUAGES.iter() {
            if language.get_words().iter().any(|v| v.to_lowercase() == word) {
                count += 1;
                if count > 1 {
                    // This word is not unique
                    // lets try another word
                    continue 'outer;
                }
            }
        }

        // If we reach here, it means this word is unique
        if count == 1 {
            return true;
        }
    }

    false
}

// Find the indices of the words in the languages
fn find_indices(words: &[&str]) -> Result<Option<(Vec<usize>, usize)>, MnemonicsError> {
    'main: for (i, language) in LANGUAGES.iter().enumerate() {
        // find the indices of the words
        let mut indices = Vec::new();
        for (i, word) in words.iter().enumerate() {
            let trimmed = word.trim().to_lowercase();
            if let Some(index) = language.get_words().iter().position(|v| v.to_lowercase() == trimmed) {
                indices.push(index);
            } else if indices.is_empty() {
                // incorrect language, try next one
                continue 'main;
            } else if has_unique_word_for_a_language(words.iter().take(i + 1).copied()) {
                // We made sure that we don't have any duplicated words among languages
                // So we can safely report an unknown word

                // We have found some indices, but one word is invalid
                // report it
                return Err(MnemonicsError::UnknownWord(word.to_string(), indices.len()));
            }
        }

        // we were able to build the indices, now verify checksum
        if !verify_checksum(&words, language.prefix_length)?.unwrap_or(true) {
            return Err(MnemonicsError::InvalidChecksum);
        }

        return Ok(Some((indices, i)));
    }

    Ok(None)
}

// convert a words list to a Private Key (32 bytes)
pub fn words_to_key(words: &[&str]) -> Result<PrivateKey, MnemonicsError> {
    if !(words.len() == SEED_LENGTH + 1 || words.len() == SEED_LENGTH) {
        return Err(MnemonicsError::InvalidWordsCount);
    }

    let (indices, language_index) = find_indices(words)?
        .ok_or(MnemonicsError::NoIndicesFound)?;

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

    PrivateKey::from_bytes(&dest).map_err(|_| MnemonicsError::InvalidKeyFromBytes)
}

// Transform a Private Key to a list of words based on the language index
pub fn key_to_words(key: &PrivateKey, language_index: usize) -> Result<Vec<&str>, MnemonicsError> {
    let language = LANGUAGES.get(language_index).ok_or(MnemonicsError::InvalidLanguageIndex)?;
    key_to_words_with_language(key, language)
}

// Transform a Private Key to a list of words with a specific language
pub fn key_to_words_with_language<'a>(key: &PrivateKey, language: &'a Language) -> Result<Vec<&'a str>, MnemonicsError> {
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

        words.extend([
            language.words[a as usize],
            language.words[b as usize],
            language.words[c as usize],
        ]);
    }

    let checksum = calculate_checksum_index(&words, language.prefix_length)?;
    words.push(words.get(checksum as usize).ok_or(MnemonicsError::InvalidChecksumCalculation)?);

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

    #[test]
    fn test_ignore_case() {
        // Try a random seed with mixed case
        let seed = ["KiNG", "gleeFuL", "fidgET", "furnished", "agreed", "rowboat", "factual", "echo", "scrub", "enforce", "bygones", "muzzle", "mews", "abbey", "swiftly", "issued", "tonic", "cinema", "lettuce", "zapped", "sighting", "kettle", "leopard", "logic", "enforce"];
        super::words_to_key(&seed).expect("Failed to convert words to key");
    }

    #[test]
    fn test_ignore_case_non_ascii() {
        // Try a random seed with mixed case and non-ascii characters
        let seed = ["的", "一", "是", "在", "不", "了", "有", "和", "人", "这", "中", "大", "为", "上", "个", "国", "我", "以", "要", "他", "时", "来", "用", "们"];
        super::words_to_key(&seed).expect("Failed to convert words to key");
    }

    #[test]
    fn test_duplicated_word_among_languages() {
        // album is present in French & English
        assert!(!super::has_unique_word_for_a_language(["album"].iter().copied()));
        // acheter is only present in French
        assert!(super::has_unique_word_for_a_language(["acheter"].iter().copied()));
        // acheter is unique, so it should return true
        assert!(super::has_unique_word_for_a_language(["album", "acheter", "album"].iter().copied()));
    }
}