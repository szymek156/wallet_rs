/// Implementation of BIP39 - generation of mnemonics from entropy
/// # Resources
/// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
/// https://iancoleman.io/bip39/#english
use crate::entropy::EntropySource;
use hmac::Hmac;
use log::{debug, error, info};
use pbkdf2::pbkdf2;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::vec::Vec;
// TODO: no setup/teardown for tests, shame!
use test_env_log::test;
use to_binary::BinaryString;

pub type Mnemonics = Vec<String>;
pub type Seed = Vec<u8>;

// TODO: any better alternative for narrowing type to have only a subset of valid integer values?
#[derive(Debug, PartialEq)]
pub enum WordsCount {
    _12 = 12,
    _15 = 15,
    _18 = 18,
    _21 = 21,
    _24 = 24,
}

/// Converting usize to WordsCount
impl TryFrom<usize> for WordsCount {
    type Error = String;

    fn try_from(from: usize) -> Result<Self, Self::Error> {
        match from {
            12 => Ok(WordsCount::_12),
            15 => Ok(WordsCount::_15),
            18 => Ok(WordsCount::_18),
            21 => Ok(WordsCount::_21),
            24 => Ok(WordsCount::_24),
            _ => Err(format!("Invalid argument to convert WordsCount {}", from)),
        }
    }
}

/// Gets string representing binary number of arbitrary size
/// Returns it's hexadecimal representation
fn bitstring_to_hex(bitstring: &str) -> String {
    let len = bitstring.len() / 32;
    let remainder = bitstring.len() % 32;

    let mut hex = String::default();

    //  Split bitstring to u32 packets and convert it one by one
    for i in 0..len {
        let start = i * 32;
        let end = start + 32;

        let n: u32 = u32::from_str_radix(&bitstring[start..end], 2).unwrap();
        hex += &format!("{:08x}", n);
    }

    //TODO: add tests
    // Convert the remainder < u32, if any
    if remainder > 0 {
        let start = bitstring.len() - remainder;
        let n = u32::from_str_radix(&bitstring[start..], 2).unwrap();
        hex += &format!("{:x}", n);
    }

    hex
}

/// Opens a file containing dictionary of words used in mnemonic generation
fn get_dictionary() -> Vec<String> {
    let mut filename = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    filename.push("src/bip39/english.txt");
    let reader = BufReader::new(File::open(filename).unwrap());

    let words: Vec<_> = reader.lines().map(|word| word.unwrap()).collect();
    words
}

/// Gets mnemonics collection, calculates their checksum and returns bool indicating if it is correct.
pub fn is_checksum_valid(mnemonics: &Mnemonics) -> Result<bool, String> {
    let words = get_dictionary();

    let word_count = mnemonics.len();
    let entropy_len = word_count / 3 * 32;
    let checksum_len = entropy_len / 32;

    // Convert words to indices
    // Change indices to bitstring
    let mut bitstring = String::default();

    for memo in mnemonics {
        let position = match words.iter().position(|el| memo == el) {
            Some(p) => p as u32,
            None => return Err(format!("Index for word {} not found!", memo)),
        };

        // Convert to bit, 11 bits wide, leading zeros
        bitstring += &format!("{:011b}", position);
    }

    debug!("Bitstring is {}", bitstring);

    let entropy_hex = bitstring_to_hex(&bitstring[..entropy_len]);
    let checksum_memo = &bitstring[entropy_len..];

    debug!("Entropy: {}", entropy_hex);

    // hex_string -> hex::decode [u8] -> Sha256::digest GenericArray -> .as_slice() &[u8] -> .0 bin string
    let checksum =
        &BinaryString::from(Sha256::digest(&hex::decode(entropy_hex).unwrap()).as_slice()).0
            [..checksum_len];

    if checksum_memo == checksum {
        info!("Checksum is correct!");
        Ok(true)
    } else {
        error!(
            "Incorrect checksum expected {}, calculated {}",
            checksum_memo, checksum
        );
        Ok(false)
    }
}

/// Generates seed from given mnemonics, can be used later in HD wallets
pub fn generate_master_seed(mnemonics: &Mnemonics) -> Result<Seed, String> {
    generate_master_seed_with_password(mnemonics, "")
}

/// Generates seed from given mnemonics, and password. Can be used later in HD wallets
pub fn generate_master_seed_with_password(
    mnemonics: &Mnemonics,
    user_password: &str,
) -> Result<Seed, String> {
    let salt = "mnemonic".to_string() + user_password;
    let iterations = 2048;
    let password = mnemonics.join(" ");

    let mut seed: Seed = vec![0; 64];
    // Use low level api - can be used in [nostd] environment.
    pbkdf2::<Hmac<Sha512>>(password.as_bytes(), salt.as_bytes(), iterations, &mut seed);

    Ok(seed)
}

/// Uses entropy to generate indices for given ```word_count``` words
fn generate_word_indices(word_count: WordsCount, ent: &dyn EntropySource) -> Vec<usize> {
    let entropy_len = word_count as usize / 3 * 32;

    debug!("Total bits {}", entropy_len);

    let entropy = ent.get_random_bits(entropy_len);
    debug!("Entropy {:x?}", entropy);

    // A checksum is generated by taking the first
    //  ENT / 32  bits of its SHA256 hash.
    let checksum_len = entropy_len / 32;
    // Calculate hash, convert to bit string, get first checksum_len bits
    let checksum = &BinaryString::from(Sha256::digest(&entropy).as_slice()).0[..checksum_len];

    // Change entropy bytes to bin string
    // This checksum is appended to the end of the initial entropy.
    let entropy_bits = BinaryString::from(entropy).0 + checksum;

    debug!("Raw binary: {}", entropy_bits);

    // Next, these concatenated bits are split into groups of 11 bits,
    // each encoding a number from 0-2047, serving as an index into a wordlist.
    let mut word_indices = vec![];

    for start in (0..entropy_bits.len()).step_by(11) {
        // Get 11 bits and convert to decimal
        let bits = &entropy_bits[start..start + 11];
        word_indices.push(usize::from_str_radix(&bits, 2).unwrap());
    }
    debug!("Word indexes: {:?}", word_indices);

    return word_indices;
}

/// Converts indices to actual mnemonics collection
fn get_words_from_file(indices: &Vec<usize>) -> Mnemonics {
    // Convert indices to actual words
    let words = get_dictionary();

    let word_count = indices.len();
    let mut found_memos = 0;

    let mut mnemonics = vec![String::new(); word_count];
    // Read the file line by line using the lines() iterator from std::io::BufRead.
    'file_loop: for (index, word) in words.iter().enumerate() {
        // Iterate over indices, check if any element matches, if so,
        // put in mnemonics on 'position'
        for (position, i) in indices.iter().enumerate() {
            // TODO: how to get rid off * here?
            if *i == index {
                mnemonics[position] = String::from(word);
                found_memos += 1;

                // 'sort of' optimization, if all words are found - break
                if found_memos == word_count {
                    debug!("Breaking the loop at idx {}", index);

                    // TODO: this smells like a goto, but smell is nice
                    break 'file_loop;
                }
            }
        }
    }

    debug!("Mnemonics {:?}", mnemonics);

    // TODO: mnemonics is of type Vec<String> isn't it better to be Vec<&String> ??
    mnemonics
}

/// Generates mnemonics as defined in BIP39
///
/// Function gets specific amount of bits from entropy source, calculates checksum,
/// and uses both to select given amount of words from english dictionary.
///
/// Mnemonics can be later used to generate a seed for deterministic wallets
/// Or to recover one on a new device.
///
/// # Example
/// ```
/// let ent = BasicEntropy;
/// let mnemonics = bip39::generate_mnemonics(WordsCount::_12, &ent).unwrap();
/// ```
///
pub fn generate_mnemonics(word_count: WordsCount, ent: &dyn EntropySource) -> Mnemonics {
    let indices = generate_word_indices(word_count, ent);

    get_words_from_file(&indices)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyEntropy<'a> {
        input: &'a str,
    }

    impl<'a> EntropySource for DummyEntropy<'a> {
        fn get_random_bits(&self, _count: usize) -> Vec<u8> {
            let decoded = hex::decode(&self.input).expect("Decoding failed");
            decoded
        }
    }

    impl<'a> Default for DummyEntropy<'a> {
        fn default() -> Self {
            DummyEntropy {
                // Use site from the top of this file to get other values, and compare
                input: &"d5a58c5fded9ac099f432a253dbffb68",
            }
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct TestElement {
        ent: String,
        seed: String,
        mnemonics: String,
        xprv: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct TestVector {
        english: Vec<TestElement>,
    }

    #[test_env_log::test]
    fn generate_mnemonics_works() {
        let mnemonics = vec![
            // TODO: how to avoid that .to_string() crap?
            "stick".to_string(),
            "cluster".to_string(),
            "blood".to_string(),
            "sad".to_string(),
            "onion".to_string(),
            "age".to_string(),
            "laptop".to_string(),
            "grab".to_string(),
            "cement".to_string(),
            "unknown".to_string(),
            "yard".to_string(),
            "spend".to_string(),
        ];
        assert_eq!(
            mnemonics,
            generate_mnemonics(WordsCount::_12, &DummyEntropy::default())
        );
    }

    #[test_env_log::test]
    fn is_checksum_valid_works() {
        let mut mnemonics = generate_mnemonics(WordsCount::_12, &DummyEntropy::default());

        assert_eq!(is_checksum_valid(&mnemonics).unwrap(), true);

        mnemonics[0] = "spend".to_string();
        assert_eq!(is_checksum_valid(&mnemonics).unwrap(), false);
    }

    #[test_env_log::test]
    fn is_checksum_valid_returns_error_on_invalid_word() {
        let mut mnemonics = generate_mnemonics(WordsCount::_12, &DummyEntropy::default());
        mnemonics[0] = "slick".to_string();
        assert_eq!(
            is_checksum_valid(&mnemonics),
            Err(String::from("Index for word slick not found!"))
        );
    }

    #[test_env_log::test]
    fn generate_master_seed_works() {
        let mnemonics = vec![
            // TODO: how to avoid that .to_string() crap?
            "stick".to_string(),
            "cluster".to_string(),
            "blood".to_string(),
            "sad".to_string(),
            "onion".to_string(),
            "age".to_string(),
            "laptop".to_string(),
            "grab".to_string(),
            "cement".to_string(),
            "unknown".to_string(),
            "yard".to_string(),
            "spend".to_string(),
        ];
        let seed = "f3990aab57ffcba134df93414ce4246091a68598c6e06142dd3e62\
                    5990542bcc51f356971e33c98e597dc76590e1fa8b3a2e5e3195b6\
                    41d0ad34ddd5441dd0ec";
        assert_eq!(
            Ok(hex::decode(seed).unwrap()),
            generate_master_seed(&mnemonics)
        );
    }

    #[test_env_log::test]
    fn cannot_convert_invalid_integer_to_words_count() {
        let invalid = 69;
        assert_eq!(
            Err(format!(
                "Invalid argument to convert WordsCount {}",
                invalid
            )),
            WordsCount::try_from(invalid)
        );
    }

    #[test_env_log::test]
    #[ignore]
    fn test_vector() {
        // https://github.com/trezor/python-mnemonic/blob/master/vectors.json
        let mut filename = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        filename.push("src/bip39/vectors.json");
        let reader = BufReader::new(File::open(filename).unwrap());

        let test_vector: TestVector = serde_json::from_reader(reader).unwrap();

        for test in &test_vector.english {
            let mnemonics: Vec<String> = test
                .mnemonics
                .split_whitespace() // Returns Vec<&str>...convert to String...
                .map(String::from)
                .collect();

            let ent = DummyEntropy { input: &test.ent };

            let word_count: WordsCount = WordsCount::try_from(mnemonics.len()).unwrap();

            assert_eq!(mnemonics, generate_mnemonics(word_count, &ent));

            assert_eq!(is_checksum_valid(&mnemonics), Ok(true));

            assert_eq!(
                Ok(hex::decode(&test.seed).unwrap()),
                generate_master_seed_with_password(&mnemonics, "TREZOR")
            );
        }
    }
}
