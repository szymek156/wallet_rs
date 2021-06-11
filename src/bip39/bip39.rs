// typedef btc_bool (*entropy_source)(uint8_t *buf, uint32_t len, const uint8_t update_seed);

// btc_bool generate_mnemonics(size_t word_count, vector *words_out, entropy_source ent);

// btc_bool generate_master_seed(vector *words,
//                               const char *password,
//                               uint8_t seed_out[SHA512_DIGEST_LENGTH]);

// btc_bool recover_master_seed(vector *mnemonics,
//                              const char *password,
//                              uint8_t seed_out[SHA512_DIGEST_LENGTH]);

// btc_bool validate_checksum(vector *mnemonics);

// https://iancoleman.io/bip39/#english

use crate::entropy::EntropySource;
use log::debug;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::vec::Vec;
use to_binary::BinaryString;

// TODO: docs
fn generate_word_indices(word_count: usize, ent: &dyn EntropySource) -> Result<Vec<usize>, String> {
    let entropy_len = match word_count {
        12 | 15 | 18 | 21 | 24 => word_count / 3 * 32,
        _ => return Err(format!("Invalid word_count {}", word_count)),
    };

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
        let bits = &entropy_bits[start..start + 11];
        word_indices.push(usize::from_str_radix(&bits, 2).unwrap());
    }
    debug!("Word indexes: {:?}", word_indices);

    return Ok(word_indices);
}

pub fn generate_mnemonics(
    word_count: usize,
    ent: &dyn EntropySource,
) -> Result<Vec<String>, String> {
    let indices = generate_word_indices(word_count, ent)?;

    // Convert indices to actual words
    let mut filename = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    filename.push("src/bip39/english.txt");

    let reader = BufReader::new(File::open(filename).unwrap());

    let mut mnemonics = vec![String::new(); word_count];
    // Read the file line by line using the lines() iterator from std::io::BufRead.
    for (index, line) in reader.lines().enumerate() {
        match indices.iter().position(|&i| i == index) {
            Some(pos) => {
                let line = line.unwrap();
                mnemonics[pos] = line;
            }
            None => (),
        };
    }

    debug!("Mnemonics {:?}", mnemonics);

    // TODO: mnemonics is of type Vec<String> isn't it better to be Vec<&String> ??
    Ok(mnemonics)
}

#[cfg(test)]
mod tests {
    #[test]
    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    use super::*;

    struct DummyEntropy {
        input: String,
    }

    impl EntropySource for DummyEntropy {
        fn get_random_bits(&self, _count: usize) -> Vec<u8> {
            // let input = "d5a58c5fded9ac099f432a253dbffb68";
            // let input = "00000000000000000000000000000000";

            let decoded = hex::decode(&self.input).expect("Decoding failed");
            return decoded;
        }
    }

    impl Default for DummyEntropy {
        fn default() -> Self {
            DummyEntropy {
                input: "d5a58c5fded9ac099f432a253dbffb68".to_string(),
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    struct TestVector {
        ent: String,
        seed: String,
        mnemonics: String,
        xprv: String,
    }

    #[test]
    fn fiddling_around() {
        // SHA256
        let mut hasher = Sha256::new();

        // https://emn178.github.io/online-tools/sha256.html
        // 0x11 -> 4a64a107f0cb32536e5bce6c98c393db21cca7f4ea187ba8c4dca8b51d4ea80a
        // BIG ENDIAN!
        hasher.update(0x11002233_u32.to_be_bytes());
        println!("hash {:x}", hasher.finalize());

        // Converting hex strng to array of bytes
        let decoded = hex::decode("d5a58c5fded9ac099f432a253dbffb68").unwrap();

        let mut hasher = Sha256::new();
        hasher.update(decoded);
        println!("hash of string {:x}", hasher.finalize());
    }

    #[test]
    fn sha256_calculation_works() {
        let mut hasher = Sha256::new();
        hasher.update(DummyEntropy::default().get_random_bits(12));

        assert_eq!(
            "af6d1c421d3fc9a770c960c6552c22d25d0f6d2300c437a750e9f607f091ff9a",
            format!("{:x}", hasher.finalize())
        );
    }

    #[test]
    fn invalid_word_count() {
        assert_eq!(
            Err("Invalid word_count 69".to_string()),
            generate_mnemonics(69, &DummyEntropy::default())
        );
    }

    #[test]
    fn valid_word_count() {
        assert_eq!(
            Ok(vec![
                // TODO: da fuck
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
                "spend".to_string()
            ]),
            generate_mnemonics(12, &DummyEntropy::default())
        );
    }
}
