// typedef btc_bool (*entropy_source)(uint8_t *buf, uint32_t len, const uint8_t update_seed);

// btc_bool generate_mnemonics(size_t word_count, vector *words_out, entropy_source ent);

// btc_bool generate_master_seed(vector *words,
//                               const char *password,
//                               uint8_t seed_out[SHA512_DIGEST_LENGTH]);

// btc_bool recover_master_seed(vector *mnemonics,
//                              const char *password,
//                              uint8_t seed_out[SHA512_DIGEST_LENGTH]);

// btc_bool validate_checksum(vector *mnemonics);

use std::vec::Vec;

use crate::entropy::EntropySource;


pub struct Bip39;

// impl Bip39 {

// }
pub fn generate_mnemonics(word_count: usize, ent: &dyn EntropySource) -> Vec<&str> {
    let out = ent.get_random_bits(16);

    println!("Entropy {:?}", out);

    // match word_count {
    //     12 | 15 | 18 | 21 | 24 =>
    // }

    [].to_vec()

    // TODO: use proper err handling
}

#[cfg(test)]
mod tests {

    use super::*;

    struct DummyEntropy {}

    impl EntropySource for DummyEntropy {
        fn get_random_bits(&self, count: usize) -> Vec<u8> {
            return vec![];
        }
    }

    #[test]
    fn bla() {}
}
