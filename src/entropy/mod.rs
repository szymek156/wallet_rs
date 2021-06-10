// use rand::{thread_rng, Rng};
use rand::prelude::*;

pub trait EntropySource {
    // TODO docs
    fn get_random_bits(&self, count: usize) -> Vec<u8>;
}

pub struct BasicEntropy;

impl EntropySource for BasicEntropy {
    fn get_random_bits(&self, count: usize) -> Vec<u8> {
        // Count is number of BITS, change to BYTES by / 8
        let mut out = vec![0; count / 8];

        thread_rng().fill_bytes(&mut out);

        out
    }
}
