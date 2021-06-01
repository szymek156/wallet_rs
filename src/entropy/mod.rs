// use rand::{thread_rng, Rng};
use rand::prelude::*;

pub trait EntropySource {
    fn get_random_bits(&self, count: usize) -> Vec<u8>;
}

pub struct BasicEntropy;

impl EntropySource for BasicEntropy {
    fn get_random_bits(&self, count: usize) -> Vec<u8> {
        let mut out = vec![0; count];

        thread_rng().fill_bytes(&mut out);

        out
    }
}
