
mod bip39;
mod entropy;

use entropy::BasicEntropy;
// use crate::bip39::Bip39;//generate_mnemonics;
// use bip39::generate_mnemonics;

fn main() {
    let ent = BasicEntropy;

    bip39::generate_mnemonics(15, &ent);
    // generate_mnemonics(15, &ent);
}
