mod bip39;
mod entropy;

use entropy::BasicEntropy;

fn main() {
    let ent = BasicEntropy;

    let _res = bip39::generate_mnemonics(12, &ent).unwrap();
    // generate_mnemonics(15, &ent);
}
