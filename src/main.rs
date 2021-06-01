mod bip39;
mod entropy;
use entropy::BasicEntropy;

fn main() {
    let ent = BasicEntropy;

    bip39::generate_mnemonics(15, &ent);
}
