mod bip39;
mod entropy;
use entropy::BasicEntropy;
use log::{debug, error, info, trace, warn};
use std::io::Write;
use std::process;
use std::thread;
use bip39::WordsCount;

fn setup_logger() {
    env_logger::builder()
        .format(|buf, record| {
            writeln!(
                buf,
                "{ts} [{pid}, {tid:?}] {level:^5} {module}.{loc:.>4}: {msg}",
                ts = buf.timestamp_micros(),
                pid = process::id(),
                tid = thread::current().id(),
                level = buf.default_styled_level(record.level()),
                module = record.module_path().unwrap(),
                loc = record.line().unwrap(),
                msg = record.args(),
            )
        })
        .init();

    trace!("This is an trace message.");
    debug!("This is an debug message.");
    info!("This is an info message.");
    warn!("This is an warn message.");
    error!("This is an error message.");
}

fn main() {
    setup_logger();

    let ent = BasicEntropy;
    let mnemonics = bip39::generate_mnemonics(WordsCount::_12, &ent).unwrap();
    let _seed = bip39::generate_master_seed(&mnemonics);
}
