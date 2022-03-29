mod globals;
mod config;
mod crypto;
mod wallet;
mod core;
mod p2p;

use crate::core::blockchain::Blockchain;
use crate::config::VERSION;
use log::{info, error, Level};
use fern::colors::{ColoredLevelConfig, Color};
use std::thread;
use argh::FromArgs;
use std::time::Duration;


fn main() { // TODO add command line arguments
    if let Err(e) = setup_logger(true) {
        eprintln!("Couldn't initialize logger: {}", e);
        return;
    }

    info!("Xelis Blockchain running version: {}", VERSION);
    info!("----------------------------------------------");
    
    let blockchain = match Blockchain::new(None, String::from("127.0.0.1:2128")) {
        Ok(blockchain) => blockchain,
        Err(e) => {
            error!("Couldn't create blockchain: {}", e);
            return;
        }
    };

    if false {
        let key = blockchain.get_dev_address().clone();
        loop {
            if blockchain.is_synced() {
                if let Err(e) = blockchain.mine_block(&key) {
                    println!("Error while mining block: {}", e);
                }
            } else {
                thread::sleep(Duration::from_millis(1000));
            }
        }
    }
    thread::park();
}

fn setup_logger(debug: bool) -> Result<(), fern::InitError> {
    let colors = ColoredLevelConfig::new()
        .info(Color::Green)
        .warn(Color::Yellow)
        .error(Color::Red);

    let base = fern::Dispatch::new();
    let stdout_log = fern::Dispatch::new()
        .format(move |out, message, record| {
            let target = record.target();
            let mut target_with_pad = " ".repeat((30i16 - target.len() as i16).max(0) as usize) + target;
            if record.level() != Level::Error {
                target_with_pad = " ".to_owned() + &target_with_pad;
            }
            out.finish(format_args!(
                "{} {} {} > {}",
                chrono::Local::now().format("[%Y-%m-%d] (%H:%M:%S%.3f)"),
                colors.color(record.level()),
                target_with_pad,
                message
            ))
        }).chain(std::io::stdout());

    let file_log = fern::Dispatch::new()
        .format(move |out, message, record| {
            let pad = " ".repeat((30i16 - record.target().len() as i16).max(0) as usize);
            let level_pad = if record.level() == Level::Error { "" } else { " " };
            out.finish(format_args!(
                "{} [{}{}] [{}]{} | {}",
                chrono::Local::now().format("[%Y-%m-%d] (%H:%M:%S%.3f)"),
                record.level(),
                level_pad,
                record.target(),
                pad,
                message
            ))
        }).chain(fern::log_file("xelis.log")?);

    let mut base = base.chain(file_log).chain(stdout_log).level(log::LevelFilter::Info);

    if debug {
        base = base
            .level_for("blockchain", log::LevelFilter::Debug)
            .level_for("p2p", log::LevelFilter::Debug);
    }
    base.apply()?;
    Ok(())
}