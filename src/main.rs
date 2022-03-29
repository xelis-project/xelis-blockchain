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

#[derive(FromArgs)]
/// Xelis Blockchain daemon
struct NodeConfig {
    /// optional node tag
    #[argh(option)]
    tag: Option<String>,
    /// bind address for p2p
    #[argh(option)]
    bind_address: String,
    /// enable debug logging
    #[argh(switch)]
    debug: bool,
    /// enable mining on this node
    #[argh(switch)]
    mining: bool
}

fn main() { // TODO add command line arguments
    let config: NodeConfig = argh::from_env();
    if let Err(e) = setup_logger(config.debug) {
        eprintln!("Couldn't initialize logger: {}", e);
        return;
    }

    info!("Xelis Blockchain running version: {}", VERSION);
    info!("----------------------------------------------");

    let blockchain = match Blockchain::new(config.tag, config.bind_address) {
        Ok(blockchain) => blockchain,
        Err(e) => {
            error!("Couldn't create blockchain: {}", e);
            return;
        }
    };

    if config.mining {
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
        .debug(Color::Green)
        .info(Color::Cyan)
        .warn(Color::Yellow)
        .error(Color::Red);
    let base = fern::Dispatch::new();
    let stdout_log = fern::Dispatch::new()
        .format(move |out, message, record| {
            let target = record.target();
            let mut target_with_pad = " ".repeat((30i16 - target.len() as i16).max(0) as usize) + target;
            if record.level() != Level::Error && record.level() != Level::Debug {
                target_with_pad = " ".to_owned() + &target_with_pad;
            }
            out.finish(format_args!(
                "\x1B[90m{} {}\x1B[0m \x1B[{}m{}\x1B[0m \x1B[90m>\x1B[0m {}",
                chrono::Local::now().format("[%Y-%m-%d] (%H:%M:%S%.3f)"),
                colors.color(record.level()),
                Color::BrightBlue.to_fg_str(),
                target_with_pad,
                message
            ))
        }).chain(std::io::stdout());

    let file_log = fern::Dispatch::new()
        .format(move |out, message, record| {
            let pad = " ".repeat((30i16 - record.target().len() as i16).max(0) as usize);
            let level_pad = if record.level() == Level::Error || record.level() == Level::Debug { "" } else { " " };
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

    let mut base = base.chain(file_log).chain(stdout_log);
    base = if debug {
        base.level(log::LevelFilter::Debug)
    } else {
        base.level(log::LevelFilter::Info)
    };
    base.apply()?;
    Ok(())
}