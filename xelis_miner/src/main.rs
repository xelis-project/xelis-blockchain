pub mod config;

use std::{time::Duration, sync::Arc};
use crate::config::DEFAULT_DAEMON_ADDRESS;
use serde_json::Value;
use tokio::{sync::{broadcast, mpsc}, time::interval, select};
use xelis_common::{
    json_rpc::JsonRPCClient,
    block::Block,
    serializer::Serializer,
    difficulty::check_difficulty,
    config::{VERSION, DEV_ADDRESS},
    globals::get_current_timestamp,
    crypto::{hash::{Hashable, Hash}, address::Address},
    api::daemon::{GetBlockTemplateResult, GetBlockTemplateParams, SubmitBlockParams}, prompt::{Prompt, command::{CommandManager, Command, CommandError}, argument::{Arg, ArgType, ArgumentManager}}
};
use clap::Parser;
use log::{error, info, debug};
use anyhow::Result;

#[derive(Parser)]
#[clap(version = VERSION, about = "XELIS Miner")]
pub struct MinerConfig {
    /// Wallet address to mine and receive block rewards on
    #[clap(short, long, default_value_t = String::from(DEV_ADDRESS))]
    miner_address: String,
    /// Daemon address to connect to for mining
    #[clap(short = 'a', long, default_value_t = String::from(DEFAULT_DAEMON_ADDRESS))]
    daemon_address: String,
    /// Enable the debug mode
    #[clap(short, long)]
    debug: bool,
    /// Disable the log file
    #[clap(short = 'f', long)]
    disable_file_logging: bool,
    /// Log filename
    #[clap(short = 'l', long, default_value_t = String::from("xelis-miner.log"))]
    filename_log: String,
    /// Numbers of threads to use (at least 1)
    #[clap(short, long, default_value_t = 1)]
    num_threads: usize
}

#[derive(Clone)]
enum ThreadNotification {
    NewJob(Block, u64),
    Exit
}

#[tokio::main]
async fn main() -> Result<()> {
    let config: MinerConfig = MinerConfig::parse();
    let prompt = Prompt::new(config.debug, config.filename_log, config.disable_file_logging)?;
    let address = match Address::from_string(&config.miner_address) {
        Ok(address) => address,
        Err(e) => {
            error!("Invalid miner address specified: {}", e);
            return Ok(())
        }
    };
    info!("Miner address: {}", address);

    let threads = config.num_threads;
    if threads < 1 {
        error!("You must use at least 1 thread.");
        return Ok(())
    }

    info!("Total threads to use: {}", threads);
    // TODO show recommended threads count

    // broadcast channel to send new jobs / exit command to all threads
    let (sender, _) = broadcast::channel::<ThreadNotification>(threads);
    // mpsc channel to send from threads to the "communication" task.
    let (block_sender, block_receiver) = mpsc::channel::<Block>(threads);
    for id in 0..threads {
        debug!("Starting thread #{}", id);
        start_thread(id, sender.subscribe(), block_sender.clone());
    }

    // start communication task
    tokio::spawn(communication_task(config.daemon_address, sender.clone(), block_receiver, address));

    // run prompt until user exit
    run_prompt(prompt).await?;

    // send exit command to all threads to stop
    if let Err(_) = sender.send(ThreadNotification::Exit) {
        debug!("Error while sending exit message to threads");
    }

    Ok(())
}

async fn communication_task(daemon_address: String, job_sender: broadcast::Sender<ThreadNotification>, mut block_receiver: mpsc::Receiver<Block>, address: Address<'_>) {
    let client = JsonRPCClient::new(format!("{}/json_rpc", daemon_address));
    let block_template = GetBlockTemplateParams { address };
    let mut request_job_interval = interval(Duration::from_secs(5));
    // TODO tokio select! with websocket from node
    loop {
        select! {
            Some(block) = block_receiver.recv() => {
                match client.call_with::<SubmitBlockParams, Value>("submit_block", &SubmitBlockParams { block_template: block.to_hex() }) {
                    Ok(_) => {
                        info!("Block at height {} was successfully accepted!", block.get_height());
                    }
                    Err(e) => {
                        error!("Error while adding new block: {:?}", e);
                    }
                };
                request_job_interval.reset();
            },
            _ = request_job_interval.tick() => {
                match client.call_with::<GetBlockTemplateParams<'_>, GetBlockTemplateResult>("get_block_template", &block_template) {
                    Ok(block_template) => {
                        if let Ok(block) = Block::from_hex(block_template.template) {
                            if let Err(_) = job_sender.send(ThreadNotification::NewJob(block, block_template.difficulty)) {
                                error!("Error while sending job to threads!");
                            }
                        } else {
                            error!("Invalid Block Template, custom node?");
                        }
                    }
                    Err(e) => {
                        error!("Error while getting new job: {}", e);
                    }
                };
            }
        }
    }
}

fn start_thread(id: usize, mut job_receiver: broadcast::Receiver<ThreadNotification>, block_sender: mpsc::Sender<Block>) {
    std::thread::spawn(move || {
        let mut block: Block;
        let mut expected_difficulty: u64;
        let mut hash: Hash;

        info!("Thread #{}: started", id);
        'main: loop {
            debug!("Thread #{}: Waiting for new job...", id);
            match job_receiver.try_recv() { // TODO blocking
                Ok(message) => match message {
                    ThreadNotification::Exit => break,
                    ThreadNotification::NewJob(job, difficulty) => {
                        block = job;
                        expected_difficulty = difficulty;
                    }
                },
                Err(e) => {
                    error!("Thread #{}: Error while trying to receive new job: {}. Retry in 1s", id, e);
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }
            }

            hash = block.hash();
            while !match check_difficulty(&hash, expected_difficulty) {
                Ok(value) => value,
                Err(e) => {
                    error!("Thread #{}: error on difficulty check: {}", id, e);
                    continue 'main;
                }
            } {
                // check if we have a new job pending
                if !job_receiver.is_empty() {
                    continue 'main;
                }

                block.nonce += 1;
                block.timestamp = get_current_timestamp();
                hash = block.hash();
            }
            info!("Thread #{}: block {} found at height {}", id, hash, block.get_height());
            if let Err(_) = block_sender.blocking_send(block) {
                error!("Thread #{}: error while sending block found with hash {}", id, hash);
            }
        }
        info!("Thread #{}: stopped", id);
    });

}

async fn run_prompt(prompt: Arc<Prompt>) -> Result<()> {
    let mut command_manager = CommandManager::new();
    command_manager.add_command(Command::new("help", "Show this help", Some(Arg::new("command", ArgType::String)), help));
    command_manager.add_command(Command::new("exit", "Shutdown the daemon", None, exit));

    let closure = || async {
        format!("XELIS Miner >>")
    };
    prompt.start(Duration::from_millis(100), &closure, command_manager).await?;
    Ok(())
}

fn help(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    if args.has_argument("command") {
        let arg_value = args.get_value("command")?.to_string_value()?;
        let cmd = manager.get_command(&arg_value).ok_or(CommandError::CommandNotFound)?;
        manager.message(&format!("Usage: {}", cmd.get_usage()));
    } else {
        manager.message("Available commands:");
        for cmd in manager.get_commands() {
            manager.message(&format!("- {}: {}", cmd.get_name(), cmd.get_description()));
        }
    }
    Ok(())
}

fn exit(manager: &CommandManager, mut args: ArgumentManager) -> Result<(), CommandError> {
    info!("Stopping...");
    Err(CommandError::Exit)
}