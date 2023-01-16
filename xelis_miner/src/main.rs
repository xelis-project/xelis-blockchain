pub mod config;

use std::{time::Duration, sync::Arc};
use crate::config::DEFAULT_DAEMON_ADDRESS;
use futures_util::StreamExt;
use tokio::{sync::{broadcast, mpsc}, select};
use tokio_tungstenite::connect_async;
use xelis_common::{
    block::{Block, EXTRA_NONCE_SIZE},
    serializer::Serializer,
    difficulty::check_difficulty,
    config::{VERSION, DEV_ADDRESS},
    globals::get_current_timestamp,
    crypto::{hash::{Hashable, Hash}, address::Address},
    api::daemon::{GetBlockTemplateResult, SubmitBlockParams}, prompt::{Prompt, command::{CommandManager, Command, CommandError}, argument::{Arg, ArgType, ArgumentManager}}
};
use clap::Parser;
use log::{error, info, debug, warn};
use anyhow::{Result, Error};

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
    /// Numbers of threads to use (at least 1, max: 255)
    #[clap(short, long, default_value_t = 0)]
    num_threads: u8,
    /// Worker name to be displayed on daemon side
    #[clap(short, long, default_value_t = String::from("default"))]
    worker: String
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
    
    let threads_count = num_cpus::get();
    let mut threads = config.num_threads;
    if threads_count > u8::MAX as usize {
        warn!("Your CPU have more than 255 threads. This miner only support up to 255 threads used at once.");
    }

    // if no specific threads count is specified in options, set detected threads count
    if threads < 1 {
        threads = threads_count as u8;
    }

    info!("Total threads to use: {}", threads);
    
    if config.num_threads != 0 && threads as usize != threads_count {
        warn!("Attention, the number of threads used may not be optimal, recommended is: {}", threads);
    }
    // TODO show recommended threads count

    // broadcast channel to send new jobs / exit command to all threads
    let (sender, _) = broadcast::channel::<ThreadNotification>(threads as usize);
    // mpsc channel to send from threads to the "communication" task.
    let (block_sender, block_receiver) = mpsc::channel::<Block>(threads as usize);
    for id in 0..threads {
        debug!("Starting thread #{}", id);
        if let Err(e) = start_thread(id, sender.subscribe(), block_sender.clone()) {
            error!("Error while creating Mining Thread #{}: {}", id, e);
        }
    }

    // start communication task
    let task = tokio::spawn(communication_task(config.daemon_address, sender.clone(), block_receiver, address, config.worker));

    // run prompt until user exit
    run_prompt(prompt).await?;

    // stop the communication task
    task.abort();
    // send exit command to all threads to stop
    if let Err(_) = sender.send(ThreadNotification::Exit) {
        debug!("Error while sending exit message to threads");
    }

    Ok(())
}

// this Tokio task will runs indefinitely until the user stop himself the miner.
// It maintains a WebSocket connection with the daemon and notify all threads when it receive a new job.
// Its also the task who have the job to send directly the new block found by one of the threads.
// This allow mining threads to only focus on mining and receiving jobs through memory channels.
async fn communication_task(daemon_address: String, job_sender: broadcast::Sender<ThreadNotification>, mut block_receiver: mpsc::Receiver<Block>, address: Address<'_>, worker: String) {
    info!("Starting communication task");
    let client = match connect_async(format!("ws://{}/getwork/{}/{}", daemon_address, address.to_string(), worker)).await {
        Ok((client, response)) => {
            let status = response.status();
            if status.is_server_error() || status.is_client_error() {
                error!("Error while connecting to {}, got an unexpected response: {}", daemon_address, status.as_str());
                return;
            }
            client
        },
        Err(e) => {
            error!("Error while connecting to {}: {}", daemon_address, e);
            return;
        }
    };
    info!("Connected successfully to {}", daemon_address);
    let (write, read) = client.split();
    read.for_each(|message| async {
        match message {
            Ok(message) => {
                let text = message.into_text().unwrap();
                warn!("{}", text);
                // {"NewJob":{"difficulty":150000,"template":"aaa"}}
            },
            Err(e) => {
                error!("Error while reading message from {}: {}", daemon_address, e);
            }
        };
    }).await;

    // TODO tokio select! with websocket from node
    loop {
        select! {
            Some(block) = block_receiver.recv() => {
                /*match client.call_with::<SubmitBlockParams, Value>("submit_block", &SubmitBlockParams { block_template: block.to_hex() }) {
                    Ok(_) => {
                        info!("Block at height {} was successfully accepted!", block.get_height());
                    }
                    Err(e) => {
                        error!("Error while adding new block: {:?}", e);
                    }
                };*/
            }
        }
    }
}

fn start_thread(id: u8, mut job_receiver: broadcast::Receiver<ThreadNotification>, block_sender: mpsc::Sender<Block>) -> Result<(), Error> {
    let builder = std::thread::Builder::new().name(format!("Mining Thread #{}", id));
    builder.spawn(move || {
        let mut block: Block;
        let mut expected_difficulty: u64;
        let mut hash: Hash;

        info!("Mining Thread #{}: started", id);
        'main: loop {
            debug!("Mining Thread #{}: Waiting for new job...", id);
            match job_receiver.try_recv() { // TODO blocking
                Ok(message) => match message {
                    ThreadNotification::Exit => break,
                    ThreadNotification::NewJob(job, difficulty) => {
                        block = job;
                        // set thread id in extra nonce for more work spread between threads
                        block.extra_nonce[EXTRA_NONCE_SIZE - 1] = id;
                        expected_difficulty = difficulty;
                    }
                },
                Err(e) => {
                    error!("Mining Thread #{}: Error while trying to receive new job: {}. Retry in 1s", id, e);
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }
            }

            hash = block.hash();
            while !match check_difficulty(&hash, expected_difficulty) {
                Ok(value) => value,
                Err(e) => {
                    error!("Mining Thread #{}: error on difficulty check: {}", id, e);
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
            info!("Mining Thread #{}: block {} found at height {}", id, hash, block.get_height());
            if let Err(_) = block_sender.blocking_send(block) {
                error!("Mining Thread #{}: error while sending block found with hash {}", id, hash);
            }
        }
        info!("Mining Thread #{}: stopped", id);
    })?;
    Ok(())
}

async fn run_prompt(prompt: Arc<Prompt>) -> Result<()> {
    let mut command_manager = CommandManager::new();
    command_manager.add_command(Command::new("help", "Show this help", Some(Arg::new("command", ArgType::String)), help));
    command_manager.add_command(Command::new("exit", "Shutdown the daemon", None, exit));

    let closure = || async {
        format!("XELIS Miner >> ")
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

fn exit(_: &CommandManager, _: ArgumentManager) -> Result<(), CommandError> {
    info!("Stopping...");
    Err(CommandError::Exit)
}