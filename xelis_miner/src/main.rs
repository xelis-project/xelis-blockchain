pub mod config;

use std::{time::Duration, sync::atomic::{AtomicU64, Ordering, AtomicUsize, AtomicBool}, thread};
use crate::config::DEFAULT_DAEMON_ADDRESS;
use fern::colors::Color;
use futures_util::{StreamExt, SinkExt};
use serde::{Serialize, Deserialize};
use tokio::{sync::{broadcast, mpsc, Mutex}, select, time::Instant};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use xelis_common::{
    block::{BlockMiner, BLOCK_WORK_SIZE, Difficulty},
    serializer::Serializer,
    difficulty::check_difficulty,
    config::VERSION,
    utils::{get_current_timestamp, format_hashrate, format_difficulty},
    crypto::{hash::{Hashable, Hash, hash}, address::Address},
    api::daemon::{GetBlockTemplateResult, SubmitBlockParams}, prompt::{Prompt, command::CommandManager, LogLevel, ShareablePrompt, self}, async_handler,
};
use clap::Parser;
use log::{error, info, debug, warn};
use anyhow::{Result, Error, Context};
use lazy_static::lazy_static;

#[derive(Parser)]
#[clap(version = VERSION, about = "XELIS Miner")]
pub struct MinerConfig {
    /// Wallet address to mine and receive block rewards on
    #[clap(short, long)]
    miner_address: String,
    /// Daemon address to connect to for mining
    #[clap(short = 'a', long, default_value_t = String::from(DEFAULT_DAEMON_ADDRESS))]
    daemon_address: String,
    /// Set log level
    #[clap(long, arg_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
    /// Enable the benchmark mode
    #[clap(short, long)]
    benchmark: bool,
    /// Iterations to run the benchmark
    #[clap(short, long, default_value_t = 1_000_000)]
    iterations: usize,
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
enum ThreadNotification<'a> {
    NewJob(BlockMiner<'a>, Difficulty, u64), // block work, difficulty, height
    WebSocketClosed, // WebSocket connection has been closed
    Exit // all threads must stop
}

#[derive(Serialize, Deserialize)]
pub enum SocketMessage {
    NewJob(GetBlockTemplateResult),
    BlockAccepted,
    BlockRejected
}

static WEBSOCKET_CONNECTED: AtomicBool = AtomicBool::new(false);
static CURRENT_HEIGHT: AtomicU64 = AtomicU64::new(0);
static BLOCKS_FOUND: AtomicUsize = AtomicUsize::new(0);
static BLOCKS_REJECTED: AtomicUsize = AtomicUsize::new(0);
static HASHRATE_COUNTER: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    static ref HASHRATE_LAST_TIME: Mutex<Instant> = Mutex::new(Instant::now());
}

// After how many iterations we update the timestamp of the block to avoid too much CPU usage 
const UPDATE_EVERY_NONCE: u64 = 1_000;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config: MinerConfig = MinerConfig::parse();
    let prompt = Prompt::new(config.log_level, config.filename_log, config.disable_file_logging)?;
    let address = match Address::from_string(&config.miner_address) {
        Ok(address) => address,
        Err(e) => {
            error!("Invalid miner address specified: {}", e);
            return Ok(())
        }
    };
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
    if config.benchmark {
        info!("Benchmark mode enabled, miner will try up to {} threads", threads_count);
        benchmark(threads as usize, config.iterations);
        info!("Benchmark finished");
        return Ok(())
    }

    info!("Miner address: {}", address);    
    if config.num_threads != 0 && threads as usize != threads_count {
        warn!("Attention, the number of threads used may not be optimal, recommended is: {}", threads_count);
    }

    // broadcast channel to send new jobs / exit command to all threads
    let (sender, _) = broadcast::channel::<ThreadNotification>(threads as usize);
    // mpsc channel to send from threads to the "communication" task.
    let (block_sender, block_receiver) = mpsc::channel::<BlockMiner>(threads as usize);
    for id in 0..threads {
        debug!("Starting thread #{}", id);
        if let Err(e) = start_thread(id, sender.subscribe(), block_sender.clone()) {
            error!("Error while creating Mining Thread #{}: {}", id, e);
        }
    }

    // start communication task
    let task = tokio::spawn(communication_task(config.daemon_address, sender.clone(), block_receiver, address, config.worker));

    if let Err(e) = run_prompt(prompt).await {
        error!("Error on running prompt: {}", e);
    }

    // send exit command to all threads to stop
    if let Err(_) = sender.send(ThreadNotification::Exit) {
        debug!("Error while sending exit message to threads");
    }

    // stop the communication task
    task.abort();

    Ok(())
}

fn benchmark(threads: usize, iterations: usize) {
    println!("{0: <10} | {1: <10} | {2: <16} | {3: <13} | {4: <13}", "Threads", "Total Time", "Total Iterations", "Time/PoW (ms)", "Hashrate");

    for bench in 1..=threads {
        let start = Instant::now();
        let mut handles = vec![];
        for _ in 0..bench {
            let handle = thread::spawn(move || {
                let mut random_bytes: [u8; BLOCK_WORK_SIZE] = [0; BLOCK_WORK_SIZE];
                for _ in 0..iterations {
                    random_bytes.iter_mut().for_each(|v| *v = rand::random::<u8>());
                    let _ = hash(&random_bytes);
                }
            });
            handles.push(handle);
        }

        for handle in handles { // wait on all threads
            handle.join().unwrap();
        }
        let duration = start.elapsed().as_millis();
        let hashrate = format_hashrate(1000f64 / (duration as f64 / (bench*iterations) as f64));
        println!("{0: <10} | {1: <10} | {2: <16} | {3: <13} | {4: <13}", bench, duration, bench*iterations, duration/(bench*iterations) as u128, hashrate);
    }
}

// this Tokio task will runs indefinitely until the user stop himself the miner.
// It maintains a WebSocket connection with the daemon and notify all threads when it receive a new job.
// Its also the task who have the job to send directly the new block found by one of the threads.
// This allow mining threads to only focus on mining and receiving jobs through memory channels.
async fn communication_task(mut daemon_address: String, job_sender: broadcast::Sender<ThreadNotification<'_>>, mut block_receiver: mpsc::Receiver<BlockMiner<'_>>, address: Address, worker: String) {
    info!("Starting communication task");
    'main: loop {
        if !daemon_address.starts_with("ws://") && !daemon_address.starts_with("wss://") {
            daemon_address = format!("ws://{}", daemon_address);
        }

        info!("Trying to connect to {}", daemon_address);
        let client = match connect_async(format!("{}/getwork/{}/{}", daemon_address, address.to_string(), worker)).await {
            Ok((client, response)) => {
                let status = response.status();
                if status.is_server_error() || status.is_client_error() {
                    error!("Error while connecting to {}, got an unexpected response: {}", daemon_address, status.as_str());
                    warn!("Trying to connect to WebSocket again in 10 seconds...");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue 'main;
                }
                client
            },
            Err(e) => {
                if let tokio_tungstenite::tungstenite::Error::Http(e) = e {
                    let body: String = e.into_body()
                        .map_or(
                            "Unknown error".to_owned(),
                            |v| String::from_utf8_lossy(&v).to_string()
                        );
                    error!("Error while connecting to {}, got an unexpected response: {}", daemon_address, body);
                } else {
                    error!("Error while connecting to {}: {}", daemon_address, e);
                }

                warn!("Trying to connect to WebSocket again in 10 seconds...");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue 'main;
            }
        };
        WEBSOCKET_CONNECTED.store(true, Ordering::SeqCst);
        info!("Connected successfully to {}", daemon_address);
        let (mut write, mut read) = client.split();
        loop {
            select! {
                Some(message) = read.next() => { // read all messages from daemon
                    match handle_websocket_message(message, &job_sender).await {
                        Ok(exit) => {
                            if exit {
                                break;
                            }
                        },
                        Err(e) => {
                            error!("Error while handling message from WebSocket: {}", e);
                            break;
                        }
                    }
                },
                Some(block) = block_receiver.recv() => { // send all valid blocks found to the daemon
                    debug!("Block header work hash found: {}", block.header_work_hash);
                    let submit = serde_json::json!(SubmitBlockParams { block_template: block.to_hex() }).to_string();
                    if let Err(e) = write.send(Message::Text(submit)).await {
                        error!("Error while sending the block found to the daemon: {}", e);
                        break;
                    }
                }
            }
        }

        WEBSOCKET_CONNECTED.store(false, Ordering::SeqCst);
        if job_sender.send(ThreadNotification::WebSocketClosed).is_err() {
            error!("Error while sending WebSocketClosed message to threads");
        }

        warn!("Trying to connect to WebSocket again in 10 seconds...");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn handle_websocket_message(message: Result<Message, tokio_tungstenite::tungstenite::Error>, job_sender: &broadcast::Sender<ThreadNotification<'_>>) -> Result<bool, Error> {
    match message? {
        Message::Text(text) => {
            debug!("new message from daemon: {}", text);
            match serde_json::from_slice::<SocketMessage>(text.as_bytes())? {
                SocketMessage::NewJob(job) => {
                    info!("New job received from daemon: difficulty = {} and height = {}", job.difficulty, job.height);
                    let block = BlockMiner::from_hex(job.template).context("Error while decoding new job received from daemon")?;
                    CURRENT_HEIGHT.store(job.height, Ordering::SeqCst);

                    if let Err(e) = job_sender.send(ThreadNotification::NewJob(block, job.difficulty, job.height)) {
                        error!("Error while sending new job to threads: {}", e);
                    }
                },
                SocketMessage::BlockAccepted => {
                    BLOCKS_FOUND.fetch_add(1, Ordering::SeqCst);
                    info!("Block submitted has been accepted by network !");
                },
                SocketMessage::BlockRejected => {
                    BLOCKS_REJECTED.fetch_add(1, Ordering::SeqCst);
                    error!("Block submitted has been rejected by network !");
                }
            }
        },
        Message::Close(reason) => {
            let reason: String = if let Some(reason) = reason {
                reason.to_string()
            } else {
                "No reason".into()
            };
            warn!("Daemon has closed the WebSocket connection with us: {}", reason);
            return Ok(true);
        },
        _ => {
            warn!("Unexpected message from WebSocket");
            return Ok(true);
        }
    };

    Ok(false)
}

fn start_thread(id: u8, mut job_receiver: broadcast::Receiver<ThreadNotification<'static>>, block_sender: mpsc::Sender<BlockMiner<'static>>) -> Result<(), Error> {
    let builder = thread::Builder::new().name(format!("Mining Thread #{}", id));
    builder.spawn(move || {
        let mut job: BlockMiner;
        let mut hash: Hash;

        info!("Mining Thread #{}: started", id);
        'main: loop {
            let message = match job_receiver.blocking_recv() {
                Ok(message) => message,
                Err(e) => {
                    error!("Error on thread #{} while waiting on new job: {}", id, e);
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
            };

            match message {
                ThreadNotification::WebSocketClosed => {
                    // wait until we receive a new job, check every 100ms
                    while job_receiver.is_empty() {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
                ThreadNotification::Exit => {
                    info!("Exiting Mining Thread #{}...", id);
                    break 'main;
                },
                ThreadNotification::NewJob(new_job, expected_difficulty, height) => {
                    debug!("Mining Thread #{} received a new job", id);
                    job = new_job;
                    // set thread id in extra nonce for more work spread between threads
                    // because it's a u8, it support up to 255 threads
                    job.extra_nonce[job.extra_nonce.len() - 1] = id;

                    // Solve block
                    hash = job.get_pow_hash();
                    while !match check_difficulty(&hash, expected_difficulty) {
                        Ok(value) => value,
                        Err(e) => {
                            error!("Mining Thread #{}: error on difficulty check: {}", id, e);
                            continue 'main;
                        }
                    } {
                        // check if we have a new job pending
                        // Only update every 1 000 iterations to avoid too much CPU usage
                        if job.nonce % UPDATE_EVERY_NONCE == 0 {
                            if !job_receiver.is_empty() {
                                continue 'main;
                            }
                        }

                        job.nonce += 1;
                        hash = job.get_pow_hash();
                        job.timestamp = get_current_timestamp();
                        HASHRATE_COUNTER.fetch_add(1, Ordering::Relaxed);
                    }

                    // compute the reference hash for easier finding of the block
                    let block_hash = job.hash();
                    info!("Mining Thread #{}: block {} found at height {} with difficulty {}", id, block_hash, height, format_difficulty(expected_difficulty));
                    if let Err(_) = block_sender.blocking_send(job) {
                        error!("Mining Thread #{}: error while sending block found with hash {}", id, block_hash);
                        continue 'main;
                    }
                }
            };
        }
        info!("Mining Thread #{}: stopped", id);
    })?;
    Ok(())
}

async fn run_prompt(prompt: ShareablePrompt) -> Result<()> {
    let command_manager = CommandManager::default(prompt.clone())?;
    let closure = |_: &_, _: &_| async {
        let height_str = format!(
            "{}: {}",
            prompt::colorize_str(Color::Yellow, "Height"),
            prompt::colorize_string(Color::Green, &format!("{}", CURRENT_HEIGHT.load(Ordering::SeqCst))),
        );
        let blocks_found = format!(
            "{}: {}",
            prompt::colorize_str(Color::Yellow, "Accepted"),
            prompt::colorize_string(Color::Green, &format!("{}", BLOCKS_FOUND.load(Ordering::SeqCst))),
        );
        let blocks_rejected = format!(
            "{}: {}",
            prompt::colorize_str(Color::Yellow, "Rejected"),
            prompt::colorize_string(Color::Green, &format!("{}", BLOCKS_REJECTED.load(Ordering::SeqCst))),
        );
        let status = if WEBSOCKET_CONNECTED.load(Ordering::SeqCst) {
            prompt::colorize_str(Color::Green, "Online")
        } else {
            prompt::colorize_str(Color::Red, "Offline")
        };
        let hashrate = {
            let mut last_time = HASHRATE_LAST_TIME.lock().await;
            let counter = HASHRATE_COUNTER.swap(0, Ordering::SeqCst);

            let hashrate = 1000f64 / (last_time.elapsed().as_millis() as f64 / counter as f64);
            *last_time = Instant::now();

            prompt::colorize_string(Color::Green, &format!("{}", format_hashrate(hashrate)))
        };

        Ok(
            format!(
                "{} | {} | {} | {} | {} | {} {} ",
                prompt::colorize_str(Color::Blue, "XELIS Miner"),
                height_str,
                blocks_found,
                blocks_rejected,
                hashrate,
                status,
                prompt::colorize_str(Color::BrightBlack, ">>")
            )
        )
    };

    prompt.start(Duration::from_millis(100), Box::new(async_handler!(closure)), &Some(command_manager)).await?;
    Ok(())
}