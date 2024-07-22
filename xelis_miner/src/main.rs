pub mod config;

use std::{
    sync::{
        atomic::{
            AtomicBool,
            AtomicU64,
            AtomicUsize,
            Ordering
        },
        RwLock
    },
    thread,
    time::Duration
};
use crate::config::DEFAULT_DAEMON_ADDRESS;
use fern::colors::Color;
use futures_util::{StreamExt, SinkExt};
use serde::{Serialize, Deserialize};
use tokio::{
    select,
    sync::{
        broadcast,
        mpsc,
        Mutex
    },
    task::JoinHandle,
    time::Instant
};
#[cfg(feature = "api_stats")]
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        Message,
        Error as TungsteniteError
    }
};
use xelis_common::{
    tokio::spawn_task,
    api::daemon::{
        GetMinerWorkResult,
        SubmitMinerWorkParams,
    },
    async_handler,
    block::{MinerWork, Worker, Algorithm},
    config::VERSION,
    crypto::{
        Address,
        Hash,
    },
    difficulty::{
        check_difficulty_against_target,
        compute_difficulty_target,
        difficulty_from_hash,
        Difficulty
    },
    prompt::{
        command::CommandManager,
        LogLevel,
        Prompt,
        ShareablePrompt,
        ModuleConfig
    },
    serializer::Serializer,
    time::get_current_time_in_millis,
    utils::{
        format_difficulty,
        format_hashrate,
        sanitize_daemon_address
    }
};
use clap::Parser;
use log::{
    debug,
    info,
    warn,
    error,
};
use anyhow::{
    Result,
    Error,
    Context
};
use lazy_static::lazy_static;

#[derive(Parser)]
#[clap(version = VERSION, about = "XELIS: An innovate cryptocurrency with BlockDAG and Homomorphic Encryption enabling Smart Contracts")]
#[command(styles = xelis_common::get_cli_styles())]
pub struct MinerConfig {
    /// Wallet address to mine and receive block rewards on
    #[clap(short, long)]
    miner_address: Option<Address>,
    /// Daemon address to connect to for mining
    #[clap(long, default_value_t = String::from(DEFAULT_DAEMON_ADDRESS))]
    daemon_address: String,
    /// Bind address for stats API
    #[cfg(feature = "api_stats")]
    #[clap(long)]
    api_bind_address: Option<String>,
    /// Set log level
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
    /// Enable the benchmark mode with the specified algorithm
    #[clap(long)]
    benchmark: Option<Algorithm>,
    /// Iterations to run the benchmark
    #[clap(long, default_value_t = 100)]
    iterations: usize,
    /// Disable the log file
    #[clap(long)]
    disable_file_logging: bool,
    /// Disable the log filename date based
    /// If disabled, the log file will be named xelis-miner.log instead of YYYY-MM-DD.xelis-miner.log
    #[clap(long)]
    disable_file_log_date_based: bool,
    /// Disable the usage of colors in log
    #[clap(long)]
    disable_log_color: bool,
    /// Disable terminal interactive mode
    /// You will not be able to write CLI commands in it or to have an updated prompt
    #[clap(long)]
    disable_interactive_mode: bool,
    /// Log filename
    /// 
    /// By default filename is xelis-miner.log.
    /// File will be stored in logs directory, this is only the filename, not the full path.
    /// Log file is rotated every day and has the format YYYY-MM-DD.xelis-miner.log.
    #[clap(default_value_t = String::from("xelis-miner.log"))]
    filename_log: String,
    /// Logs directory
    /// 
    /// By default it will be logs/ of the current directory.
    /// It must end with a / to be a valid folder.
    #[clap(long, default_value_t = String::from("logs/"))]
    logs_path: String,
    /// Module configuration for logs
    #[clap(long)]
    logs_modules: Vec<ModuleConfig>,
    /// Numbers of threads to use (at least 1, max: 65535)
    /// By default, this will try to detect the number of threads available on your CPU.
    #[clap(short, long)]
    num_threads: Option<u16>,
    /// Worker name to be displayed on daemon side
    #[clap(short, long, default_value_t = String::from("default"))]
    worker: String,
}

#[derive(Clone)]
enum ThreadNotification<'a> {
    NewJob(Algorithm, MinerWork<'a>, Difficulty, u64), // POW algorithm, block work, difficulty, height
    WebSocketClosed, // WebSocket connection has been closed
    Exit // all threads must stop
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")] 
pub enum SocketMessage {
    NewJob(GetMinerWorkResult),
    BlockAccepted,
    BlockRejected(String)
}

static WEBSOCKET_CONNECTED: AtomicBool = AtomicBool::new(false);
static CURRENT_TOPO_HEIGHT: AtomicU64 = AtomicU64::new(0);
static BLOCKS_FOUND: AtomicUsize = AtomicUsize::new(0);
static BLOCKS_REJECTED: AtomicUsize = AtomicUsize::new(0);
static HASHRATE_COUNTER: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "api_stats")]
static HASHRATE: AtomicU64 = AtomicU64::new(0);
static JOB_ELAPSED: RwLock<Option<Instant>> = RwLock::new(None);


lazy_static! {
    static ref HASHRATE_LAST_TIME: Mutex<Instant> = Mutex::new(Instant::now());
}

// After how many iterations we update the timestamp of the block to avoid too much CPU usage 
const UPDATE_EVERY_NONCE: u64 = 10;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config: MinerConfig = MinerConfig::parse();
    let prompt = Prompt::new(config.log_level, &config.logs_path, &config.filename_log, config.disable_file_logging, config.disable_file_log_date_based, config.disable_log_color, !config.disable_interactive_mode, config.logs_modules)?;

    let detected_threads = match thread::available_parallelism() {
        Ok(value) => value.get() as u16,
        Err(e) => {
            warn!("Couldn't detect number of available threads: {}, fallback to 1 thread only", e);
            1
        }
    };

    let threads = match config.num_threads {
        Some(value) => value,
        None => detected_threads
    };


    info!("Total threads to use: {} (detected: {})", threads, detected_threads);

    if let Some(algorithm) = config.benchmark {
        info!("Benchmark mode enabled, miner will try up to {} threads", threads);
        benchmark(threads as usize, config.iterations, algorithm);
        info!("Benchmark finished");
        return Ok(())
    }

    let address = config.miner_address.ok_or_else(|| Error::msg("No miner address specified"))?;
    info!("Miner address: {}", address);    
    if threads != detected_threads {
        warn!("Attention, the number of threads used may not be optimal, recommended is: {}", detected_threads);
    }

    // broadcast channel to send new jobs / exit command to all threads
    let (sender, _) = broadcast::channel::<ThreadNotification>(threads as usize);
    // mpsc channel to send from threads to the "communication" task.
    let (block_sender, block_receiver) = mpsc::channel::<MinerWork>(threads as usize);
    for id in 0..threads {
        debug!("Starting thread #{}", id);
        if let Err(e) = start_thread(id, sender.subscribe(), block_sender.clone()) {
            error!("Error while creating Mining Thread #{}: {}", id, e);
        }
    }

    // start communication task
    let task = spawn_task("communication", communication_task(config.daemon_address, sender.clone(), block_receiver, address, config.worker));
    
    let stats_task: Option<JoinHandle<Result<()>>>;
    #[cfg(feature = "api_stats")]
    {
        // start stats task
        stats_task = match config.api_bind_address {
            Some(addr) => Some(spawn_task("broadcast", broadcast_stats_task(addr))),
            None => None,
        };
    }
    #[cfg(not(feature = "api_stats"))]
    {
        stats_task = None;
    }

    if let Err(e) = run_prompt(prompt).await {
        error!("Error on running prompt: {}", e);
    }

    // send exit command to all threads to stop
    if let Err(_) = sender.send(ThreadNotification::Exit) {
        debug!("Error while sending exit message to threads");
    }

    // stop the communication task
    task.abort();

    // stop the stats broadcast task
    if let Some(stats_handle) = stats_task {
        stats_handle.abort()
    }

    Ok(())
}

// This Tokio task will runs indefinitely until the user stops the miner himself.
// It maintains a http listener and sends stats on connection in json.
#[cfg(feature = "api_stats")]
async fn broadcast_stats_task(broadcast_address: String) -> Result<()> {
    info!("Starting broadcast task");
    loop {
        // Start TCP listener
        let listener = TcpListener::bind(broadcast_address).await?;
        loop {
            let (mut socket, _) = listener.accept().await?;

            let blocks_found = BLOCKS_FOUND.load(Ordering::SeqCst);
            let blocks_rejected = BLOCKS_REJECTED.load(Ordering::SeqCst);
            let hashrate = HASHRATE.load(Ordering::SeqCst);

            // Build JSON data
            let data = serde_json::json!({
                "accepted": blocks_found,
                "rejected": blocks_rejected,
                "hashrate": hashrate,
                "hashrate_formatted": format_hashrate(hashrate as f64),
            });

            // Build HTTP response
            let status_line = "HTTP/1.1 200 OK\r\n";
            let content_type = "Content-Type: application/json\r\n";
            let contents = data.to_string();
            let length = contents.len();
            let response = format!("{status_line}{content_type}Content-Length: {length}\r\n\r\n{contents}");

            // Send HTTP repsonse and close socket
            AsyncWriteExt::write_all(&mut socket, response.as_bytes())
                .await?;
            socket.shutdown().await?;
        }
    }
}


// Benchmark the miner with the specified number of threads and iterations
// It will output the total time, total iterations, time per PoW and hashrate for each number of threads
fn benchmark(threads: usize, iterations: usize, algorithm: Algorithm) {
    info!("{0: <10} | {1: <10} | {2: <16} | {3: <13} | {4: <13}", "Threads", "Total Time", "Total Iterations", "Time/PoW (ms)", "Hashrate");

    for bench in 1..=threads {
        let start = Instant::now();
        let mut handles = vec![];
        for _ in 0..bench {
            let job = MinerWork::new(Hash::zero(), get_current_time_in_millis());
            let mut worker = Worker::new();
            worker.set_work(job, algorithm).unwrap();

            let handle = thread::spawn(move || {
                for _ in 0..iterations {
                    let _ = worker.get_pow_hash().unwrap();
                    worker.increase_nonce().unwrap();
                }
            });
            handles.push(handle);
        }

        for handle in handles { // wait on all threads
            handle.join().unwrap();
        }
        let duration = start.elapsed().as_millis();
        let hashrate = format_hashrate(1000f64 / (duration as f64 / (bench*iterations) as f64));
        info!("{0: <10} | {1: <10} | {2: <16} | {3: <13} | {4: <13}", bench, duration, bench*iterations, duration/(bench*iterations) as u128, hashrate);
    }
}

// this Tokio task will runs indefinitely until the user stop himself the miner.
// It maintains a WebSocket connection with the daemon and notify all threads when it receive a new job.
// Its also the task who have the job to send directly the new block found by one of the threads.
// This allow mining threads to only focus on mining and receiving jobs through memory channels.
async fn communication_task(daemon_address: String, job_sender: broadcast::Sender<ThreadNotification<'_>>, mut block_receiver: mpsc::Receiver<MinerWork<'_>>, address: Address, worker: String) {
    info!("Starting communication task");
    let daemon_address = sanitize_daemon_address(&daemon_address);
    'main: loop {
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
                if let TungsteniteError::Http(e) = e {
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
                    debug!("Received message from daemon: {:?}", message);
                    match handle_websocket_message(message, &job_sender).await {
                        Ok(exit) => {
                            if exit {
                                debug!("Exiting communication task");
                                break;
                            }
                        },
                        Err(e) => {
                            error!("Error while handling message from WebSocket: {}", e);
                            break;
                        }
                    }
                },
                Some(work) = block_receiver.recv() => { // send all valid blocks found to the daemon
                    info!("submitting new block found...");
                    let submit = serde_json::json!(SubmitMinerWorkParams { miner_work: work.to_hex() }).to_string();
                    if let Err(e) = write.send(Message::Text(submit)).await {
                        error!("Error while sending the block found to the daemon: {}", e);
                        break;
                    }
                    debug!("Block found has been sent to daemon");
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

async fn handle_websocket_message(message: Result<Message, TungsteniteError>, job_sender: &broadcast::Sender<ThreadNotification<'_>>) -> Result<bool, Error> {
    match message? {
        Message::Text(text) => {
            debug!("new message from daemon: {}", text);
            match serde_json::from_slice::<SocketMessage>(text.as_bytes())? {
                SocketMessage::NewJob(job) => {
                    info!("New job received: difficulty {} at height {}", format_difficulty(job.difficulty), job.height);
                    let block = MinerWork::from_hex(job.miner_work).context("Error while decoding new job received from daemon")?;
                    CURRENT_TOPO_HEIGHT.store(job.topoheight, Ordering::SeqCst);
                    JOB_ELAPSED.write().unwrap().replace(Instant::now());

                    if let Err(e) = job_sender.send(ThreadNotification::NewJob(job.algorithm, block, job.difficulty, job.height)) {
                        error!("Error while sending new job to threads: {}", e);
                    }
                },
                SocketMessage::BlockAccepted => {
                    BLOCKS_FOUND.fetch_add(1, Ordering::SeqCst);
                    info!("Block submitted has been accepted by network !");
                },
                SocketMessage::BlockRejected(err) => {
                    BLOCKS_REJECTED.fetch_add(1, Ordering::SeqCst);
                    error!("Block submitted has been rejected by network: {}", err);
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

fn start_thread(id: u16, mut job_receiver: broadcast::Receiver<ThreadNotification<'static>>, block_sender: mpsc::Sender<MinerWork<'static>>) -> Result<(), Error> {
    let builder = thread::Builder::new().name(format!("Mining Thread #{}", id));
    builder.spawn(move || {
        let mut worker = Worker::new();
        let mut hash: Hash;

        info!("Mining Thread #{}: started", id);
        'main: loop {
            let message = match job_receiver.blocking_recv() {
                Ok(message) => message,
                Err(e) => {
                    error!("Error on thread #{} while waiting on new job: {}", id, e);
                    // Channel is maybe lagging, try to empty it
                    while job_receiver.len() > 1 {
                        let _ = job_receiver.blocking_recv();
                    }
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
                ThreadNotification::NewJob(algorithm, mut new_job, expected_difficulty, height) => {
                    debug!("Mining Thread #{} received a new job", id);
                    // set thread id in extra nonce for more work spread between threads
                    // u16 support up to 65535 threads
                    new_job.set_thread_id_u16(id);
                    let initial_timestamp = new_job.get_timestamp();
                    worker.set_work(new_job, algorithm).unwrap();

                    let difficulty_target = match compute_difficulty_target(&expected_difficulty) {
                        Ok(value) => value,
                        Err(e) => {
                            error!("Mining Thread #{}: error on difficulty target computation: {}", id, e);
                            continue 'main;
                        }
                    };

                    // Solve block
                    hash = worker.get_pow_hash().unwrap();
                    let mut tries = 0;
                    while !check_difficulty_against_target(&hash, &difficulty_target) {
                        worker.increase_nonce().unwrap();
                        // check if we have a new job pending
                        // Only update every N iterations to avoid too much CPU usage
                        if tries % UPDATE_EVERY_NONCE == 0 {
                            if !job_receiver.is_empty() {
                                continue 'main;
                            }
                            if let Ok(instant) = JOB_ELAPSED.read() {
                                if let Some(instant) = instant.as_ref() {
                                    worker.set_timestamp(initial_timestamp + instant.elapsed().as_millis() as u64).unwrap();
                                }
                            }
                            HASHRATE_COUNTER.fetch_add(UPDATE_EVERY_NONCE as usize, Ordering::SeqCst);
                        }

                        hash = worker.get_pow_hash().unwrap();
                        tries += 1;
                    }

                    // compute the reference hash for easier finding of the block
                    let block_hash = worker.get_block_hash().unwrap();
                    info!("Thread #{}: block {} found at height {} with difficulty {}", id, block_hash, height, format_difficulty(difficulty_from_hash(&hash)));

                    let job = worker.take_work().unwrap();
                    if let Err(_) = block_sender.blocking_send(job) {
                        error!("Mining Thread #{}: error while sending block found with hash {}", id, block_hash);
                        continue 'main;
                    }
                    debug!("Job sent to communication task");
                }
            };
        }
        info!("Mining Thread #{}: stopped", id);
    })?;
    Ok(())
}

async fn run_prompt(prompt: ShareablePrompt) -> Result<()> {
    let command_manager = CommandManager::new(prompt.clone());
    command_manager.register_default_commands()?;

    let closure = |_: &_, _: _| async {
        let topoheight_str = format!(
            "{}: {}",
            prompt.colorize_str(Color::Yellow, "TopoHeight"),
            prompt.colorize_string(Color::Green, &format!("{}", CURRENT_TOPO_HEIGHT.load(Ordering::SeqCst))),
        );
        let blocks_found = format!(
            "{}: {}",
            prompt.colorize_str(Color::Yellow, "Accepted"),
            prompt.colorize_string(Color::Green, &format!("{}", BLOCKS_FOUND.load(Ordering::SeqCst))),
        );
        let blocks_rejected = format!(
            "{}: {}",
            prompt.colorize_str(Color::Yellow, "Rejected"),
            prompt.colorize_string(Color::Green, &format!("{}", BLOCKS_REJECTED.load(Ordering::SeqCst))),
        );
        let status = if WEBSOCKET_CONNECTED.load(Ordering::SeqCst) {
            prompt.colorize_str(Color::Green, "Online")
        } else {
            prompt.colorize_str(Color::Red, "Offline")
        };
        let hashrate = {
            let mut last_time = HASHRATE_LAST_TIME.lock().await;
            let counter = HASHRATE_COUNTER.swap(0, Ordering::SeqCst);

            let hashrate = 1000f64 / (last_time.elapsed().as_millis() as f64 / counter as f64);
            *last_time = Instant::now();

            #[cfg(feature = "api_stats")]
            HASHRATE.store(hashrate as u64, Ordering::SeqCst);

            prompt.colorize_string(Color::Green, &format!("{}", format_hashrate(hashrate)))
        };

        Ok(
            format!(
                "{} | {} | {} | {} | {} | {} {} ",
                prompt.colorize_str(Color::Blue, "XELIS Miner"),
                topoheight_str,
                blocks_found,
                blocks_rejected,
                hashrate,
                status,
                prompt.colorize_str(Color::BrightBlack, ">>")
            )
        )
    };

    prompt.start(Duration::from_millis(1000), Box::new(async_handler!(closure)), Some(&command_manager)).await?;
    Ok(())
}