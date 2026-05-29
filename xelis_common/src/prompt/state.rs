use std::{
    collections::VecDeque,
    io::{stdout, Write},
    sync::{
        atomic::{
            AtomicBool,
            AtomicU16,
            AtomicUsize,
            Ordering
        },
        Arc,
        Mutex
    }
};
use crossterm::{
    event::{
        self,
        Event,
        KeyCode,
        KeyEventKind,
        KeyModifiers
    },
    terminal
};
use regex::Regex;
use log::{debug, error, info};
use crate::tokio::sync::{mpsc::UnboundedSender, oneshot};

use super::PromptError;


// State used to be shared between stdin thread and Prompt instance
pub struct State {
    prompt: Mutex<Option<String>>,
    exit_channel: Mutex<Option<oneshot::Sender<()>>>,
    width: AtomicU16,
    previous_prompt_line: AtomicUsize,
    user_input: Mutex<String>,
    mask_input: AtomicBool,
    prompt_sender: Mutex<Option<oneshot::Sender<String>>>,
    exit: AtomicBool,
    ascii_escape_regex: Regex,
    last_rendered_key: Mutex<String>,
    dirty: AtomicBool,
    interactive: bool
}

impl State {
    pub fn new(allow_interactive: bool) -> Self {
        // enable the raw mode for terminal
        // so we can read each event/action
        let interactive = if allow_interactive { !terminal::enable_raw_mode().is_err() } else { false };

        Self {
            prompt: Mutex::new(None),
            exit_channel: Mutex::new(None),
            width: AtomicU16::new(terminal::size().unwrap_or((80, 0)).0),
            previous_prompt_line: AtomicUsize::new(0),
            user_input: Mutex::new(String::new()),
            mask_input: AtomicBool::new(false),
            prompt_sender: Mutex::new(None),
            exit: AtomicBool::new(false),
            ascii_escape_regex: Regex::new("\x1B\\[[0-9;]*[A-Za-z]").unwrap(),
            last_rendered_key: Mutex::new(String::new()),
            dirty: AtomicBool::new(false),
            interactive
        }
    }

    pub fn exit(&self) -> &AtomicBool {
        &self.exit
    }

    pub fn get_prompt(&self) -> &Mutex<Option<String>> {
        &self.prompt
    }

    pub fn get_prompt_sender(&self) -> &Mutex<Option<oneshot::Sender<String>>> {
        &self.prompt_sender
    }

    pub fn get_user_input(&self) -> &Mutex<String> {
        &self.user_input
    }

    pub fn get_ascii_escape_regex(&self) -> &Regex {
        &self.ascii_escape_regex
    }

    pub fn get_mask_input(&self) -> &AtomicBool {
        &self.mask_input
    }

    pub fn set_exit_channel(&self, sender: oneshot::Sender<()>) -> Result<(), PromptError> {
        let mut exit = self.exit_channel.lock()?;
        if exit.is_some() {
            return Err(PromptError::AlreadyRunning)
        }
        *exit = Some(sender);
        Ok(())
    }

    pub fn stop(&self) -> Result<(), PromptError> {
        let mut exit = self.exit_channel.lock()?;
        let sender = exit.take().ok_or(PromptError::NotRunning)?;

        if sender.send(()).is_err() {
            error!("Error while sending exit signal");
        }

        Ok(())
    }

    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::SeqCst);
    }

    pub fn ioloop(self: &Arc<Self>, sender: UnboundedSender<String>) -> Result<(), PromptError> {
        debug!("ioloop started");

        // all the history of commands
        let mut history: VecDeque<String> = VecDeque::new();
        // current index in history in case we use arrows to move in history
        let mut history_index = 0;
        let mut is_in_history = false;
        loop {
            if !is_in_history {
                history_index = 0;
            }

            match event::read() {
                Ok(event) => {
                    match event {
                        Event::Resize(width, _) => {
                            self.width.store(width, Ordering::SeqCst);
                            self.show()?;
                        }
                        Event::Paste(s) => {
                            is_in_history = false;
                            let mut buffer = self.user_input.lock()?;
                            buffer.push_str(&s);
                        }
                        Event::Key(key) => {
                            // Windows bug - https://github.com/crossterm-rs/crossterm/issues/772
                            if key.kind != KeyEventKind::Press {
                                continue;
                            }

                            match key.code {
                                KeyCode::Up => {
                                    let mut buffer = self.user_input.lock()?;
                                    if buffer.is_empty() {
                                        is_in_history = true;
                                    }

                                    if is_in_history {
                                        if history_index < history.len() {
                                            buffer.clear();
                                            buffer.push_str(&history[history_index]);
                                            self.show_input(&buffer)?;
                                            if history_index + 1 < history.len() {
                                                history_index += 1;
                                            }
                                        }
                                    }
                                },
                                KeyCode::Down => {
                                    if is_in_history {
                                        let mut buffer = self.user_input.lock()?;
                                        buffer.clear();
                                        if history_index > 0 {
                                            history_index -= 1;
                                            if history_index < history.len() {
                                                buffer.push_str(&history[history_index]);
                                            }
                                        } else {
                                            is_in_history = false;
                                        }
                                        self.show_input(&buffer)?;
                                    }
                                },
                                KeyCode::Char(c) => {
                                    is_in_history = false;
                                    // handle CTRL+C
                                    if key.modifiers == KeyModifiers::CONTROL && c == 'c' {
                                        break;
                                    }

                                    let mut buffer = self.user_input.lock()?;
                                    buffer.push(c);
                                    self.show_input(&buffer)?;
                                },
                                KeyCode::Backspace => {
                                    is_in_history = false;
                                    let mut buffer = self.user_input.lock()?;
                                    buffer.pop();

                                    self.show_input(&buffer)?;
                                },
                                KeyCode::Enter => {
                                    is_in_history = false;
                                    let mut buffer = self.user_input.lock()?;

                                    // clone the buffer to send it to the command handler
                                    let cloned_buffer = buffer.clone();
                                    buffer.clear();
                                    self.show_input(&buffer)?;

                                    // Save in history & Send the message
                                    let mut prompt_sender = self.prompt_sender.lock()?;
                                    if let Some(sender) = prompt_sender.take() {
                                        if let Err(e) = sender.send(cloned_buffer) {
                                            error!("Error while sending to reader: {}", e);
                                            break;
                                        }
                                    } else {
                                        if !cloned_buffer.is_empty() {
                                            history.push_front(cloned_buffer.clone());
                                            if let Err(e) = sender.send(cloned_buffer) {
                                                error!("Error while sending input to command handler: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                },
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                },
                Err(e) => {
                    error!("Error while reading input: {}", e);
                    break;
                }
            };
        }

        if !self.exit.swap(true, Ordering::SeqCst) {
            if self.is_interactive() {
                if let Err(e) = terminal::disable_raw_mode() {
                    error!("Error while disabling raw mode: {}", e);
                }
            }
        }

        info!("ioloop thread is now stopped");

        // Send an empty message to the reader to unblock it
        let mut sender = self.prompt_sender.lock()?;
        if let Some(sender) = sender.take() {
            if let Err(e) = sender.send(String::new()) {
                error!("Error while sending input to reader in ioloop: {}", e);
            }
        }

        self.stop()
    }

    pub fn should_mask_input(&self) -> bool {
        self.mask_input.load(Ordering::SeqCst)
    }

    pub fn count_lines(&self, value: &str) -> usize {
        let width = self.width.load(Ordering::SeqCst);

        let mut lines = 0;
        let mut current_line_width = 0;
        let input = self.ascii_escape_regex.replace_all(value, "");

        for c in input.chars() {
            if c == '\n' || current_line_width >= width {
                lines += 1;
                current_line_width = 0;
            } else {
                current_line_width += 1;
            }
        }

        if current_line_width > 0 {
            lines += 1;
        }

        lines
    }

    pub fn show_with_prompt_and_input(&self, prompt: &str, input: &str) -> Result<(), PromptError> {
        // if not interactive, we don't need to show anything
        if !self.is_interactive() {
            return Ok(())
        }

        let width = self.width.load(Ordering::SeqCst);
        let rendered_input = if self.should_mask_input() {
            "*".repeat(input.len())
        } else {
            input.to_string()
        };
        let rendered_key = format!("{}|{}|{}", width, prompt, rendered_input);
        let force_render = self.dirty.swap(false, Ordering::SeqCst);
        {
            let mut last = self.last_rendered_key.lock()?;
            if !force_render && *last == rendered_key {
                return Ok(());
            }
            *last = rendered_key;
        }

        let current_count = self.count_lines(&format!("\r{}{}", prompt, input));
        let previous_count = self.previous_prompt_line.swap(current_count, Ordering::SeqCst);

        // > 1 because prompt line is already counted below
        if previous_count > 1 {
            print!("\x1B[{}A\x1B[J", previous_count - 1);
        }

        if self.should_mask_input() {
            print!("\r\x1B[2K{}{}", prompt, "*".repeat(input.len()));
        } else {
            print!("\r\x1B[2K{}{}", prompt, input);
        }

        stdout().flush()?;
        Ok(())
    }

    pub fn show_input(&self, input: &str) -> Result<(), PromptError> {
        let default_value = String::with_capacity(0);
        let lock = self.prompt.lock()?;
        let prompt = lock.as_ref().unwrap_or(&default_value);
        self.show_with_prompt_and_input(prompt, input)
    }

    pub fn show(&self) -> Result<(), PromptError> {
        let input = self.user_input.lock()?;
        self.show_input(&input)
    }
}
