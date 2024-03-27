use std::mem;

use indexmap::IndexSet;

pub struct Terminal {
    // all commands used during its running time
    history: IndexSet<String>,
    // Index when navigating in the history
    history_index: Option<usize>,
    // Current index of the cursor
    cursor_index: usize,
    // Current buffer of user input
    buffer: String,
    buffer_only: bool
}

impl Terminal {
    pub fn new() -> Self {
        Self {
            history: IndexSet::new(),
            history_index: None,
            cursor_index: 0,
            buffer: String::new(),
            buffer_only: false
        }
    }

    // This will only allow to write and delete, no history
    pub fn enable_buffer_mode(&mut self) {
        self.buffer_only = true;
    }

    // Disable the write/delete mode
    pub fn disable_buffer_mode(&mut self) {
        self.buffer_only = false;
    }

    // Search in history and replace user buffer with it
    pub fn history_up(&mut self) {
        if let Some(index) = self.history_index {
            // We are already searching in the history, keep checking
            if index + 1 < self.history.len() {
                let history_index = index + 1;
                self.history_index = Some(history_index);
                self.buffer = self.history.get_index(history_index).cloned().unwrap();
            }
        } else {
            if !self.history.is_empty() {
                self.history_index = Some(0);
                self.buffer = self.history.get_index(0).cloned().unwrap();
            }
        }
    }

    // Go down of the history
    pub fn history_down(&mut self) {
        if let Some(index) = self.history_index {
            if index == 0 {
                self.history_index = None;
            }
        }
    }

    // advance by one if possible the cursor
    pub fn next_cursor(&mut self) {
        let next = self.buffer.len() > self.cursor_index;
        if next {
            self.cursor_index += 1;
        }
    }

    // Find the next word available
    pub fn next_word_cursor(&mut self) {
        if self.buffer.is_empty() {
            return;
        }

        let buffer = &self.buffer[0..self.cursor_index];
        if let Some(index) = buffer.find(|c: char| c.is_whitespace()) {
            self.cursor_index = index;
        }
    }

    // Go back with cursor
    pub fn previous_cursor(&mut self) -> bool {
        let not_zero = self.cursor_index > 0;
        if not_zero {
            self.cursor_index -= 1;
        }
        not_zero
    }

    // Delete a char at cursor index if buffer is not empty
    pub fn delete_char(&mut self) -> bool {
        if self.buffer.is_empty() {
            return false;
        }
        self.history_index = None;
        self.buffer.remove(self.cursor_index);
        if self.cursor_index != 0 {
            self.cursor_index -= 1;
        }

        true
    }

    // Add a new character to the user input buffer
    pub fn push_char(&mut self, c: char) {
        self.history_index = None;
        self.buffer.insert(self.cursor_index, c);
        self.cursor_index += 1;
    }

    // Append a string to the buffer
    pub fn push_str(&mut self, str: &String) {
        self.buffer += str;
    }

    // Reset the user buffer, update cursor, add it in history
    // and returns it
    pub fn clear(&mut self, history: bool) -> String {
        let mut buffer = String::new();
        mem::swap(&mut buffer, &mut self.buffer);

        self.cursor_index = 0;

        if history {
            self.history_index = None;
            self.history.insert(buffer.clone());
        }

        buffer
    }

    // Get current buffer of user input
    pub fn get_buffer(&self) -> &String {
        &self.buffer
    }

    // Set a new buffer
    pub fn set_buffer(&mut self, buffer: String) {
        self.buffer = buffer;
    }
}