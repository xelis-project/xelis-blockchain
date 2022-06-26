use crate::crypto::{hash::{Hash, Hashable}, key::PublicKey};
use super::message::{Message, MessageReply, MessageData};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("No channel opened for this account sender")]
    NoChannelOpened, // TODO check from storage
    #[error("Channel for is already used")]
    ChannelAlreadyUsed,
    #[error("Message is already stored")]
    MessageAlreadyStored,
    #[error("Invalid message")]
    InvalidMessage
}

pub struct MData {
    message: Vec<u8>,
    receiver: PublicKey,
    sender: PublicKey,
    height: u64, // build at height
    reply: bool
}

pub struct XPool {
    messages: HashMap<Hash, Message>,
    replies: HashMap<Hash, MessageReply>
}

impl XPool {
    pub fn new() -> Self {
        Self {
            messages: HashMap::new(),
            replies: HashMap::new()
        }
    }

    pub fn has_message(&self, sender: &PublicKey) -> bool {
        self.messages.values().find(|v| {
            *v.get_sender() == *sender
        }).is_some()
    }

    // TODO: verify message size, verify from chain the channel subscription
    pub fn add_message(&mut self, message: Message) -> Result<(), MessageError> {
        let hash = message.hash();
        if self.messages.contains_key(&hash) {
            return Err(MessageError::MessageAlreadyStored)
        }

        if self.has_message(message.get_sender()) {
            return Err(MessageError::ChannelAlreadyUsed)
        }

        match message.get_signature() {
            Some(signature) => {
                if !message.get_sender().verify_signature(&hash, signature) {
                    return Err(MessageError::InvalidMessage)
                }
            },
            None => return Err(MessageError::InvalidMessage)
        };

        self.messages.insert(hash, message);
        Ok(())
    }

    // returns all messages available for a specific account key
    pub fn get_messages_for(&self, key: &PublicKey) -> Vec<&dyn MessageData> {
        let messages: Vec<&dyn MessageData> = self.messages.values().filter(|v| {
            *v.get_receiver() == *key
        }).map(|v| v as &dyn MessageData).collect();
        messages
    }
}