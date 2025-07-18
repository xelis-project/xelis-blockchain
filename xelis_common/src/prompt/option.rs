use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll}
};
use crate::tokio::sync::mpsc::UnboundedReceiver;

pub struct OptionReader {
    reader: Option<UnboundedReceiver<String>>
}

impl OptionReader {
    pub fn new(reader: Option<UnboundedReceiver<String>>) -> Self {
        Self {
            reader
        }
    }
}

impl Future for OptionReader {
    type Output = Option<String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.reader.as_mut() {
            Some(reader) => {
                match Pin::new(reader).poll_recv(cx) {
                    Poll::Ready(Some(value)) => Poll::Ready(Some(value)),
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending
                }
            },
            None => Poll::Ready(None)
        }
    }
}
