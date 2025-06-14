use std::{collections::VecDeque, future::Future, pin::Pin, task::{Context, Poll}};

use futures::Stream;
use pin_project_lite::pin_project;

pin_project! {
    pub struct Executor<F: Future> {
        futures: VecDeque<Pin<Box<F>>>
    }
}

impl<F: Future> Executor<F> {
    pub fn new() -> Self {
        Self {
            futures: VecDeque::new()
        }
    }

    pub fn push_front(&mut self, future: F) {
        self.futures.push_front(Box::pin(future));
    }

    pub fn push_back(&mut self, future: F) {
        self.futures.push_back(Box::pin(future));
    }

    pub fn len(&self) -> usize {
        self.futures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.futures.is_empty()
    }
}

impl<F: Future> Stream for Executor<F> {
    type Item = F::Output;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        if let Some(fut) = this.futures.front_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(output) => {
                    this.futures.pop_front();
                    Poll::Ready(Some(output))
                },
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(None)
        }
    }
}