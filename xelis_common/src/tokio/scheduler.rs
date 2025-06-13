use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    task::{Context, Poll}
};
use futures::Stream;
use pin_project_lite::pin_project;

enum State<F: Future> {
    Pending(Pin<Box<F>>),
    Ready(F::Output),
}

pin_project! {
    pub struct Scheduler<F: Future> {
        states: VecDeque<State<F>>,
        max: Option<usize>
    }
}

impl<F: Future> Scheduler<F> {
    pub fn new(max: impl Into<Option<usize>>) -> Self {
        Self {
            states: VecDeque::new(),
            max: max.into(),
        }
    }

    pub fn push_back(&mut self, future: F) {
        self.states.push_back(State::Pending(Box::pin(future)));
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.back().is_none()
    }
}

impl<F: Future> Stream for Scheduler<F> {
    type Item = F::Output;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let max = self.max;
        let this = self.project();
        let len = this.states.len();

        if len == 0 {
            return Poll::Ready(None);
        }

        // Poll all pending futures starting from next_yield
        for state in this.states.iter_mut().take(max.unwrap_or(len)) {
            if let State::Pending(fut) = state {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(output) => {
                        *state = State::Ready(output);
                    }
                    Poll::Pending => {}
                }
            }
        }

        // Check if next_yield future is ready to yield
        if let Some(state) = this.states.front() {
            if matches!(state, State::Ready(_)) {
                if let Some(State::Ready(output)) = this.states.pop_front() {
                    return Poll::Ready(Some(output));
                }
            }
        } else {
            return Poll::Ready(None);
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::StreamExt;
    use tokio::time::sleep;
    use super::*;

    #[tokio::test]
    async fn test_scheduler() {
        let mut scheduler = Scheduler::new(1);

        async fn foo(duration: Duration, msg: &'static str) -> &'static str {
            sleep(duration).await;
            msg
        }

        scheduler.push_back(foo(Duration::from_secs(1), "first result"));
        scheduler.push_back(foo(Duration::from_secs(0), "second result"));

        assert_eq!(scheduler.next().await, Some("first result"));
        assert_eq!(scheduler.next().await, Some("second result"));
        assert_eq!(scheduler.next().await, None);
    }
}