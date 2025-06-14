use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    task::{Context, Poll}
};
use futures::Stream;
use pin_project_lite::pin_project;

enum State<F: Future> {
    // New, not yet polled
    New(Option<Pin<Box<F>>>),
    // Polled future
    Pending(Pin<Box<F>>),
    // Completed future
    Ready(F::Output),
}

pin_project! {
    pub struct Scheduler<F: Future> {
        states: VecDeque<State<F>>,
        n: Option<usize>,
        next_yield: usize,
    }
}

impl<F: Future> Scheduler<F> {
    pub fn new(n: impl Into<Option<usize>>) -> Self {
        Self {
            states: VecDeque::new(),
            n: n.into(),
            next_yield: 0,
        }
    }

    pub fn push_front(&mut self, future: F) {
        self.states.push_front(State::New(Some(Box::pin(future))));
    }

    pub fn push_back(&mut self, future: F) {
        self.states.push_back(State::New(Some(Box::pin(future))));
    }

    // Current len of futures available (pending & ready)
    pub fn len(&self) -> usize {
        self.states.len()
    }

    // Do we have any future left
    pub fn is_empty(&self) -> bool {
        self.states.back().is_none()
    }

    // How many futures are ready to be polled
    pub fn ready(&self) -> usize {
        self.next_yield
    }

    pub fn set_n(&mut self, n: impl Into<Option<usize>>) {
        self.n = n.into();
    }

    // Do nothing if n was set to None
    pub fn increment_n(&mut self) {
        if let Some(n) = self.n.as_mut() {
            *n += 1;
        }
    }

    // Do nothing if n was set to None
    pub fn decrement_n(&mut self) {
        if let Some(n) = self.n.as_mut() {
            *n -= 1;
        }
    }
}

impl<F: Future> Stream for Scheduler<F> {
    type Item = F::Output;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let n = self.n;
        let this = self.project();
        let len = this.states.len();

        if len == 0 || n.is_some_and(|v| v == 0) {
            return Poll::Ready(None);
        }

        // Poll all pending futures starting from next_yield
        // until the limit set
        let mut first = true;
        for state in this.states.iter_mut().take(n.unwrap_or(len)).skip(*this.next_yield) {
            if let State::New(fut) = state {
                // Mark it has polled
                *state = State::Pending(fut.take().expect("new future available"));
            }

            if let State::Pending(fut) = state {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(output) => {
                        *state = State::Ready(output);
                        if first {
                            // next yield increase
                            *this.next_yield += 1;
                        }
                    }
                    Poll::Pending => {
                        first = false;
                    }
                }
            }
        }

        // Check if next_yield future is ready to yield
        if let Some(state) = this.states.front() {
            if matches!(state, State::Ready(_)) {
                if let Some(State::Ready(output)) = this.states.pop_front() {
                    *this.next_yield -= 1;
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

        // If we don't have any capacity left
        // it will return None
        scheduler.push_back(foo(Duration::from_secs(0), "third result"));
        scheduler.push_back(foo(Duration::from_secs(0), "fourth result"));
        scheduler.push_back(foo(Duration::from_secs(0), "last result"));

        scheduler.decrement_n();
        assert_eq!(scheduler.next().await, None);

        // Ensure none of them were not polled
        assert!(scheduler.states.iter().all(|v| matches!(v, State::New(_))));

        // But if we increase it back, we can get our result again
        scheduler.increment_n();
        assert_eq!(scheduler.next().await, Some("third result"));

        scheduler.set_n(None);
        // Ensure ALL remaining futures were polled
        assert!(scheduler.states.iter().all(|v| matches!(v, State::Pending(_))));
    }
}