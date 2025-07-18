use std::{
    collections::VecDeque,
    fmt,
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

impl<F: Future> fmt::Debug for State<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::New(opt) => write!(f, "State::New({})", opt.is_some()),
            Self::Pending(_) => write!(f, "State::Pending"),
            Self::Ready(_) => write!(f, "State::Ready"),
        }
    }
}

pin_project! {
    pub struct Scheduler<F: Future> {
        states: VecDeque<State<F>>,
        n: Option<usize>
    }
}

impl<F: Future> Scheduler<F> {
    pub fn new(n: impl Into<Option<usize>>) -> Self {
        Self {
            states: VecDeque::new(),
            n: n.into(),
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
        self.states.iter()
            .filter(|v| matches!(v, State::Ready(_)))
            .count()
    }

    pub fn set_n(&mut self, n: impl Into<Option<usize>>) {
        self.n = n.into();
    }

    pub fn get_n(&self) -> Option<usize> {
        self.n
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

        // Poll all pending futures until the limit set
        for state in this.states.iter_mut().take(n.unwrap_or(len)) {
            match state {
                State::New(fut) => {
                    let mut fut = fut.take()
                        .expect("new future available");

                    // Try poll it, if its already ready, just mark it has such
                    // otherwise, we mark it has pending
                    if let Poll::Ready(output) = fut.as_mut().poll(cx) {
                        *state = State::Ready(output);
                    } else {
                        // Mark it has polled
                        *state = State::Pending(fut);
                    }
                },
                State::Pending(fut) => {
                    if let Poll::Ready(output) = fut.as_mut().poll(cx) {
                        *state = State::Ready(output);
                    }
                },
                State::Ready(_) => {}
            }
        }

        // Check if our next future is ready to yield
        if let Some(state) = this.states.front() {
            if matches!(state, State::Ready(_)) {
                if let Some(State::Ready(output)) = this.states.pop_front() {
                    return Poll::Ready(Some(output));
                }
            }
        } else {
            // no more future available
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

        // Poll it
        scheduler.next().await;

        // Ensure ALL remaining futures were polled
        assert!(scheduler.states.iter().all(|v| !matches!(v, State::New(_))));
    }
}