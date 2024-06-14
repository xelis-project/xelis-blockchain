use std::{
    future::Future, pin::Pin, sync::Arc
};

use log::debug;
use super::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
    spawn_task
};

type Job = Pin<Box<dyn Future<Output = ()> + Send>>;

pub struct ThreadPool {
    sender: mpsc::Sender<Job>,
    workers: Vec<Worker>,
}

impl ThreadPool {
    pub fn new(size: usize) -> Self {
        let (sender, receiver) = mpsc::channel(size);

        let shared_receiver = Arc::new(Mutex::new(receiver));
        let workers = (0..size)
            .map(|id| Worker::new(id, shared_receiver.clone()))
            .collect();

        Self { sender, workers }
    }

    pub fn tasks_count(&self) -> usize {
        self.workers.len()
    }

    pub async fn execute<F>(&self, future: F) -> Result<(), mpsc::error::SendError<Job>>
    where
        F: Future<Output = ()> + Send + 'static,
        F::Output: Send + 'static,
    {
        let job = Box::pin(future);
        self.sender.send(job).await
    }

    pub fn stop(&mut self) {
        for worker in self.workers.drain(..) {
            debug!("Stopping worker {}", worker.id);
            worker.handle.abort();
        }
    }
}

struct Worker {
    id: usize,
    handle: JoinHandle<()>
}

impl Worker {
    pub fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Job>>>) -> Self {
        let handle = spawn_task(format!("thread-pool-#{}", id), async move {
            debug!("Worker {} started", id);
            loop {
                let job = {
                    let mut receiver = receiver.lock().await;
                    receiver.recv().await
                };

                if let Some(job) = job {
                    job.await;
                } else {
                    break;
                }
            }
        });

        Self { id, handle }
    }
}