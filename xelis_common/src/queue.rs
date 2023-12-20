use std::{hash::Hash, collections::{VecDeque, HashSet}, fmt::Debug, sync::Arc};

// A queue that allows for O(1) lookup of elements
// The queue is backed by a VecDeque and a HashSet
// The HashSet is used to check if an element is already in the queue
// The VecDeque is used to keep track of the order of the elements
// This can be shared between threads
pub struct Queue<K: Hash + Eq + Debug, V> {
    keys: HashSet<Arc<K>>,
    order: VecDeque<(Arc<K>, V)>
}

impl<K: Hash + Eq + Debug, V> Queue<K, V> {
    pub fn new() -> Self {
        Self {
            keys: HashSet::new(),
            order: VecDeque::new()
        }
    }

    // Pushes a new element to the back of the queue
    pub fn push(&mut self, key: K, value: V) -> bool {
        if self.keys.contains(&key) {
            return false;
        }

        let key = Arc::new(key);
        self.keys.insert(key.clone());
        self.order.push_back((key, value));

        true
    }

    // Removes and returns the first element
    pub fn pop(&mut self) -> Option<(K, V)> {
        let (key, value) = self.order.pop_front()?;
        self.keys.remove(&key);

        let key = Arc::try_unwrap(key).expect("Failed to unwrap Arc");
        Some((key, value))
    }

    // Removes and returns the first element
    pub fn get(&self, key: &K) -> Option<&V> {
        self.keys.get(key).and_then(|key| {
            self.order.iter().find(|(k, _)| Arc::ptr_eq(k, key)).map(|(_, v)| v)
        })
    }

    // Returns a reference to the element at the given index
    pub fn get_index(&self, index: usize) -> Option<&(Arc<K>, V)> {
        self.order.get(index)
    }

    // Returns a reference to the first element
    pub fn peek(&self) -> Option<&(Arc<K>, V)> {
        self.order.front()
    }

    // Returns a mutable reference to the first element
    pub fn peek_mut(&mut self) -> Option<&mut (Arc<K>, V)> {
        self.order.front_mut()
    }

    // Returns current size of the queue
    pub fn len(&self) -> usize {
        self.order.len()
    }
}