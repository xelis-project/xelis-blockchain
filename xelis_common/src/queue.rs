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
    // Returns true if the element was added, false if it already exists
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

    // Returns true if key is presents in the queue
    pub fn has(&self, key: &K) -> bool {
        self.keys.contains(key)
    }

    // Removes and returns the element for the given key
    pub fn remove(&mut self, key: &K) -> Option<(K, V)> {
        let index = self.order.iter().position(|(k, _)| *k.as_ref() == *key)?;
        let (key, value) = self.order.remove(index)?;
        self.keys.remove(&key);

        let key = Arc::try_unwrap(key).expect("Failed to unwrap Arc");
        Some((key, value))
    }

    // Gets a reference to the element with the given key
    pub fn get(&self, key: &K) -> Option<&V> {
        self.keys.get(key).and_then(|key| {
            self.order.iter().find(|(k, _)| Arc::ptr_eq(k, key)).map(|(_, v)| v)
        })
    }

    // Gets a mutable reference to the element with the given key
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.keys.get(key).and_then(|key| {
            self.order.iter_mut().find(|(k, _)| Arc::ptr_eq(k, key)).map(|(_, v)| v)
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

    // Returns true if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    // Clears the queue
    pub fn clear(&mut self) {
        self.keys.clear();
        self.order.clear();
    }

    // Returns an iterator over the elements in the queue
    pub fn iter(&self) -> impl Iterator<Item = &(Arc<K>, V)> {
        self.order.iter()
    }

    // Returns an iterator over the elements in the queue
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut (Arc<K>, V)> {
        self.order.iter_mut()
    }

    // Returns an iterator over the keys in the queue
    pub fn keys(&self) -> impl Iterator<Item = &Arc<K>> {
        self.keys.iter()
    }

    // Returns an iterator over the values in the queue
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.order.iter().map(|(_, v)| v)
    }

    // Returns an iterator over the values in the queue
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.order.iter_mut().map(|(_, v)| v)
    }

    // Delete from queue and returns deleted elements
    pub fn extract_if<'a, F: 'a + FnMut((&Arc<K>, &V)) -> bool>(&'a mut self, mut f: F) -> impl Iterator<Item = (Arc<K>, V)> + 'a {
        let mut tmp = VecDeque::with_capacity(self.order.capacity());
        std::mem::swap(&mut self.order, &mut tmp);
        tmp.into_iter().filter_map(move |(k, v)| {
            if f((&k, &v)) {
                self.keys.remove(&k);
                Some((k, v))
            } else {
                self.order.push_back((k, v));
                None
            }
        })
    }
}