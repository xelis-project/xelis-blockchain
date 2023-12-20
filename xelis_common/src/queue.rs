use std::{rc::Rc, hash::Hash, collections::{VecDeque, HashSet}};

pub struct Queue<K: Hash + Eq, V> {
    keys: HashSet<Rc<K>>,
    order: VecDeque<(Rc<K>, V)>
}

impl<K: Hash + Eq, V> Queue<K, V> {
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

        let key = Rc::new(key);
        self.keys.insert(key.clone());
        self.order.push_back((key, value));

        true
    }

    // Removes and returns the first element
    pub fn pop(&mut self) -> Option<(Rc<K>, V)> {
        let (key, value) = self.order.pop_front()?;
        self.keys.remove(&key);

        Some((key, value))
    }

    // Removes and returns the first element
    pub fn get(&self, key: &K) -> Option<&V> {
        self.keys.get(key).and_then(|key| {
            self.order.iter().find(|(k, _)| Rc::ptr_eq(k, key)).map(|(_, v)| v)
        })
    }

    // Returns a reference to the element at the given index
    pub fn get_index(&self, index: usize) -> Option<&(Rc<K>, V)> {
        self.order.get(index)
    }

    // Returns a reference to the first element
    pub fn peek(&self) -> Option<&(Rc<K>, V)> {
        self.order.front()
    }

    // Returns a mutable reference to the first element
    pub fn peek_mut(&mut self) -> Option<&mut (Rc<K>, V)> {
        self.order.front_mut()
    }

    // Returns current size of the queue
    pub fn len(&self) -> usize {
        self.order.len()
    }
}