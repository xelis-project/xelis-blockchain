use std::{
    collections::{
        VecDeque,
        BinaryHeap,
        HashMap,
        hash_map::Entry
    },
    sync::Arc,
    cmp::Ordering
};
use xelis_common::{
    transaction::Transaction,
    crypto::{
        Hash,
        PublicKey
    }
};

// this struct is used to store transaction with its hash and its size in bytes
pub struct TxSelectorEntry<'a> {
    // Hash of the transaction
    pub hash: &'a Arc<Hash>,
    // Current transaction
    pub tx: &'a Arc<Transaction>,
    // Size in bytes of the TX
    pub size: usize
}

impl PartialEq for TxSelectorEntry<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for TxSelectorEntry<'_> {}

// this struct is used to store transactions in a queue
// and to order them by fees
// Each Transactions is for a specific sender
#[derive(PartialEq, Eq)]
struct Transactions<'a>(VecDeque<TxSelectorEntry<'a>>);

impl PartialOrd for Transactions<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.front().map(|e| e.tx.get_fee()).partial_cmp(&other.0.front().map(|e| e.tx.get_fee()))
    }
}

impl Ord for Transactions<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.front().map(|e| e.tx.get_fee()).cmp(&other.0.front().map(|e| e.tx.get_fee()))
    }
}

// TX selector is used to select transactions from the mempool
// It create sub groups of transactions by sender and order them by nonces
// It joins all sub groups in a queue that is ordered by fees
pub struct TxSelector<'a> {
    queue: BinaryHeap<Transactions<'a>>
}

impl<'a> TxSelector<'a> {
    // Create a TxSelector from a list of groups
    pub fn grouped<I>(groups: I) -> Self
    where
        I: Iterator<Item = Vec<TxSelectorEntry<'a>>>
    {
        let mut queue = BinaryHeap::new();

        // push every group to the queue
        for group in groups {
            queue.push(Transactions(VecDeque::from(group)));
        }

        Self {
            queue
        }
    }

    // Create a TxSelector from a list of transactions with their hash and size
    pub fn new<I>(iter: I) -> Self
    where
        I: Iterator<Item = (usize, &'a Arc<Hash>, &'a Arc<Transaction>)>
    {
        let mut groups: HashMap<&PublicKey, Vec<TxSelectorEntry>> = HashMap::new();

        // Create groups of transactions
        for (size, hash, tx) in iter {
            let entry = TxSelectorEntry {
                hash,
                tx,
                size
            };

            match groups.entry(tx.get_source()) {
                Entry::Occupied(mut e) => {
                    e.get_mut().push(entry);
                },
                Entry::Vacant(e) => {
                    e.insert(vec![entry]);
                }
            }
        }

        // Order each group by nonces and push it to the queue
        let iter = groups.into_iter().map(|(_, mut v)| {
            v.sort_by(|a, b| a.tx.get_nonce().cmp(&b.tx.get_nonce()));
            v
        });
        Self::grouped(iter)
    }

    // Get the next transaction with the highest fee
    pub fn next(&mut self) -> Option<TxSelectorEntry<'a>> {
        // get the group with the highest fee
        let mut group = self.queue.pop()?;
        // get the entry with the highest fee from this group
        let entry = group.0.pop_front()?;

        // if its not empty, push it back to the queue
        if !group.0.is_empty() {
            self.queue.push(group);
        }

        Some(entry)
    }
}