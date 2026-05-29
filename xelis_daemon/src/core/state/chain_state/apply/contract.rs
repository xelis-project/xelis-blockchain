use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, VecDeque}
};
use xelis_common::{
    contract::{
        ContractCache,
        AssetChanges,
        CallbackEvent,
        ContractEventTracker,
        ContractLog,
        EventCallbackRegistration,
        ExecutionsChanges
    },
    crypto::Hash
};

#[derive(Default)]
pub struct ContractManager<'b> {
    // logs per caller hash
    pub logs: HashMap<Cow<'b, Hash>, Vec<ContractLog>>,
    pub caches: HashMap<Hash, ContractCache>,
    // global assets cache
    pub assets: HashMap<Hash, Option<AssetChanges>>,
    pub tracker: ContractEventTracker,
    // Planned executions for the current block
    pub executions: ExecutionsChanges,
    // All events callback to process
    pub events: VecDeque<CallbackEvent>,
    // all events registrations that must be stored
    pub events_listeners: HashMap<(Hash, u64), Vec<(Hash, EventCallbackRegistration)>>,
    // all events already processed from storage
    pub events_processed: HashMap<(Hash, u64), HashSet<Hash>>,
}
