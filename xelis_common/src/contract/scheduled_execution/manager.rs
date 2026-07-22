use std::{collections::HashMap, sync::Arc};

use xelis_vm::EnvironmentError;

use crate::crypto::Hash;
use super::{ScheduledExecution, ScheduledExecutionKind};

#[derive(Debug, Clone, Default)]
pub struct ExecutionsChanges {
    // Registered executions during the current execution
    pub executions: HashMap<Arc<Hash>, ScheduledExecution>,
    // Hashes of scheduled executions to trigger at specific topoheights
    pub at_topoheight: Vec<Arc<Hash>>,
    // Hashes of scheduled executions to trigger at the end of the block
    pub block_end: Vec<Arc<Hash>>,
}

pub struct ExecutionsManager<'a> {
    // In case we are in a scheduled execution already, prevent from
    // recursive scheduling
    pub allow_executions: bool,
    // all scheduled executions in the global chain state
    pub global_executions: &'a HashMap<Arc<Hash>, ScheduledExecution>,
    pub changes: ExecutionsChanges,
}

impl<'a> ExecutionsManager<'a> {
    pub fn contains_key(&self, hash: &Hash) -> bool {
        self.global_executions.contains_key(hash) || self.changes.executions.contains_key(hash)
    }

    pub fn get(&self, hash: &Hash) -> Result<&ScheduledExecution, EnvironmentError> {
        if let Some(execution) = self.changes.executions.get(hash) {
            Ok(execution)
        } else {
            self.global_executions.get(hash)
                .ok_or(EnvironmentError::Static("scheduled execution not found in cache"))
        }
    }

    pub fn get_mut(&mut self, hash: &Hash) -> Result<&mut ScheduledExecution, EnvironmentError> {
        if !self.changes.executions.contains_key(hash) {
            let execution = self.global_executions.get(hash)
                .cloned()
                .ok_or(EnvironmentError::Static("scheduled execution not found in global cache"))?;
            self.changes.executions.insert(execution.hash.clone(), execution);
        }

        self.changes.executions.get_mut(hash)
            .ok_or(EnvironmentError::Static("scheduled execution not found in cache"))
    }

    pub fn insert(&mut self, execution: ScheduledExecution) -> bool {
        if self.global_executions.contains_key(&execution.hash) || self.changes.executions.contains_key(&execution.hash) {
            return false
        }

        match &execution.kind {
            ScheduledExecutionKind::TopoHeight(_) => self.changes.at_topoheight.push(execution.hash.clone()),
            ScheduledExecutionKind::BlockEnd => self.changes.block_end.push(execution.hash.clone()),
        };

        self.changes.executions.insert(execution.hash.clone(), execution).is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_execution_is_copied_before_mutation() {
        let hash = Arc::new(Hash::zero());
        let execution = ScheduledExecution {
            hash: hash.clone(),
            contract: Hash::zero(),
            chunk_id: 0,
            params: Vec::new(),
            max_gas: 10,
            kind: ScheduledExecutionKind::BlockEnd,
            gas_sources: Default::default(),
        };
        let global_executions = [(hash.clone(), execution)].into_iter().collect();
        let mut manager = ExecutionsManager {
            allow_executions: true,
            global_executions: &global_executions,
            changes: Default::default(),
        };

        manager.get_mut(hash.as_ref()).unwrap().max_gas = 20;

        assert_eq!(global_executions.get(hash.as_ref()).unwrap().max_gas, 10);
        assert_eq!(manager.get(hash.as_ref()).unwrap().max_gas, 20);
        assert_eq!(manager.changes.executions.get(hash.as_ref()).unwrap().max_gas, 20);
    }
}
