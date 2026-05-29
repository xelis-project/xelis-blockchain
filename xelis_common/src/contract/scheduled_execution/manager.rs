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
        if let Some(execution) = self.global_executions.get(hash) {
            Ok(execution)
        } else {
            self.changes.executions.get(hash)
                .ok_or(EnvironmentError::Static("scheduled execution not found in cache"))
        }
    }

    pub fn get_mut(&mut self, hash: &Hash) -> Result<&mut ScheduledExecution, EnvironmentError> {
        if let Some(execution) = self.changes.executions.get_mut(hash) {
            Ok(execution)
        } else {
            Err(EnvironmentError::Static("scheduled execution not found in cache"))
        }
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
