use std::{
    cmp::Ordering,
    collections::hash_map::Entry,
    hash::{Hash as StdHash, Hasher},
};
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context, EnvironmentError, FnInstance, FnParams, FnReturnType, OpaqueWrapper, Primitive,
    SysCallResult, ValueCell,
};

use crate::{
    contract::{from_context, get_cache_for_contract, ChainState, ContractMetadata, ContractProvider, ModuleMetadata},
    crypto::Hash,
    serializer::{Reader, ReaderError, Writer},
    versioned_type::VersionedState,
};

use super::{Serializer, MAX_KEY_SIZE, MAX_VALUE_SIZE};

const PREFIX: &[u8] = b"\x00btree:";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueBTreeStore {
    namespace: Vec<u8>,
}
impl Serializable for OpaqueBTreeStore {}
impl JSONHelper for OpaqueBTreeStore {}

#[derive(Debug, Clone)]
pub struct OpaqueBTreeCursor {
    contract: Hash,
    namespace: Vec<u8>,
    current_node: Option<u64>,
    cached_key: Option<Vec<u8>>,
    cached_value: Option<ValueCell>,
}
impl Serializable for OpaqueBTreeCursor {}
impl JSONHelper for OpaqueBTreeCursor {}
impl PartialEq for OpaqueBTreeCursor {
    fn eq(&self, other: &Self) -> bool {
        self.contract == other.contract
            && self.namespace == other.namespace
            && self.current_node == other.current_node
    }
}
impl Eq for OpaqueBTreeCursor {}
impl StdHash for OpaqueBTreeCursor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.contract.hash(state);
        self.namespace.hash(state);
        self.current_node.hash(state);
    }
}

#[derive(Debug, Clone)]
struct Node {
    id: u64,
    key: Vec<u8>,
    value: ValueCell,
    parent: Option<u64>,
    left: Option<u64>,
    right: Option<u64>,
}

pub(crate) struct TreeContext<'ctx, 'ty, P: ContractProvider> {
    storage: &'ctx P,
    state: &'ctx mut ChainState<'ty>,
    contract: &'ctx Hash,
    namespace: &'ctx [u8],
}
impl<'ctx, 'ty, P: ContractProvider> TreeContext<'ctx, 'ty, P> {
    pub(crate) fn new(
        storage: &'ctx P,
        state: &'ctx mut ChainState<'ty>,
        contract: &'ctx Hash,
        namespace: &'ctx [u8],
    ) -> Self {
        Self { storage, state, contract, namespace }
    }
}

// Helper macro that unwraps the opaque store, contracts, and builds a `TreeContext`
// so individual syscalls can focus on their core logic. The body typically executes
// a short async block that returns a `SysCallResult`.
macro_rules! with_store_ctx {
    ($instance:expr, $metadata:expr, $context:expr, |$store:ident, $tree_ctx:ident, $contract:ident| $body:block) => {{
        let (storage, state) = from_context::<P>($context)?;
        let instance = $instance?;
        let $store: &OpaqueBTreeStore = instance.as_opaque_type()?;
        let $contract = $metadata.metadata.contract_executor.clone();
        let mut $tree_ctx = TreeContext::new(storage, state, &$contract, &$store.namespace);
        $body
    }};
}

#[derive(Clone, Copy)]
enum BranchDirection { Left, Right }
#[derive(Clone, Copy)]
enum ParentSide { Left, Right }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BTreeSeekBias {
    Exact = 0, GreaterOrEqual = 1, Greater = 2, LessOrEqual = 3, Less = 4,
}
impl TryFrom<u8> for BTreeSeekBias {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Exact,
            1 => Self::GreaterOrEqual,
            2 => Self::Greater,
            3 => Self::LessOrEqual,
            4 => Self::Less,
            _ => return Err(anyhow::anyhow!("invalid BTreeSeekBias variant {}", value)),
        })
    }
}

#[inline]
fn missing() -> EnvironmentError { EnvironmentError::Static("missing node") }

impl Node {
    fn new(id: u64, key: Vec<u8>, value: ValueCell, parent: Option<u64>) -> Self {
        Self { id, key, value, parent, left: None, right: None }
    }
    fn to_value(&self) -> ValueCell { ValueCell::Bytes(self.to_bytes()) }
    fn to_bytes(&self) -> Vec<u8> {
        debug_assert!(self.key.len() <= u32::MAX as usize);
        let mut bytes = Vec::new();
        let mut w = Writer::new(&mut bytes);
        w.write_u64(self.parent.unwrap_or(0));
        w.write_u64(self.left.unwrap_or(0));
        w.write_u64(self.right.unwrap_or(0));
        w.write_u32(self.key.len() as u32);
        w.write_bytes(&self.key);
        self.value.write(&mut w);
        bytes
    }
    fn from_value(id: u64, value: &ValueCell) -> Result<Self, EnvironmentError> {
        let bytes = match value { ValueCell::Bytes(bytes) => bytes, _ => return Err(EnvironmentError::Static("invalid BTree node encoding")) };
        let mut r = Reader::new(bytes);
        let parent = decode_ptr(r.read_u64().map_err(reader_error)?) ;
        let left   = decode_ptr(r.read_u64().map_err(reader_error)?) ;
        let right  = decode_ptr(r.read_u64().map_err(reader_error)?) ;
        let key_len = r.read_u32().map_err(reader_error)? as usize;
        let key = r.read_bytes_ref(key_len).map_err(reader_error)?.to_vec();
        let node_value = ValueCell::read(&mut r).map_err(reader_error)?;
        Ok(Self { id, key, value: node_value, parent, left, right })
    }
}

pub fn btree_store_new(_: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut Context)
-> FnReturnType<ContractMetadata> {
    let namespace = read_bytes(params.remove(0).into_owned(), "namespace")?;
    if namespace.len() > MAX_KEY_SIZE { return Err(EnvironmentError::Static("namespace is too large")); }
    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(OpaqueBTreeStore { namespace })).into()))
}

/// Inserts a value for `key`, always appending a new node even if the key already exists.
/// Returns `Null` to signal that duplicates are allowed; use cursors to scan or delete all entries.
pub async fn btree_store_insert<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>
) -> FnReturnType<ContractMetadata> {
    let key = read_key_bytes(params.remove(0).into_owned())?;
    let value = params.remove(0).into_owned();
    ensure_value_constraints(&value)?;
    with_store_ctx!(instance, metadata, context, |_store, ctx, _contract| {
        let replaced = insert_key(&mut ctx, key, value).await?;
        Ok(SysCallResult::Return(replaced.unwrap_or_else(|| ValueCell::Primitive(Primitive::Null)).into()))
    })
}

/// Finds the first (oldest) node whose key matches `key`. Later duplicates require cursor iteration.
pub async fn btree_store_get<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>
) -> FnReturnType<ContractMetadata> {
    let key = read_key_bytes(params.remove(0).into_owned())?;
    with_store_ctx!(instance, metadata, context, |_store, ctx, _contract| {
        let value = find_key(&mut ctx, &key).await?;
        Ok(SysCallResult::Return(value.unwrap_or_else(|| ValueCell::Primitive(Primitive::Null)).into()))
    })
}

/// Removes the first matching key. Invoke repeatedly or scan through a cursor to delete all duplicates.
pub async fn btree_store_delete<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>
) -> FnReturnType<ContractMetadata> {
    let key = read_key_bytes(params.remove(0).into_owned())?;
    with_store_ctx!(instance, metadata, context, |_store, ctx, _contract| {
        let removed = delete_key(&mut ctx, &key).await?;
        Ok(SysCallResult::Return(removed.unwrap_or_else(|| ValueCell::Primitive(Primitive::Null)).into()))
    })
}

pub async fn btree_store_seek<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>
) -> FnReturnType<ContractMetadata> {
    let key = read_key_bytes(params.remove(0).into_owned())?;
    let bias = read_bias(&params.remove(0).into_owned())?;
    with_store_ctx!(instance, metadata, context, |store, ctx, contract| {
        let Some(node) = seek_node(&mut ctx, &key, bias).await? else {
            return Ok(SysCallResult::Return(Primitive::Null.into()));
        };
        Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(OpaqueBTreeCursor {
            contract, namespace: store.namespace.clone(), current_node: Some(node.id),
            cached_key: Some(node.key), cached_value: Some(node.value),
        })).into()))
    })
}

pub fn btree_cursor_current(instance: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _context: &mut Context)
-> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let cursor: &OpaqueBTreeCursor = instance.as_opaque_type()?;
    if cursor.current_node.is_none() { return Ok(SysCallResult::Return(ValueCell::Primitive(Primitive::Null).into())); }
    if let Some(value) = &cursor.cached_value { return Ok(SysCallResult::Return(value.clone().into())); }
    Ok(SysCallResult::Return(ValueCell::Primitive(Primitive::Null).into()))
}

pub async fn btree_cursor_next<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>
) -> FnReturnType<ContractMetadata> {
    cursor_step::<P>(instance, context, BranchDirection::Right).await
}

pub async fn btree_cursor_prev<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>
) -> FnReturnType<ContractMetadata> {
    cursor_step::<P>(instance, context, BranchDirection::Left).await
}

async fn cursor_step<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>, context: &mut Context<'ty, 'r>, dir: BranchDirection,
) -> FnReturnType<ContractMetadata> {
    let (storage, state) = from_context::<P>(context)?;
    let mut instance = instance?;
    let cursor: &mut OpaqueBTreeCursor = instance.as_opaque_type_mut()?;
    let (contract, namespace) = (cursor.contract.clone(), cursor.namespace.clone());
    let mut ctx = TreeContext::new(storage, state, &contract, &namespace);
    refresh_cursor_cache(cursor, &mut ctx).await?;
    let Some(current_id) = cursor.current_node else { return Ok(SysCallResult::Return(Primitive::Boolean(false).into())); };
    cursor.current_node = match dir {
        BranchDirection::Right => successor(&mut ctx, current_id).await?,
        BranchDirection::Left  => predecessor(&mut ctx, current_id).await?,
    };
    refresh_cursor_cache(cursor, &mut ctx).await?;
    Ok(SysCallResult::Return(Primitive::Boolean(cursor.current_node.is_some()).into()))
}

async fn refresh_cursor_cache<'ty, P: ContractProvider>(
    cursor: &mut OpaqueBTreeCursor, ctx: &mut TreeContext<'_, 'ty, P>,
) -> Result<(), EnvironmentError> {
    cursor.cached_key = None;
    cursor.cached_value = None;
    if let Some(id) = cursor.current_node {
        if let Some(node) = read_node(ctx, id).await? {
            cursor.cached_key = Some(node.key);
            cursor.cached_value = Some(node.value);
        } else {
            cursor.current_node = None;
        }
    }
    Ok(())
}

async fn insert_key<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: Vec<u8>, value: ValueCell,
) -> Result<Option<ValueCell>, EnvironmentError> {
    let root = read_root_id(ctx).await?;
    if root == 0 {
        let id = allocate_node_id(ctx).await?;
        write_node(ctx, &Node::new(id, key, value, None)).await?;
        write_root_id(ctx, id).await?;
        return Ok(None);
    }
    let mut current_id = root;
    loop {
        // Load the current node from storage so we can decide which branch to descend.
        let mut node = load_node(ctx, current_id).await?;
        match key.cmp(&node.key) {
            Ordering::Less => {
                if let Some(left) = node.left { current_id = left; }
                else {
                    let id = allocate_node_id(ctx).await?;
                    node.left = Some(id);
                    write_node(ctx, &node).await?;
                    write_node(ctx, &Node::new(id, key, value, Some(node.id))).await?;
                    return Ok(None);
                }
            }
            Ordering::Greater | Ordering::Equal => {
                // Equal keys are routed to the right subtree so duplicates stay contiguous
                // when walking via `successor`.
                if let Some(right) = node.right { current_id = right; }
                else {
                    let id = allocate_node_id(ctx).await?;
                    node.right = Some(id);
                    write_node(ctx, &node).await?;
                    write_node(ctx, &Node::new(id, key, value, Some(node.id))).await?;
                    return Ok(None);
                }
            }
        }
    }
}

async fn find_key<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: &[u8],
) -> Result<Option<ValueCell>, EnvironmentError> {
    Ok(find_node_by_key(ctx, key).await?.map(|n| n.value))
}

async fn find_node_by_key<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: &[u8],
) -> Result<Option<Node>, EnvironmentError> {
    let mut current_id = read_root_id(ctx).await?;
    while current_id != 0 {
        let node = load_node(ctx, current_id).await?;
        match key.cmp(&node.key) {
            Ordering::Less => current_id = node.left.unwrap_or(0),
            Ordering::Greater => current_id = node.right.unwrap_or(0),
            Ordering::Equal => return Ok(Some(node)),
        }
    }
    Ok(None)
}

async fn delete_key<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: &[u8],
) -> Result<Option<ValueCell>, EnvironmentError> {
    if let Some(node) = find_node_by_key(ctx, key).await? {
        let removed = node.value.clone();
        delete_node(ctx, node).await?;
        return Ok(Some(removed));
    }
    Ok(None)
}

async fn seek_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: &[u8], bias: BTreeSeekBias,
) -> Result<Option<Node>, EnvironmentError> {
    let mut current_id = read_root_id(ctx).await?;
    let mut candidate: Option<Node> = None;
    while current_id != 0 {
        let node = load_node(ctx, current_id).await?;
        match key.cmp(&node.key) {
            Ordering::Equal => {
                return Ok(match bias {
                    BTreeSeekBias::Exact | BTreeSeekBias::GreaterOrEqual | BTreeSeekBias::LessOrEqual => Some(node),
                    BTreeSeekBias::Greater => {
                        match neighbor(ctx, node.id, BranchDirection::Right).await? {
                            Some(id) => Some(load_node(ctx, id).await?),
                            None => None,
                        }
                    }
                    BTreeSeekBias::Less => {
                        match neighbor(ctx, node.id, BranchDirection::Left).await? {
                            Some(id) => Some(load_node(ctx, id).await?),
                            None => None,
                        }
                    }
                });
            }
            Ordering::Less => {
                if matches!(bias, BTreeSeekBias::Greater | BTreeSeekBias::GreaterOrEqual) { candidate = Some(node.clone()); }
                current_id = node.left.unwrap_or(0);
            }
            Ordering::Greater => {
                if matches!(bias, BTreeSeekBias::Less | BTreeSeekBias::LessOrEqual) { candidate = Some(node.clone()); }
                current_id = node.right.unwrap_or(0);
            }
        }
    }
    Ok(if matches!(bias, BTreeSeekBias::Exact) { None } else { candidate })
}

async fn delete_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node: Node,
) -> Result<(), EnvironmentError> {
    // Classic BST removal: prune leaves, splice single children, or swap in-order successor.
    match (node.left, node.right) {
        (None, None) => replace_node(ctx, &node, None).await,
        (Some(child), None) | (None, Some(child)) => replace_node(ctx, &node, Some(child)).await,
        (Some(_), Some(right)) => {
            let successor = find_min_node(ctx, right).await?;
            let mut current = node;
            current.key = successor.key.clone();
            current.value = successor.value.clone();
            write_node(ctx, &current).await?;
            replace_node(ctx, &successor, successor.right).await
        }
    }
}

async fn replace_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node: &Node, child: Option<u64>,
) -> Result<(), EnvironmentError> {
    if let Some(child_id) = child {
        let mut child_node = load_node(ctx, child_id).await?;
        child_node.parent = node.parent;
        write_node(ctx, &child_node).await?;
    }
    if let Some(parent_id) = node.parent {
        let mut parent = load_node(ctx, parent_id).await?;
        if parent.left == Some(node.id) { parent.left = child; }
        else if parent.right == Some(node.id) { parent.right = child; }
        else { return Err(EnvironmentError::Static("inconsistent parent link")); }
        write_node(ctx, &parent).await?;
    } else {
        write_root_id(ctx, child.unwrap_or(0)).await?;
    }
    write_storage_value(ctx, node_storage_key(ctx.namespace, node.id), None).await?;
    Ok(())
}

async fn neighbor<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64, dir: BranchDirection,
) -> Result<Option<u64>, EnvironmentError> {
    let node = load_node(ctx, node_id).await?;
    let child = match dir { BranchDirection::Right => node.right, BranchDirection::Left => node.left };
    if let Some(c) = child {
        let n = match dir {
            BranchDirection::Right => find_min_node(ctx, c).await?,
            BranchDirection::Left  => find_max_node(ctx, c).await?,
        };
        return Ok(Some(n.id));
    }
    let side = match dir { BranchDirection::Right => ParentSide::Left, BranchDirection::Left => ParentSide::Right };
    ascend_until_parent_side(ctx, node, side).await
}

async fn successor<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<Option<u64>, EnvironmentError> {
    neighbor(ctx, node_id, BranchDirection::Right).await
}

async fn predecessor<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<Option<u64>, EnvironmentError> {
    neighbor(ctx, node_id, BranchDirection::Left).await
}

async fn find_min_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<Node, EnvironmentError> { find_extreme_node(ctx, node_id, BranchDirection::Left).await }

async fn find_max_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<Node, EnvironmentError> { find_extreme_node(ctx, node_id, BranchDirection::Right).await }

async fn find_extreme_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, mut node_id: u64, direction: BranchDirection,
) -> Result<Node, EnvironmentError> {
    loop {
        let node = load_node(ctx, node_id).await?;
        let next = match direction { BranchDirection::Left => node.left, BranchDirection::Right => node.right };
        if let Some(child) = next { node_id = child; } else { return Ok(node); }
    }
}

async fn ascend_until_parent_side<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, mut current: Node, expected_side: ParentSide,
) -> Result<Option<u64>, EnvironmentError> {
    let mut parent_id = current.parent;
    while let Some(pid) = parent_id {
        let parent = load_node(ctx, pid).await?;
        let matches = match expected_side {
            ParentSide::Left => parent.left == Some(current.id),
            ParentSide::Right => parent.right == Some(current.id),
        };
        if matches { return Ok(Some(parent.id)); }
        current = parent;
        parent_id = current.parent;
    }
    Ok(None)
}

async fn read_root_id<'ty, P: ContractProvider>(ctx: &mut TreeContext<'_, 'ty, P>) -> Result<u64, EnvironmentError> {
    read_u64_slot(ctx, root_storage_key(ctx.namespace), 0).await
}
async fn write_root_id<'ty, P: ContractProvider>(ctx: &mut TreeContext<'_, 'ty, P>, value: u64) -> Result<(), EnvironmentError> {
    write_u64_slot(ctx, root_storage_key(ctx.namespace), value).await
}
async fn read_next_id<'ty, P: ContractProvider>(ctx: &mut TreeContext<'_, 'ty, P>) -> Result<u64, EnvironmentError> {
    // `next` defaults to 1 so the very first allocated node gets id=1.
    read_u64_slot(ctx, next_storage_key(ctx.namespace), 1).await
}
async fn write_next_id<'ty, P: ContractProvider>(ctx: &mut TreeContext<'_, 'ty, P>, value: u64) -> Result<(), EnvironmentError> {
    write_u64_slot(ctx, next_storage_key(ctx.namespace), value).await
}
async fn read_u64_slot<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: ValueCell, default: u64,
) -> Result<u64, EnvironmentError> {
    Ok(read_storage_value(ctx, &key).await?.and_then(valuecell_to_u64).unwrap_or(default))
}
async fn write_u64_slot<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: ValueCell, value: u64,
) -> Result<(), EnvironmentError> {
    write_storage_value(ctx, key, Some(ValueCell::from(Primitive::U64(value)))).await?;
    Ok(())
}

async fn allocate_node_id<'ty, P: ContractProvider>(ctx: &mut TreeContext<'_, 'ty, P>) -> Result<u64, EnvironmentError> {
    // Sequential ids are sufficient because inserts happen serially within a contract execution.
    let next = read_next_id(ctx).await?;
    write_next_id(ctx, next + 1).await?;
    Ok(next)
}

async fn read_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<Option<Node>, EnvironmentError> {
    Ok(read_storage_value(ctx, &node_storage_key(ctx.namespace, node_id)).await?
        .map(|v| Node::from_value(node_id, &v)).transpose()?)
}
async fn load_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, id: u64,
) -> Result<Node, EnvironmentError> {
    read_node(ctx, id).await?.ok_or_else(missing)
}

async fn write_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node: &Node,
) -> Result<(), EnvironmentError> {
    write_storage_value(ctx, node_storage_key(ctx.namespace, node.id), Some(node.to_value())).await?;
    Ok(())
}

async fn read_storage_value<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: &ValueCell,
) -> Result<Option<ValueCell>, EnvironmentError> {
    ensure_cache_entry(ctx, key).await?;
    let cache = get_cache_for_contract(&mut ctx.state.caches, ctx.state.global_caches, ctx.contract.clone());
    Ok(cache.storage.get(key).and_then(|e| e.as_ref().and_then(|(_, v)| v.clone())))
}

async fn write_storage_value<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: ValueCell, value: Option<ValueCell>,
) -> Result<Option<ValueCell>, EnvironmentError> {
    let cache = get_cache_for_contract(&mut ctx.state.caches, ctx.state.global_caches, ctx.contract.clone());
    let entry = cache.storage.entry(key);
    let previous = match entry {
        Entry::Occupied(mut occ) => {
            let slot = occ.get_mut();
            if let Some((version, stored)) = slot {
                version.mark_updated();
                let prev = stored.clone();
                *stored = value;
                prev
            } else {
                *slot = Some((VersionedState::New, value));
                None
            }
        }
        Entry::Vacant(v) => { v.insert(Some((VersionedState::New, value))); None }
    };
    Ok(previous)
}

async fn ensure_cache_entry<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: &ValueCell,
) -> Result<(), EnvironmentError> {
    let exists = {
        let cache = get_cache_for_contract(&mut ctx.state.caches, ctx.state.global_caches, ctx.contract.clone());
        cache.storage.contains_key(key)
    };
    if !exists {
        let fetched = ctx.storage.load_data(ctx.contract, key, ctx.state.topoheight).await?;
        let cache = get_cache_for_contract(&mut ctx.state.caches, ctx.state.global_caches, ctx.contract.clone());
        let entry_value = fetched.map(|(topo, value)| (VersionedState::FetchedAt(topo), value));
        cache.storage.insert(key.clone(), entry_value);
    }
    Ok(())
}

fn root_storage_key(namespace: &[u8]) -> ValueCell { storage_key(namespace, b"root") }
fn next_storage_key(namespace: &[u8]) -> ValueCell { storage_key(namespace, b"next") }
fn node_storage_key(namespace: &[u8], id: u64) -> ValueCell { storage_key(namespace, format!("node:{id}").as_bytes()) }

fn storage_key(namespace: &[u8], suffix: &[u8]) -> ValueCell {
    let mut bytes = Vec::with_capacity(PREFIX.len() + namespace.len() + 1 + suffix.len());
    bytes.extend_from_slice(PREFIX);
    bytes.extend_from_slice(namespace);
    bytes.push(b':'); // Separator keeps namespaces disjoint without relying on null terminators.
    bytes.extend_from_slice(suffix);
    ValueCell::Bytes(bytes)
}

fn read_bytes(value: ValueCell, field: &str) -> Result<Vec<u8>, EnvironmentError> {
    match value {
        ValueCell::Bytes(bytes) => Ok(bytes),
        _ => Err(EnvironmentError::Static(match field {
            "namespace" => "BTree namespace must be bytes",
            "key" => "BTree key must be bytes",
            _ => "expected bytes value",
        })),
    }
}
fn read_key_bytes(value: ValueCell) -> Result<Vec<u8>, EnvironmentError> {
    let bytes = read_bytes(value, "key")?;
    if bytes.is_empty() { return Err(EnvironmentError::Static("key cannot be empty")); }
    if bytes.len() > MAX_KEY_SIZE { return Err(EnvironmentError::Static("key is too large")); }
    Ok(bytes)
}
fn ensure_value_constraints(value: &ValueCell) -> Result<(), EnvironmentError> {
    let size = value.size();
    if size > MAX_VALUE_SIZE { return Err(EnvironmentError::Static("value is too large")); }
    if !value.is_serializable() { return Err(EnvironmentError::Static("value is not serializable")); }
    Ok(())
}
fn read_bias(cell: &ValueCell) -> Result<BTreeSeekBias, EnvironmentError> {
    let (variant, _) = cell.as_enum()?;
    BTreeSeekBias::try_from(variant).map_err(|_| EnvironmentError::Static("invalid BTreeSeekBias variant"))
}
fn valuecell_to_u64(value: ValueCell) -> Option<u64> { if let ValueCell::Primitive(Primitive::U64(v)) = value { Some(v) } else { None } }
fn decode_ptr(value: u64) -> Option<u64> { if value == 0 { None } else { Some(value) } }
fn reader_error(err: ReaderError) -> EnvironmentError { EnvironmentError::Any(err.into()) }

#[cfg(test)]
mod tests;

#[cfg(test)]
mod seek_node_regression_tests;