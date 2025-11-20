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
    serializer::{Reader, ReaderError, Writer, Serializer},
    versioned_type::VersionedState,
};

use super::{MAX_KEY_SIZE, MAX_VALUE_SIZE};

const PREFIX: &[u8] = b"\x00btree:";
const ERR_NODE_ENC: &str = "invalid BTree node encoding";

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
    cached_value: Option<ValueCell>,
    ascending: bool,
}
impl Serializable for OpaqueBTreeCursor {}
impl JSONHelper for OpaqueBTreeCursor {}
impl PartialEq for OpaqueBTreeCursor {
    fn eq(&self, other: &Self) -> bool {
        self.contract == other.contract
            && self.namespace == other.namespace
            && self.current_node == other.current_node
            && self.ascending == other.ascending
    }
}
impl Eq for OpaqueBTreeCursor {}
impl StdHash for OpaqueBTreeCursor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.contract.hash(state);
        self.namespace.hash(state);
        self.current_node.hash(state);
        self.ascending.hash(state);
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

#[derive(Debug, Clone)]
struct NodeHeader {
    id: u64,
    key: Vec<u8>,
    parent: Option<u64>,
    left: Option<u64>,
    right: Option<u64>,
}

mod record;
use record::{read_node_header_from_reader, NodeRecord};

const GAS_SCALING_FACTOR: u64 = 1000;
const GAS_PER_BYTE_READ: u64 = 100;
const GAS_PER_BYTE_WRITE: u64 = 1000;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
struct StorageUsage {
    read_bytes: u64,
    written_bytes: u64,
}

impl StorageUsage {
    fn charge<'ty, 'r>(self, context: &mut Context<'ty, 'r>) -> Result<(), EnvironmentError> {
        let cost = (self.read_bytes * GAS_PER_BYTE_READ + self.written_bytes * GAS_PER_BYTE_WRITE) / GAS_SCALING_FACTOR;
        if cost > 0 {
            context.increase_gas_usage(cost)?;
        }
        Ok(())
    }
}

pub(crate) struct TreeContext<'ctx, 'ty, P: ContractProvider> {
    storage: &'ctx P,
    state: &'ctx mut ChainState<'ty>,
    contract: &'ctx Hash,
    namespace: &'ctx [u8],
    usage: StorageUsage,
}
impl<'ctx, 'ty, P: ContractProvider> TreeContext<'ctx, 'ty, P> {
    pub(crate) fn new(
        storage: &'ctx P,
        state: &'ctx mut ChainState<'ty>,
        contract: &'ctx Hash,
        namespace: &'ctx [u8],
    ) -> Self {
        Self { storage, state, contract, namespace, usage: StorageUsage::default() }
    }

    fn charge_read(&mut self, bytes: usize) {
        self.usage.read_bytes += bytes as u64;
    }

    fn charge_write(&mut self, bytes: usize) {
        self.usage.written_bytes += bytes as u64;
    }

    fn finish(self) -> StorageUsage {
        let TreeContext { storage: _, state: _, contract: _, namespace: _, usage } = self;
        usage
    }

    #[inline]
    fn cached_value<'a>(&'a mut self, key: &ValueCell) -> Option<&'a ValueCell> {
        let cache = get_cache_for_contract(&mut self.state.caches, self.state.global_caches, self.contract.clone());
        cache
            .storage
            .get(key)
            .and_then(|e| e.as_ref().and_then(|(_, v)| v.as_ref()))
    }

    #[inline]
    fn cache_contains(&mut self, key: &ValueCell) -> bool {
        let cache = get_cache_for_contract(&mut self.state.caches, self.state.global_caches, self.contract.clone());
        cache.storage.contains_key(key)
    }

    #[inline]
    fn cache_insert_entry(&mut self, key: ValueCell, entry: Option<(VersionedState, Option<ValueCell>)>) {
        let cache = get_cache_for_contract(&mut self.state.caches, self.state.global_caches, self.contract.clone());
        cache.storage.insert(key, entry);
    }
}

// Helper macro that unwraps the opaque store, contracts, and builds a `TreeContext`
macro_rules! with_store_ctx {
    ($instance:expr, $metadata:expr, $context:expr, |$store:ident, $tree_ctx:ident, $contract:ident| $body:block) => {{
        let (storage, state) = from_context::<P>($context)?;
        let instance = $instance?;
        let $store: &OpaqueBTreeStore = instance.as_opaque_type()?;
        let $contract = $metadata.metadata.contract_executor.clone();
        let mut $tree_ctx = TreeContext::new(storage, state, &$contract, &$store.namespace);
        let res = { $body };
        $tree_ctx.finish().charge($context)?;
        res
    }};
}

// Helper macro for mutable cursor operations
macro_rules! with_cursor_ctx_mut {
    ($instance:expr, $context:expr, |$cursor:ident, $tree_ctx:ident| $body:block) => {{
        let (storage, state) = from_context::<P>($context)?;
        let mut instance = $instance?;
        let $cursor: &mut OpaqueBTreeCursor = instance.as_opaque_type_mut()?;
        let (contract, namespace) = ($cursor.contract.clone(), $cursor.namespace.clone());
        let mut $tree_ctx = TreeContext::new(storage, state, &contract, &namespace);
        let res = { $body };
        $tree_ctx.finish().charge($context)?;
        res
    }};
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction { Left, Right }

#[inline]
fn opposite(side: Direction) -> Direction {
    match side {
        Direction::Left => Direction::Right,
        Direction::Right => Direction::Left,
    }
}

#[inline]
fn child_id(n: &Node, side: Direction) -> Option<u64> {
    match side { Direction::Left => n.left, Direction::Right => n.right }
}

#[inline]
fn set_child(n: &mut Node, side: Direction, v: Option<u64>) {
    match side { Direction::Left => n.left = v, Direction::Right => n.right = v }
}

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
        let record: NodeRecord = self.into();
        let mut bytes = Vec::with_capacity(record.size());
        {
            let mut writer = Writer::new(&mut bytes);
            record.write(&mut writer);
        }
        bytes
    }
    fn from_value(id: u64, value: &ValueCell) -> Result<Self, EnvironmentError> {
        let bytes = match value {
            ValueCell::Bytes(bytes) => bytes,
            _ => return Err(EnvironmentError::Static(ERR_NODE_ENC)),
        };
        let mut reader = Reader::new(bytes);
        let record = NodeRecord::read(&mut reader).map_err(reader_error)?;
        Ok(record.into_node(id))
    }
}

fn decode_header_and_maybe_value(
    id: u64,
    cell: &ValueCell,
    with_value: bool,
) -> Result<(NodeHeader, Option<ValueCell>), EnvironmentError> {
    let bytes = match cell { ValueCell::Bytes(bytes) => bytes, _ => return Err(EnvironmentError::Static(ERR_NODE_ENC)) };
    let mut r = Reader::new(bytes);
    let header = read_node_header_from_reader(&mut r, id).map_err(reader_error)?;

    if with_value {
        let node_value = ValueCell::read(&mut r).map_err(reader_error)?;
        Ok((header, Some(node_value)))
    } else {
        Ok((header, None))
    }
}

fn node_header_from_value(id: u64, value: &ValueCell) -> Result<NodeHeader, EnvironmentError> {
    Ok(decode_header_and_maybe_value(id, value, false)?.0)
}

/* -------------------------- Treap helpers --------------------------- */

#[inline]
fn cmp_pair(a_key: &[u8], a_id: u64, b_key: &[u8], b_id: u64) -> Ordering {
    match a_key.cmp(b_key) {
        Ordering::Equal => a_id.cmp(&b_id),
        other => other,
    }
}

// Simple 64-bit FNV-1a for bytes
#[inline]
fn hash_key64(key: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in key {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// SplitMix64 finalizer (xorshift* variant) for good bit diffusion
#[inline]
fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

#[inline]
fn priority_for_pair(key: &[u8], id: u64) -> u64 {
    mix64(hash_key64(key) ^ id)
}

async fn node_priority<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<u64, EnvironmentError> {
    let header = load_node_header(ctx, node_id).await?;
    Ok(priority_for_pair(&header.key, header.id))
}

async fn rotate<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>,
    x_id: u64,
    dir: Direction,
) -> Result<(), EnvironmentError> {
    let child_side = opposite(dir);
    let opp_side = opposite(child_side);

    let mut x = load_node(ctx, x_id).await?;
    let y_id = child_id(&x, child_side).ok_or_else(|| EnvironmentError::Static(match dir {
        Direction::Left  => "rotate_left with missing right child",
        Direction::Right => "rotate_right with missing left child",
    }))?;
    let mut y = load_node(ctx, y_id).await?;
    let beta = child_id(&y, opp_side);

    // Link y to x's parent (single parent load+write)
    if let Some(pid) = x.parent {
        let mut parent = load_node(ctx, pid).await?;
        if parent.left == Some(x_id) {
            parent.left = Some(y_id);
        } else if parent.right == Some(x_id) {
            parent.right = Some(y_id);
        } else {
            return Err(EnvironmentError::Static("inconsistent parent link"));
        }
        write_node(ctx, &parent).await?;
        y.parent = Some(pid);
    } else {
        write_root_id(ctx, y_id).await?;
        y.parent = None;
    }

    // Move beta to x.<child_side>
    set_child(&mut x, child_side, beta);
    if let Some(b) = beta {
        let mut beta_node = load_node(ctx, b).await?;
        beta_node.parent = Some(x_id);
        write_node(ctx, &beta_node).await?;
    }

    // Make x the <opp_side> child of y
    set_child(&mut y, opp_side, Some(x_id));
    x.parent = Some(y_id);

    write_node(ctx, &x).await?;
    write_node(ctx, &y).await?;
    Ok(())
}

async fn rotate_left<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, x_id: u64,
) -> Result<(), EnvironmentError> {
    rotate(ctx, x_id, Direction::Left).await
}

async fn rotate_right<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, x_id: u64,
) -> Result<(), EnvironmentError> {
    rotate(ctx, x_id, Direction::Right).await
}

/* ------------------------ end Treap helpers ------------------------- */

pub fn btree_store_new(_: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut Context)
-> FnReturnType<ContractMetadata> {
    let namespace = read_bytes(params.remove(0).into_owned(), "namespace")?;
    if namespace.len() > MAX_KEY_SIZE { return Err(EnvironmentError::Static("namespace is too large")); }
    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(OpaqueBTreeStore { namespace })).into()))
}

/// Inserts a value for `key`, allowing duplicates.
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

/// Finds the first node whose key matches `key` (leftmost equal by (key,id)).
pub async fn btree_store_get<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>
) -> FnReturnType<ContractMetadata> {
    let key = read_key_bytes(params.remove(0).into_owned())?;
    with_store_ctx!(instance, metadata, context, |_store, ctx, _contract| {
        let value = find_key(&mut ctx, &key).await?;
        Ok(SysCallResult::Return(value.unwrap_or_else(|| ValueCell::Primitive(Primitive::Null)).into()))
    })
}

/// Removes one matching key.
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
    let ascending = read_bool(&params.remove(0).into_owned())?;
    with_store_ctx!(instance, metadata, context, |store, ctx, contract| {
        let result = if let Some(node) = seek_node(&mut ctx, &key, bias).await? {
            Primitive::Opaque(OpaqueWrapper::new(OpaqueBTreeCursor {
                contract: contract.clone(),
                namespace: store.namespace.clone(),
                current_node: Some(node.id),
                cached_value: Some(node.value),
                ascending,
            })).into()
        } else {
            Primitive::Null.into()
        };
        Ok(SysCallResult::Return(result))
    })
}

pub fn btree_cursor_current(instance: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _context: &mut Context)
-> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let cursor: &OpaqueBTreeCursor = instance.as_opaque_type()?;
    let out = match (cursor.current_node, &cursor.cached_value) {
        (Some(_), Some(v)) => v.clone(),
        _ => ValueCell::Primitive(Primitive::Null),
    };
    Ok(SysCallResult::Return(out.into()))
}

pub async fn btree_cursor_next<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>
) -> FnReturnType<ContractMetadata> {
    cursor_step::<P>(instance, context).await
}

pub async fn btree_cursor_delete<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>
) -> FnReturnType<ContractMetadata> {
    with_cursor_ctx_mut!(instance, context, |cursor, ctx| {
        let result = match delete_at_cursor(cursor, &mut ctx).await? {
            Some(val) => Ok(SysCallResult::Return(val.into())),
            None => Ok(SysCallResult::Return(Primitive::Null.into())),
        };
        result
    })
}

async fn cursor_step<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>, context: &mut Context<'ty, 'r>,
) -> FnReturnType<ContractMetadata> {
    with_cursor_ctx_mut!(instance, context, |cursor, ctx| {
        match cursor.current_node {
            None => Ok(SysCallResult::Return(Primitive::Boolean(false).into())),
            Some(current_id) => {
                if load_node_header(&mut ctx, current_id).await.is_err() {
                    cursor.current_node = None;
                    cursor.cached_value = None;
                    Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
                } else {
                    cursor.current_node = match cursor.ascending {
                        true => successor(&mut ctx, current_id).await?,
                        false => predecessor(&mut ctx, current_id).await?,
                    };
                    refresh_cursor_cache(cursor, &mut ctx).await?;
                    Ok(SysCallResult::Return(Primitive::Boolean(cursor.current_node.is_some()).into()))
                }
            }
        }
    })
}

async fn refresh_cursor_cache<'ty, P: ContractProvider>(
    cursor: &mut OpaqueBTreeCursor, ctx: &mut TreeContext<'_, 'ty, P>,
) -> Result<(), EnvironmentError> {
    cursor.cached_value = None;
    if let Some(id) = cursor.current_node {
        if let Some(node) = read_node(ctx, id).await? {
            cursor.cached_value = Some(node.value);
        } else {
            cursor.current_node = None;
        }
    }
    Ok(())
}

async fn delete_at_cursor<'ty, P: ContractProvider>(
    cursor: &mut OpaqueBTreeCursor, ctx: &mut TreeContext<'_, 'ty, P>,
) -> Result<Option<ValueCell>, EnvironmentError> {
    if let Some(current_id) = cursor.current_node {
         // Load value to return
        if let Some(node) = read_node(ctx, current_id).await? {
            let value = node.value.clone();

            // Find neighbor to move cursor to
            let next_id = match cursor.ascending {
                true => successor(ctx, current_id).await?,
                false => predecessor(ctx, current_id).await?,
            };

            // Delete node
            treap_delete_node(ctx, current_id).await?;

            // Update cursor
            cursor.current_node = next_id;
            refresh_cursor_cache(cursor, ctx).await?;
            
            return Ok(Some(value));
        } else {
             // Node not found in storage (stale cursor?)
             cursor.current_node = None;
             cursor.cached_value = None;
        }
    }
    Ok(None)
}

/* --------------------------- Treap core ----------------------------- */

async fn insert_key<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: Vec<u8>, value: ValueCell,
) -> Result<Option<ValueCell>, EnvironmentError> {
    // Allocate id first so (key,id) defines total order and deterministic priority.
    let id = allocate_node_id(ctx).await?;
    let root = read_root_id(ctx).await?;
    if root == 0 {
        write_node(ctx, &Node::new(id, key, value, None)).await?;
        write_root_id(ctx, id).await?;
        return Ok(None);
    }

    let new_priority = priority_for_pair(&key, id);

    // Standard BST insert using (key,id) ordering (duplicates go to the right because id increases).
    let mut current_id = root;
    loop {
        let header = load_node_header(ctx, current_id).await?;
        match cmp_pair(&key, id, &header.key, header.id) {
            Ordering::Less => {
                if let Some(l) = header.left { current_id = l; }
                else {
                    let mut parent = load_node(ctx, header.id).await?;
                    parent.left = Some(id);
                    write_node(ctx, &parent).await?;
                    write_node(ctx, &Node::new(id, key, value, Some(header.id))).await?;
                    break;
                }
            }
            Ordering::Greater => {
                if let Some(r) = header.right { current_id = r; }
                else {
                    let mut parent = load_node(ctx, header.id).await?;
                    parent.right = Some(id);
                    write_node(ctx, &parent).await?;
                    write_node(ctx, &Node::new(id, key, value, Some(header.id))).await?;
                    break;
                }
            }
            Ordering::Equal => unreachable!("(key,id) is unique"),
        }
    }

    // Treap heap property: bubble the new node up by rotations until parent priority >= node priority.
    loop {
        let node = load_node_header(ctx, id).await?;
        let Some(pid) = node.parent else { break; };
        let parent = load_node_header(ctx, pid).await?;
        let parent_p = priority_for_pair(&parent.key, parent.id);
        if new_priority > parent_p {
            if parent.left == Some(id) { rotate_right(ctx, pid).await?; } else { rotate_left(ctx, pid).await?; }
        } else {
            break;
        }
    }
    Ok(None)
}

async fn treap_delete_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<(), EnvironmentError> {
    // Rotate the target down until it's a leaf, then remove.
    loop {
        let header = load_node_header(ctx, node_id).await?;
        match (header.left, header.right) {
            (None, None) => {
                let node = load_node(ctx, node_id).await?;
                replace_node(ctx, &node, None).await?;
                return Ok(());
            }
            (Some(l), Some(r)) => {
                let lp = node_priority(ctx, l).await?;
                let rp = node_priority(ctx, r).await?;
                if lp > rp { rotate_right(ctx, header.id).await?; }
                else { rotate_left(ctx, header.id).await?; }
            }
            (Some(_), None) => rotate_right(ctx, header.id).await?,
            (None, Some(_)) => rotate_left(ctx, header.id).await?,
        }
        // After a rotation, the same logical node `node_id` moved down one level; keep rotating.
    }
}

/* ------------------------- end Treap core --------------------------- */

async fn find_key<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: &[u8],
) -> Result<Option<ValueCell>, EnvironmentError> {
    Ok(find_node_by_key(ctx, key).await?.map(|n| n.value))
}

async fn lower_bound_header<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, q_key: &[u8], q_id: u64,
) -> Result<Option<NodeHeader>, EnvironmentError> {
    let mut current_id = read_root_id(ctx).await?;
    let mut candidate: Option<NodeHeader> = None;
    while current_id != 0 {
        let header = load_node_header(ctx, current_id).await?;
        match cmp_pair(&header.key, header.id, q_key, q_id) {
            Ordering::Less => current_id = header.right.unwrap_or(0),
            _ => {
                let next = header.left.unwrap_or(0);
                candidate = Some(header);
                current_id = next;
            }
        }
    }
    Ok(candidate)
}

async fn find_node_by_key<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>,
    key: &[u8],
) -> Result<Option<Node>, EnvironmentError> {
    match lower_bound_header(ctx, key, 0).await? {
        Some(h) if h.key == key => Ok(Some(load_node(ctx, h.id).await?)),
        _ => Ok(None),
    }
}

async fn tree_extreme_id<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, direction: Direction,
) -> Result<Option<u64>, EnvironmentError> {
    let root = read_root_id(ctx).await?;
    if root == 0 {
        return Ok(None);
    }
    let id = match direction {
        Direction::Left => find_min_id(ctx, root).await?,
        Direction::Right => find_max_id(ctx, root).await?,
    };
    Ok(Some(id))
}

async fn delete_key<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: &[u8],
) -> Result<Option<ValueCell>, EnvironmentError> {
    if let Some(node) = find_node_by_key(ctx, key).await? {
        let removed = node.value.clone();
        treap_delete_node(ctx, node.id).await?;
        return Ok(Some(removed));
    }
    Ok(None)
}

async fn seek_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: &[u8], bias: BTreeSeekBias,
) -> Result<Option<Node>, EnvironmentError> {
    let target_id = match bias {
        BTreeSeekBias::Exact => {
            if let Some(candidate) = lower_bound_header(ctx, key, 0).await? {
                if candidate.key == key { Some(candidate.id) } else { None }
            } else {
                None
            }
        }
        BTreeSeekBias::GreaterOrEqual => lower_bound_header(ctx, key, 0).await?.map(|h| h.id),
        BTreeSeekBias::Greater => lower_bound_header(ctx, key, u64::MAX).await?.map(|h| h.id),
        BTreeSeekBias::LessOrEqual => {
            if let Some(gt_hdr) = lower_bound_header(ctx, key, u64::MAX).await? {
                predecessor(ctx, gt_hdr.id).await?
            } else {
                tree_extreme_id(ctx, Direction::Right).await?
            }
        }
        BTreeSeekBias::Less => {
            if let Some(ge_hdr) = lower_bound_header(ctx, key, 0).await? {
                predecessor(ctx, ge_hdr.id).await?
            } else {
                tree_extreme_id(ctx, Direction::Right).await?
            }
        }
    };
    load_node_by_id(ctx, target_id).await
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
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64, dir: Direction,
) -> Result<Option<u64>, EnvironmentError> {
    let node = load_node_header(ctx, node_id).await?;
    let child = match dir { Direction::Right => node.right, Direction::Left => node.left };
    if let Some(c) = child {
        let next_id = match dir {
            Direction::Right => find_min_id(ctx, c).await?,
            Direction::Left => find_max_id(ctx, c).await?,
        };
        return Ok(Some(next_id));
    }
    let side = opposite(dir);
    ascend_until_parent_side(ctx, node, side).await
}

async fn successor<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<Option<u64>, EnvironmentError> {
    neighbor(ctx, node_id, Direction::Right).await
}

async fn predecessor<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<Option<u64>, EnvironmentError> {
    neighbor(ctx, node_id, Direction::Left).await
}

#[cfg_attr(not(test), allow(dead_code))]
async fn find_min_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<Node, EnvironmentError> {
    let id = find_min_id(ctx, node_id).await?;
    load_node(ctx, id).await
}

async fn find_min_id<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<u64, EnvironmentError> {
    find_extreme_id(ctx, node_id, Direction::Left).await
}

async fn find_max_id<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node_id: u64,
) -> Result<u64, EnvironmentError> {
    find_extreme_id(ctx, node_id, Direction::Right).await
}

async fn find_extreme_id<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, mut node_id: u64, direction: Direction,
) -> Result<u64, EnvironmentError> {
    loop {
        let node = load_node_header(ctx, node_id).await?;
        let next = match direction { Direction::Left => node.left, Direction::Right => node.right };
        if let Some(child) = next { node_id = child; } else { return Ok(node.id); }
    }
}

async fn ascend_until_parent_side<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, mut current: NodeHeader, expected_side: Direction,
) -> Result<Option<u64>, EnvironmentError> {
    let mut parent_id = current.parent;
    while let Some(pid) = parent_id {
        let parent = load_node_header(ctx, pid).await?;
        let matches = match expected_side {
            Direction::Left => parent.left == Some(current.id),
            Direction::Right => parent.right == Some(current.id),
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
    ensure_cache_entry(ctx, &key).await?;
    Ok(ctx.cached_value(&key).and_then(valuecell_as_u64).unwrap_or(default))
}
async fn write_u64_slot<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: ValueCell, value: u64,
) -> Result<(), EnvironmentError> {
    write_storage_value(ctx, key, Some(ValueCell::from(Primitive::U64(value)))).await.map(|_| ())
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
    let key = node_storage_key(ctx.namespace, node_id);
    ensure_cache_entry(ctx, &key).await?;
    Ok(ctx.cached_value(&key).map(|v| Node::from_value(node_id, v)).transpose()?)
}
async fn load_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, id: u64,
) -> Result<Node, EnvironmentError> {
    read_node(ctx, id).await?.ok_or_else(missing)
}

async fn load_node_header<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, id: u64,
) -> Result<NodeHeader, EnvironmentError> {
    let key = node_storage_key(ctx.namespace, id);
    ensure_cache_entry(ctx, &key).await?;
    let v = ctx.cached_value(&key).ok_or_else(missing)?;
    node_header_from_value(id, v)
}

async fn load_node_by_id<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>,
    id: Option<u64>,
) -> Result<Option<Node>, EnvironmentError> {
    match id {
        Some(id) => Ok(Some(load_node(ctx, id).await?)),
        None => Ok(None),
    }
}

async fn write_node<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, node: &Node,
) -> Result<(), EnvironmentError> {
    write_storage_value(ctx, node_storage_key(ctx.namespace, node.id), Some(node.to_value())).await.map(|_| ())
}

async fn write_storage_value<'ty, P: ContractProvider>(
    ctx: &mut TreeContext<'_, 'ty, P>, key: ValueCell, value: Option<ValueCell>,
) -> Result<Option<ValueCell>, EnvironmentError> {
    let size = key.size() + value.as_ref().map(|v| v.size()).unwrap_or(0);
    ctx.charge_write(size);
    let cache = get_cache_for_contract(&mut ctx.state.caches, ctx.state.global_caches, ctx.contract.clone());
    let entry = cache.storage.entry(key);
    let previous = match entry {
        Entry::Occupied(mut occ) => {
            let slot = occ.get_mut();
            if let Some((version, stored)) = slot {
                version.mark_updated();
                std::mem::replace(stored, value)
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
    if ctx.cache_contains(key) { return Ok(()); }

    let fetched = ctx.storage.load_data(ctx.contract, key, ctx.state.topoheight).await?;
    let mut size = key.size();
    if let Some((_, Some(v))) = &fetched {
        size += v.size();
    }
    ctx.charge_read(size);

    let entry_value = fetched.map(|(topo, value)| (VersionedState::FetchedAt(topo), value));
    ctx.cache_insert_entry(key.clone(), entry_value);
    Ok(())
}

fn root_storage_key(namespace: &[u8]) -> ValueCell { storage_key(namespace, b"root") }
fn next_storage_key(namespace: &[u8]) -> ValueCell { storage_key(namespace, b"next") }
fn node_storage_key(namespace: &[u8], id: u64) -> ValueCell { storage_key(namespace, format!("node:{id}").as_bytes()) }

fn storage_key(namespace: &[u8], suffix: &[u8]) -> ValueCell {
    let mut bytes = Vec::with_capacity(PREFIX.len() + namespace.len() + 1 + suffix.len());
    bytes.extend_from_slice(PREFIX);
    bytes.extend_from_slice(namespace);
    bytes.push(b':');
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
fn read_bool(cell: &ValueCell) -> Result<bool, EnvironmentError> {
    match cell {
        ValueCell::Primitive(Primitive::Boolean(b)) => Ok(*b),
        _ => Err(EnvironmentError::Static("expected boolean")),
    }
}
#[inline]
fn valuecell_as_u64(value: &ValueCell) -> Option<u64> {
    if let ValueCell::Primitive(Primitive::U64(v)) = value { Some(*v) } else { None }
}
#[inline]
fn decode_ptr(value: u64) -> Option<u64> {
    if value == 0 { None } else { Some(value) }
}
fn reader_error(err: ReaderError) -> EnvironmentError { EnvironmentError::Any(err.into()) }

#[cfg(test)]
mod tests;