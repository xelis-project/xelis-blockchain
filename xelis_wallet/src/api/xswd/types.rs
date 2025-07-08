use indexmap::{IndexMap, IndexSet};
use serde::{Serialize, Deserialize};
use std::{
    fmt,
    hash::{Hash, Hasher},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc
    }
};
use xelis_common::{rpc::RpcRequest, tokio::sync::Mutex};

// Used for context only
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct XSWDAppId(pub Arc<String>);

// Application state shared between all threads
// Built from the application data
pub struct AppState {
    // Application ID in hexadecimal format
    id: XSWDAppId,
    // Name of the app
    name: String,
    // Small description of the app
    description: String,
    // URL of the app if exists
    url: Option<String>,
    // All permissions for each method based on user config
    permissions: Mutex<IndexMap<String, Permission>>,
    // Do we have a pending request?
    is_requesting: AtomicBool
}

impl Hash for AppState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.0.hash(state);
    }
}

impl PartialEq for AppState {
    fn eq(&self, other: &Self) -> bool {
        self.id.0.eq(&other.id.0)
    }
}

impl Eq for AppState {}

pub type AppStateShared = Arc<AppState>;

impl AppState {
    pub fn new(data: ApplicationData) -> Self {
        Self {
            id: XSWDAppId(Arc::new(data.id)),
            name: data.name,
            description: data.description,
            url: data.url,
            permissions: Mutex::new(data.permissions.into_iter().map(|k| (k, Permission::Ask)).collect()),
            is_requesting: AtomicBool::new(false)
        }
    }

    pub fn with_permissions(data: ApplicationData, permissions: IndexMap<String, Permission>) -> Self {
        Self {
            id: XSWDAppId(Arc::new(data.id)),
            name: data.name,
            description: data.description,
            url: data.url,
            permissions: Mutex::new(permissions),
            is_requesting: AtomicBool::new(false)
        }
    }

    pub fn id(&self) -> XSWDAppId {
        self.id.clone()
    }

    pub fn get_id(&self) -> &str {
        &self.id.0
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_description(&self) -> &String {
        &self.description
    }

    pub fn get_url(&self) -> &Option<String> {
        &self.url
    }

    pub fn get_permissions(&self) -> &Mutex<IndexMap<String, Permission>> {
        &self.permissions
    }

    pub fn is_requesting(&self) -> bool {
        self.is_requesting.load(Ordering::SeqCst)
    }

    pub fn set_requesting(&self, value: bool) {
        self.is_requesting.store(value, Ordering::SeqCst);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApplicationData {
    // Application ID in hexadecimal format
    id: String,
    // Name of the app
    name: String,
    // Small description of the app
    description: String,
    // URL of the app if exists
    url: Option<String>,
    // Permissions per RPC method
    // This is useful to request in one time all permissions
    #[serde(default)]
    permissions: IndexSet<String>
}

impl ApplicationData {
    pub fn get_id(&self) -> &String {
        &self.id
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_description(&self) -> &String {
        &self.description
    }

    pub fn get_url(&self) -> &Option<String> {
        &self.url
    }

    pub fn get_permissions(&self) -> &IndexSet<String> {
        &self.permissions
    }
}

pub type EncryptionKey = [u8; 32];

#[derive(Serialize, Deserialize, Debug)]
pub enum EncryptionMode {
    // No encryption, just transfer the data as is (discouraged)
    None,
    // Encrypt the data using AES-GCM
    AES {
        key: EncryptionKey
    },
    // Encrypt the data using ChaCha20Poly1305 AEAD cipher
    // Chacha20Poly1305 {
    //     key: EncryptionKey
    // }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApplicationDataRelayer {
    // Actual application data
    pub inner: ApplicationData,
    // Relayer URL where we should connect
    // to communicate with the application
    pub relayer: String,
    // Encryption mode to use for the relayer
    pub encryption_mode: EncryptionMode,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Allow,
    Reject,
    Ask
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Reject => write!(f, "reject"),
            Self::Ask => write!(f, "ask"),
        }
    }
}

pub enum PermissionRequest<'a> {
    Application,
    Request(&'a RpcRequest)
}

pub enum PermissionResult {
    Accept,
    Reject,
    AlwaysAccept,
    AlwaysReject
}

impl PermissionResult {
    pub fn is_positive(&self) -> bool {
        match self {
            Self::Accept | Self::AlwaysAccept => true,
            _ => false
        }
    }
}