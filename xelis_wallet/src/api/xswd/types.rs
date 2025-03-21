use indexmap::IndexMap;
use serde::{Serialize, Deserialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering}
    },
    fmt
};
use xelis_common::{rpc_server::RpcRequest, tokio::sync::Mutex};

// Application state shared between all threads
// Built from the application data
pub struct AppState {
    // Application ID in hexadecimal format
    id: String,
    // Name of the app
    name: String,
    // Small description of the app
    description: String,
    // URL of the app if exists
    url: Option<String>,
    // All permissions for each method
    permissions: Mutex<IndexMap<String, Permission>>,
    // Do we have a pending request?
    is_requesting: AtomicBool
}

pub type AppStateShared = Arc<AppState>;

impl AppState {
    pub fn new(data: ApplicationData) -> Self {
        Self {
            id: data.id,
            name: data.name,
            description: data.description,
            url: data.url,
            permissions: Mutex::new(data.permissions),
            is_requesting: AtomicBool::new(false)
        }
    }

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
    permissions: IndexMap<String, Permission>
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

    pub fn get_permissions(&self) -> &IndexMap<String, Permission> {
        &self.permissions
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    AcceptAlways,
    DenyAlways
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AcceptAlways => write!(f, "accept_always"),
            Self::DenyAlways => write!(f, "deny_always")
        }
    }
}

pub enum PermissionRequest<'a> {
    Application,
    Request(&'a RpcRequest)
}

pub enum PermissionResult {
    Allow,
    Deny,
    AlwaysAllow,
    AlwaysDeny
}

impl PermissionResult {
    pub fn is_positive(&self) -> bool {
        match self {
            Self::Allow | Self::AlwaysAllow => true,
            _ => false
        }
    }
}