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
use xelis_common::{rpc::RpcRequest, serializer::*, tokio::sync::Mutex};

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

impl Serializer for ApplicationData {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_string()?;
        let name = reader.read_string()?;
        let description = reader.read_string()?;
        let url = Option::read(reader)?;
        let permissions = IndexSet::read(reader)?;

        Ok(Self {
            id,
            name,
            description,
            url,
            permissions
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.id.write(writer);
        self.name.write(writer);
        self.description.write(writer);
        self.url.write(writer);
        self.permissions.write(writer);
    }
}

pub type EncryptionKey = [u8; 32];

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(tag = "mode")]
pub enum EncryptionMode {
    // Encrypt the data using AES-GCM
    #[serde(rename = "aes")]
    AES {
        key: EncryptionKey
    },
    // Encrypt the data using ChaCha20Poly1305 AEAD cipher
    #[serde(rename = "chacha20poly1305")]
    Chacha20Poly1305 {
        key: EncryptionKey
    }
}

impl Serializer for EncryptionMode {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let mode = reader.read_u8()?;
        match mode {
            0 => Ok(Self::AES { key: reader.read_bytes(32)? }),
            1 => Ok(Self::Chacha20Poly1305 { key: reader.read_bytes(32)? }),
            _ => Err(ReaderError::InvalidValue)
        }
    }

    fn write(&self, writer: &mut Writer) {
        match self {
            Self::AES { key } => {
                writer.write_u8(0);
                key.write(writer);
            }
            Self::Chacha20Poly1305 { key } => {
                writer.write_u8(1);
                key.write(writer);
            }
        }
    }

    fn size(&self) -> usize {
        1 + 32 // 1 byte for mode + 32 bytes for key
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApplicationDataRelayer {
    // Actual application data
    pub app_data: ApplicationData,
    // Relayer URL where we should connect
    // to communicate with the application
    pub relayer: String,
    // Encryption mode to use for the relayer
    pub encryption_mode: Option<EncryptionMode>,
}

impl Serializer for ApplicationDataRelayer {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let app_data = ApplicationData::read(reader)?;
        let n = reader.read_u16()?;
        let relayer = reader.read_string_with_size(n as _)?;
        let encryption_mode = Option::read(reader)?;
        Ok(Self {
            app_data,
            relayer,
            encryption_mode
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.app_data.write(writer);

        let bytes = self.relayer.as_bytes();
        writer.write_u16(bytes.len() as u16);
        bytes.write(writer);

        self.encryption_mode.write(writer);
    }
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

// Optional internal RPC method used by XSWD
// To request in one time the permissions
// example: balance, tracked assets etc is grouped into one
// modal that propose to the user to set them in "always allow"
#[derive(Serialize, Deserialize)]
pub struct InternalPrefetchPermissions {
    // Description to be shown to the user
    pub reason: Option<String>,
    // Request these permissions in advance
    pub permissions: IndexSet<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_mode_serialization() {
        let aes_mode = EncryptionMode::AES {
            key: [0; 32]
        };
        let serialized = serde_json::to_string(&aes_mode).unwrap();
        let deserialized: EncryptionMode = serde_json::from_str(&serialized).unwrap();
        assert_eq!(aes_mode, deserialized);
    }
}