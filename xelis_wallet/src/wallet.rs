use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::Path,
    sync::Arc
};
use anyhow::{Error, Context};
use serde::Serialize;
use tokio::sync::{
    broadcast::{
        Sender as BroadcastSender,
        Receiver as BroadcastReceiver
    },
    Mutex,
    RwLock
};
use xelis_common::{
    api::{
        wallet::{
            BalanceChanged,
            NotifyEvent,
            TransactionEntry
        },
        DataElement
    },
    asset::AssetWithData,
    crypto::{
        ecdlp::{self, ECDLPTablesFileView},
        elgamal::{Ciphertext, DecryptHandle, PublicKey as DecompressedPublicKey},
        Address,
        Hash,
        KeyPair,
        PublicKey,
        Signature
    },
    network::Network,
    serializer::Serializer,
    transaction::{
        aead::{self, AEADCipher},
        builder::{
            FeeBuilder,
            TransactionBuilder,
            TransactionTypeBuilder
        },
        Reference,
        Transaction
    },
    utils::{
        format_coin,
        format_xelis
    }
};
use crate::{
    cipher::Cipher,
    config::{
        PASSWORD_ALGORITHM,
        PASSWORD_HASH_SIZE,
        SALT_SIZE
    },
    daemon_api::DaemonAPI,
    mnemonics,
    network_handler::{
        NetworkError,
        NetworkHandler,
        SharedNetworkHandler
    },
    storage::{
        EncryptedStorage,
        Storage
    },
    transaction_builder::{EstimateFeesState, TransactionBuilderState}
};
use chacha20poly1305::{
    aead::OsRng,
    Error as CryptoError
};
use rand::RngCore;
use thiserror::Error;
use log::{
    trace,
    debug,
    error,
    info
};

#[cfg(feature = "api_server")]
use {
    serde_json::{json, Value},
    async_trait::async_trait,
    crate::api::{
        XSWDNodeMethodHandler,
        register_rpc_methods,
        XSWD,
        WalletRpcServer,
        AuthConfig,
        APIServer,
        AppStateShared,
        PermissionResult,
        PermissionRequest,
        XSWDPermissionHandler
    },
    xelis_common::rpc_server::{
        RPCHandler,
        RpcRequest,
        InternalRpcError,
        RpcResponseError,
        JSON_RPC_VERSION
    },
    tokio::sync::{
        mpsc::{UnboundedSender, UnboundedReceiver, unbounded_channel},
        oneshot::{Sender as OneshotSender, channel}
    }
};

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Transaction too big: {} bytes, max is {} bytes", _0, _1)]
    TransactionTooBig(usize, usize),
    #[error("Invalid key pair")]
    InvalidKeyPair,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Expected a TX")]
    ExpectedOneTx,
    #[error("Too many txs included max is {}", u8::MAX)]
    TooManyTx,
    #[error("Transaction owner is the receiver")]
    TxOwnerIsReceiver,
    #[error("Error from crypto: {}", _0)]
    CryptoError(CryptoError),
    #[error("Unexpected error on database: {}", _0)]
    DatabaseError(#[from] sled::Error),
    #[error("Invalid encrypted value: minimum 25 bytes")]
    InvalidEncryptedValue,
    #[error("No salt found in storage")]
    NoSalt,
    #[error("Error while hashing: {}", _0)]
    AlgorithmHashingError(String),
    #[error("Error while fetching encrypted master key from DB")]
    NoMasterKeyFound,
    #[error("Invalid salt size stored in storage, expected 32 bytes")]
    InvalidSaltSize,
    #[error("Error while fetching password salt from DB")]
    NoSaltFound,
    #[error("Your wallet contains only {} instead of {} for asset {}", format_coin(*_0, *_2), format_coin(*_1, *_2), _3)]
    NotEnoughFunds(u64, u64, u8, Hash),
    #[error("Your wallet don't have enough funds to pay fees: expected {} but have only {}", format_xelis(*_0), format_xelis(*_1))]
    NotEnoughFundsForFee(u64, u64),
    #[error("Invalid address params")]
    InvalidAddressParams,
    #[error("Invalid extra data in this transaction, expected maximum {} bytes but got {} bytes", _0, _1)]
    ExtraDataTooBig(usize, usize),
    #[error("Wallet is not in online mode")]
    NotOnlineMode,
    #[error("Wallet is already in online mode")]
    AlreadyOnlineMode,
    #[error("Asset is already present on disk")]
    AssetAlreadyRegistered,
    #[error("Topoheight is too high to rescan")]
    RescanTopoheightTooHigh,
    #[error(transparent)]
    Any(#[from] Error),
    #[error("No API Server is running")]
    NoAPIServer,
    #[error("RPC Server is not running")]
    RPCServerNotRunning,
    #[error("RPC Server is already running")]
    RPCServerAlreadyRunning,
    #[error("Invalid fees provided, minimum fees calculated: {}, provided: {}", format_xelis(*_0), format_xelis(*_1))]
    InvalidFeeProvided(u64, u64),
    #[error("Wallet name cannot be empty")]
    EmptyName,
    #[error("No handler available for this request")]
    NoHandlerAvailable,
    #[error(transparent)]
    NetworkError(#[from] NetworkError),
    #[error("Balance for asset {} was not found", _0)]
    BalanceNotFound(Hash),
    #[error("No result found for ciphertext")]
    CiphertextDecode,
    #[error(transparent)]
    AEADCipherFormatError(#[from] aead::CipherFormatError),
}

#[derive(Serialize, Clone)]
#[serde(untagged)]
pub enum Event {
    // When a TX is detected from daemon and is added in wallet storage
    NewTransaction(TransactionEntry),
    // When a new block is detected from daemon
    // NOTE: Same topoheight can be broadcasted several times if DAG reorg it
    // And some topoheight can be skipped because of DAG reorg
    // Example: two blocks at same height, both got same topoheight 69, next block reorg them together
    // and one of the block get topoheight 69, the other 70, next is 71, but 70 is skipped
    NewTopoHeight {
        topoheight: u64
    },
    // When a balance change occurs on wallet
    BalanceChanged(BalanceChanged),
    // When a new asset is added to wallet
    NewAsset(AssetWithData),
    // When a rescan happened (because of user request or DAG reorg/fork)
    // Value is topoheight until it deleted transactions
    // Next sync will restart at this topoheight
    Rescan {
        start_topoheight: u64   
    },
    // Wallet is now in online mode
    Online,
    // Wallet is now in offline mode
    Offline
}

impl Event {
    pub fn kind(&self) -> NotifyEvent {
        match self {
            Event::NewTransaction(_) => NotifyEvent::NewTransaction,
            Event::NewTopoHeight { .. } => NotifyEvent::NewTopoHeight,
            Event::BalanceChanged(_) => NotifyEvent::BalanceChanged,
            Event::NewAsset(_) => NotifyEvent::NewAsset,
            Event::Rescan { .. } => NotifyEvent::Rescan,
            Event::Online => NotifyEvent::Online,
            Event::Offline => NotifyEvent::Offline
        }
    }

}

// This is a 32 bytes aligned struct
// It is necessary for the precomputed tables points
#[derive(bytemuck::Pod, bytemuck::Zeroable, Copy, Clone)]
#[repr(C, align(32))]
struct Bytes32Alignment([u8; 32]);

pub struct PrecomputedTables {
    bytes: Vec<Bytes32Alignment>,
    l1: usize,
    bytes_count: usize,
}

// Allows to be used in several wallets at the same time
pub type PrecomputedTablesShared = Arc<PrecomputedTables>;

impl PrecomputedTables {
    pub fn new(l1: usize) -> Self {
        let bytes_count = ecdlp::table_generation::table_file_len(l1);
        debug!("Precomputed tables size: {} bytes", bytes_count);
        let mut n = bytes_count / 32;
        if bytes_count % 32 != 0 {
            n += 1;
        }

        let bytes = vec![Bytes32Alignment([0; 32]); n];

        Self {
            bytes,
            l1,
            bytes_count
        }
    }

    pub fn get<'a>(&'a self) -> &'a [u8] {
       &bytemuck::cast_slice(self.bytes.as_slice())[..self.bytes_count]
    }

    pub fn get_mut<'a>(&'a mut self) -> &'a mut [u8] {
        &mut bytemuck::cast_slice_mut(self.bytes.as_mut_slice())[..self.bytes_count]
    }

    pub fn l1(&self) -> usize {
        self.l1
    }

    pub fn bytes_count(&self) -> usize {
        self.bytes_count
    }
}

pub const PRECOMPUTED_TABLES_L1: usize = 26;

pub struct Wallet {
    // Encrypted Wallet Storage
    storage: RwLock<EncryptedStorage>,
    // Private & Public key linked for this wallet
    keypair: KeyPair,
    // Compressed public key
    public_key: PublicKey,
    // network handler for online mode to keep wallet synced
    network_handler: Mutex<Option<SharedNetworkHandler>>,
    // network on which we are connected
    network: Network,
    // RPC Server
    #[cfg(feature = "api_server")]
    api_server: Mutex<Option<APIServer<Arc<Self>>>>,
    // All XSWD requests are routed through this channel
    #[cfg(feature = "api_server")]
    xswd_channel: RwLock<Option<UnboundedSender<XSWDEvent>>>,
    // Event broadcaster
    event_broadcaster: Mutex<Option<BroadcastSender<Event>>>,
    // Precomputed tables byte array
    precomputed_tables: PrecomputedTablesShared
}

pub fn hash_password(password: String, salt: &[u8]) -> Result<[u8; PASSWORD_HASH_SIZE], WalletError> {
    let mut output = [0; PASSWORD_HASH_SIZE];
    PASSWORD_ALGORITHM.hash_password_into(password.as_bytes(), salt, &mut output).map_err(|e| WalletError::AlgorithmHashingError(e.to_string()))?;
    Ok(output)
}

impl Wallet {
    // This will read from file if exists, or generate and store it in file
    // This must be call only one time, and can be cloned to be shared through differents wallets
    pub fn read_or_generate_precomputed_tables<P: ecdlp::ProgressTableGenerationReportFunction>(path: Option<String>, progress_report: P) -> Result<PrecomputedTablesShared, Error> {
        const N: usize = PRECOMPUTED_TABLES_L1;
        let mut precomputed_tables = PrecomputedTables::new(N);

        if let Some(path) = path.as_ref() {
            let path = Path::new(&path);
            if !path.exists() {
                create_dir_all(path)?;
            }
        }
        let path = path.unwrap_or_default();

        // Try to read from file
        if let Ok(mut file) = File::open(format!("{path}precomputed_tables_{N}.bin")) {
            info!("Reading precomputed tables from file");
            file.read_exact(precomputed_tables.get_mut())?;
        } else {
            // File does not exists, generate and store it
            info!("Generating precomputed tables");
            ecdlp::table_generation::create_table_file_with_progress_report(N, precomputed_tables.get_mut(), progress_report)?;
            File::create(format!("{path}precomputed_tables_{N}.bin"))?.write_all(precomputed_tables.get())?;
        }

        Ok(Arc::new(precomputed_tables))
    }

    // Create a new wallet with the specificed storage, keypair and its network
    fn new(storage: EncryptedStorage, keypair: KeyPair, network: Network, precomputed_tables: PrecomputedTablesShared) -> Arc<Self> {
        let zelf = Self {
            storage: RwLock::new(storage),
            public_key: keypair.get_public_key().compress(),
            keypair,
            network_handler: Mutex::new(None),
            network,
            #[cfg(feature = "api_server")]
            api_server: Mutex::new(None),
            #[cfg(feature = "api_server")]
            xswd_channel: RwLock::new(None),
            event_broadcaster: Mutex::new(None),
            precomputed_tables
        };

        Arc::new(zelf)
    }

    // Create a new wallet on disk
    pub fn create(name: String, password: String, seed: Option<String>, network: Network, precomputed_tables: PrecomputedTablesShared) -> Result<Arc<Self>, Error> {
        if name.is_empty() {
            return Err(WalletError::EmptyName.into())
        }

        // generate random keypair or recover it from seed
        let keypair = if let Some(seed) = seed {
        debug!("Retrieving keypair from seed...");
        let words: Vec<String> = seed.split_whitespace().map(str::to_string).collect();
        let key = mnemonics::words_to_key(&words)?;
            KeyPair::from_private_key(key)
        } else {
            debug!("Generating a new keypair...");
            KeyPair::new()
        };

        // generate random salt for hashed password
        let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);

        // generate hashed password which will be used as key to encrypt master_key
        debug!("hashing provided password");
        let hashed_password = hash_password(password, &salt)?;

        debug!("Creating storage for {}", name);
        let mut inner = Storage::new(name)?;

        // generate the Cipher
        let cipher = Cipher::new(&hashed_password, None)?;

        // save the salt used for password
        debug!("Save password salt in public storage");
        inner.set_password_salt(&salt)?;

        // generate the master key which is used for storage and then save it in encrypted form
        let mut master_key: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut master_key);
        let encrypted_master_key = cipher.encrypt_value(&master_key)?;
        debug!("Save encrypted master key in public storage");
        inner.set_encrypted_master_key(&encrypted_master_key)?;
        
        // generate the storage salt and save it in encrypted form
        let mut storage_salt = [0; SALT_SIZE];
        OsRng.fill_bytes(&mut storage_salt);
        let encrypted_storage_salt = cipher.encrypt_value(&storage_salt)?;
        inner.set_encrypted_storage_salt(&encrypted_storage_salt)?;

        debug!("Creating encrypted storage");
        let mut storage = EncryptedStorage::new(inner, &master_key, storage_salt, network)?;

        // Store the private key
        storage.set_private_key(&keypair.get_private_key())?;

        Ok(Self::new(storage, keypair, network, precomputed_tables))
    }

    // Open an existing wallet on disk
    pub fn open(name: String, password: String, network: Network, precomputed_tables: PrecomputedTablesShared) -> Result<Arc<Self>, Error> {
        if name.is_empty() {
            return Err(WalletError::EmptyName.into())
        }

        debug!("Creating storage for {}", name);
        let storage = Storage::new(name)?;
        
        // get password salt for KDF
        debug!("Retrieving password salt from public storage");
        let salt = storage.get_password_salt()?;

        // retrieve encrypted master key from storage
        debug!("Retrieving encrypted master key from public storage");
        let encrypted_master_key = storage.get_encrypted_master_key()?;

        let hashed_password = hash_password(password, &salt)?;

        // decrypt the encrypted master key using the hashed password (used as key)
        let cipher = Cipher::new(&hashed_password, None)?;
        let master_key = cipher.decrypt_value(&encrypted_master_key).context("Invalid password provided for this wallet")?;

        // Retrieve the encrypted storage salt
        let encrypted_storage_salt = storage.get_encrypted_storage_salt()?;
        let storage_salt = cipher.decrypt_value(&encrypted_storage_salt).context("Invalid encrypted storage salt for this wallet")?;
        if storage_salt.len() != SALT_SIZE {
            error!("Invalid size received after decrypting storage salt: {} bytes", storage_salt.len());
            return Err(WalletError::InvalidSaltSize.into());
        }

        let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
        salt.copy_from_slice(&storage_salt);

        debug!("Creating encrypted storage");
        let storage = EncryptedStorage::new(storage, &master_key, salt, network)?;
        debug!("Retrieving private key from encrypted storage");
        let private_key =  storage.get_private_key()?;
        let keypair = KeyPair::from_private_key(private_key);

        Ok(Self::new(storage, keypair, network, precomputed_tables))
    }

    // Close the wallet
    // this will stop the network handler and the API Server if it's running
    // Because wallet is behind Arc, we need to close differents modules that has a copy of it
    pub async fn close(&self) {
        trace!("Closing wallet");

        #[cfg(feature = "api_server")]
        {
            // Close API server
            {
                let mut lock = self.api_server.lock().await;
                if let Some(server) = lock.take() {
                    server.stop().await;
                }
            }

            // Close XSWD channel in case it exists
            {
                let mut lock = self.xswd_channel.write().await;
                if let Some(sender) = lock.take() {
                    drop(sender);
                }
            }
        }

        // Stop gracefully the network handler
        {
            let mut lock = self.network_handler.lock().await;
            if let Some(handler) = lock.take() {
                if let Err(e) = handler.stop().await {
                    error!("Error while stopping network handler: {}", e);
                }
            }
        }

        // Stop gracefully the storage
        {
            let mut storage = self.storage.write().await;
            storage.stop().await;
        }

        // Close the event broadcaster
        // So all subscribers will be notified
        self.close_events_channel().await;
    }

    // Propagate a new event to registered listeners
    pub async fn propagate_event(&self, event: Event) {
        // Broadcast it to the API Server
        #[cfg(feature = "api_server")]
        {
            let mut lock = self.api_server.lock().await;
            if let Some(server) = lock.as_mut() {
                let kind = event.kind();
                server.notify_event(&kind, &event).await;
            }
        }

        // Broadcast to the event broadcaster
        {
            let mut lock = self.event_broadcaster.lock().await;
            if let Some(broadcaster) = lock.as_ref() {
                // if the receiver is closed, we remove it
                if broadcaster.send(event).is_err() {
                    lock.take();
                }
            }
        }
    }

    // Subscribe to events
    pub async fn subscribe_events(&self) -> BroadcastReceiver<Event> {
        let mut broadcaster = self.event_broadcaster.lock().await;
        match broadcaster.as_ref() {
            Some(broadcaster) => broadcaster.subscribe(),
            None => {
                let (sender, receiver) = tokio::sync::broadcast::channel(10);
                *broadcaster = Some(sender);
                receiver
            }
        }
    }

    // Close events channel
    // This will disconnect all subscribers
    pub async fn close_events_channel(&self) -> bool {
        trace!("Closing events channel");
        let mut broadcaster = self.event_broadcaster.lock().await;
        broadcaster.take().is_some()
    }

    // Enable RPC Server with requested authentication and bind address
    #[cfg(feature = "api_server")]
    pub async fn enable_rpc_server(self: &Arc<Self>, bind_address: String, config: Option<AuthConfig>) -> Result<(), Error> {
        let mut lock = self.api_server.lock().await;
        if lock.is_some() {
            return Err(WalletError::RPCServerAlreadyRunning.into())
        }
        let mut rpc_handler = RPCHandler::new(self.clone());
        register_rpc_methods(&mut rpc_handler);

        let rpc_server = WalletRpcServer::new(bind_address, rpc_handler, config).await?;
        *lock = Some(APIServer::RPCServer(rpc_server));
        Ok(())
    }

    // Enable XSWD Protocol
    #[cfg(feature = "api_server")]
    pub async fn enable_xswd(self: &Arc<Self>) -> Result<UnboundedReceiver<XSWDEvent>, Error> {
        let receiver = {
            let (sender, receiver) = unbounded_channel();
            let mut channel = self.xswd_channel.write().await;
            *channel = Some(sender);
            receiver
        };

        let mut lock = self.api_server.lock().await;
        if lock.is_some() {
            return Err(WalletError::RPCServerAlreadyRunning.into())
        }
        let mut rpc_handler = RPCHandler::new(self.clone());
        register_rpc_methods(&mut rpc_handler);

        *lock = Some(APIServer::XSWD(XSWD::new(rpc_handler)?));
        Ok(receiver)
    }

    #[cfg(feature = "api_server")]
    pub async fn stop_api_server(&self) -> Result<(), Error> {
        let mut lock = self.api_server.lock().await;
        let rpc_server = lock.take().ok_or(WalletError::RPCServerNotRunning)?;
        rpc_server.stop().await;
        Ok(())
    }

    #[cfg(feature = "api_server")]
    pub fn get_api_server<'a>(&'a self) -> &Mutex<Option<APIServer<Arc<Self>>>> {
        &self.api_server
    }

    // Verify if a password is valid or not
    pub async fn is_valid_password(&self, password: String) -> Result<(), Error> {
        let mut encrypted_storage = self.storage.write().await;
        let storage = encrypted_storage.get_mutable_public_storage();
        let salt = storage.get_password_salt()?;
        let hashed_password = hash_password(password, &salt)?;
        let cipher = Cipher::new(&hashed_password, None)?;
        let encrypted_master_key = storage.get_encrypted_master_key()?;
        let _ = cipher.decrypt_value(&encrypted_master_key).context("Invalid password provided")?;
        Ok(())
    }

    // change the current password wallet to a new one
    pub async fn set_password(&self, old_password: String, password: String) -> Result<(), Error> {
        let mut encrypted_storage = self.storage.write().await;
        let storage = encrypted_storage.get_mutable_public_storage();
        let (master_key, storage_salt) = {
            // retrieve old salt to build key from current password
            let salt = storage.get_password_salt()?;
            let hashed_password = hash_password(old_password, &salt)?;

            let encrypted_master_key = storage.get_encrypted_master_key()?;
            let encrypted_storage_salt = storage.get_encrypted_storage_salt()?;

            // decrypt the encrypted master key using the provided password
            let cipher = Cipher::new(&hashed_password, None)?;
            let master_key = cipher.decrypt_value(&encrypted_master_key).context("Invalid password provided")?;
            let storage_salt = cipher.decrypt_value(&encrypted_storage_salt)?;
            (master_key, storage_salt)
        };

        // generate a new salt for password
        let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);

        // generate the password-based derivated key to encrypt the master key
        let hashed_password = hash_password(password, &salt)?;
        let cipher = Cipher::new(&hashed_password, None)?;

        // encrypt the master key using the new password
        let encrypted_key = cipher.encrypt_value(&master_key)?;

        // encrypt the salt with the new password
        let encrypted_storage_salt = cipher.encrypt_value(&storage_salt)?;

        // save on disk
        storage.set_password_salt(&salt)?;
        storage.set_encrypted_master_key(&encrypted_key)?;
        storage.set_encrypted_storage_salt(&encrypted_storage_salt)?;

        Ok(())
    }

    // Wallet has to be under a Arc to be shared to the spawn_blocking function
    pub async fn decrypt_ciphertext(self: Arc<Self>, ciphertext: Ciphertext) -> Result<u64, WalletError> {
        trace!("decrypt ciphertext");
        tokio::task::spawn_blocking(move || {
            let view = ECDLPTablesFileView::<PRECOMPUTED_TABLES_L1>::from_bytes(self.precomputed_tables.get());
            self.keypair.get_private_key()
                .decrypt(&view, &ciphertext)
                .ok_or(WalletError::CiphertextDecode)
        }).await.context("Error while decrypting ciphertext")?
    }

    // Decrypt the extra data from a transfer
    pub fn decrypt_extra_data(&self, cipher: AEADCipher, handle: &DecryptHandle) -> Result<DataElement, WalletError> {
        trace!("decrypt extra data");
        let key = aead::derive_aead_key_from_handle(&self.keypair.get_private_key(), handle);
        let plaintext = cipher.decrypt_in_place(&key)?;
        DataElement::from_bytes(&plaintext.0).map_err(|_| WalletError::CiphertextDecode)
    }

    // Create a transaction with the given transaction type and fee
    // this will apply the changes to the storage if the transaction
    pub async fn create_transaction(&self, transaction_type: TransactionTypeBuilder, fee: FeeBuilder) -> Result<Transaction, WalletError> {
        trace!("create transaction");
        let mut storage = self.storage.write().await;
        let (mut state, transaction) = self.create_transaction_with_storage(&mut storage, transaction_type, fee).await?;

        state.apply_changes(&mut storage).await?;

        Ok(transaction)
    }

    // create the final transaction with calculated fees and signature
    // also check that we have enough funds for the transaction
    // This will returns the transaction builder state along the transaction
    // You must handle "apply changes" to the storage
    pub async fn create_transaction_with_storage(&self, storage: &mut EncryptedStorage, transaction_type: TransactionTypeBuilder, fee: FeeBuilder) -> Result<(TransactionBuilderState, Transaction), WalletError> {
        trace!("create transaction with storage");
        let nonce = storage.get_nonce().unwrap_or(0);

        // Build the state for the builder
        let used_assets = transaction_type.used_assets();

        // state used to build the transaction
        let mut state = TransactionBuilderState::new(
            self.network.is_mainnet(),
            Reference {
                topoheight: storage.get_synced_topoheight()?,
                hash: storage.get_top_block_hash()?
            },
            nonce
        );

        // Get all balances used
        for asset in used_assets {
            trace!("Checking balance for asset {}", asset);
            if !storage.has_balance_for(&asset).await? {
                return Err(WalletError::BalanceNotFound(asset));
            }

            let balance = storage.get_unconfirmed_balance_for(&asset).await?;
            state.add_balance(asset, balance);
        }

        // To pay exact fees needed, we must verify that we don't have to pay more than needed
        let used_keys = transaction_type.used_keys();
        if !used_keys.is_empty() {
            trace!("Checking if destination keys are registered");
            if let Some(network_handler) = self.network_handler.lock().await.as_ref() {
                if network_handler.is_running().await {
                    trace!("Network handler is running, checking if keys are registered");
                    for key in used_keys {
                        let addr = key.to_address(self.network.is_mainnet());
                        trace!("Checking if {} is registered in stable height", addr);
                        if network_handler.get_api().is_account_registered(&addr, true).await? {
                            state.add_registered_key(addr.to_public_key());
                        }
                    }
                }
            }
        }

        // Create the transaction builder
        let builder = TransactionBuilder::new(0, self.public_key.clone(), transaction_type, fee);

        // Build the final transaction
        let transaction = builder.build(&mut state, &self.keypair)
            .map_err(|e| WalletError::Any(e.into()))?;

        Ok((state, transaction))
    }

    // submit a transaction to the network through the connection to daemon
    // It will increase the local nonce by 1 if the TX is accepted by the daemon
    // returns error if the wallet is in offline mode or if the TX is rejected
    pub async fn submit_transaction(&self, transaction: &Transaction) -> Result<(), WalletError> {
        trace!("submit transaction");
        let network_handler = self.network_handler.lock().await;
        if let Some(network_handler) = network_handler.as_ref() {
            network_handler.get_api().submit_transaction(transaction).await?;
            Ok(())
        } else {
            Err(WalletError::NotOnlineMode)
        }
    }

    // Estimate fees for a given transaction type
    // Estimated fees returned are the minimum required to be valid on chain
    pub async fn estimate_fees(&self, tx_type: TransactionTypeBuilder) -> Result<u64, WalletError> {
        trace!("estimate fees");
        let mut state = EstimateFeesState::new();
        let builder = TransactionBuilder::new(0, self.public_key.clone(), tx_type, FeeBuilder::default());
        let estimated_fees = builder.estimate_fees(&mut state)
            .map_err(|e| WalletError::Any(e.into()))?;

        Ok(estimated_fees)
    }

    // set wallet in online mode: start a communication task which will keep the wallet synced
    pub async fn set_online_mode(self: &Arc<Self>, daemon_address: &String) -> Result<(), WalletError> {
        trace!("Set online mode");
        if self.is_online().await {
            // user have to set in offline mode himself first
            return Err(WalletError::AlreadyOnlineMode)
        }

        // create the network handler
        let network_handler = NetworkHandler::new(Arc::clone(&self), daemon_address).await?;
        // start the task
        network_handler.start().await?;
        *self.network_handler.lock().await = Some(network_handler);

        Ok(())
    }

    // set the wallet in online mode using a shared daemon API
    // this allows to share the same connection/Daemon API across several wallets to save resources
    pub async fn set_online_mode_with_api(self: &Arc<Self>, daemon_api: Arc<DaemonAPI>) -> Result<(), WalletError> {
        trace!("Set online mode with API");
        if self.is_online().await {
            // user have to set in offline mode himself first
            return Err(WalletError::AlreadyOnlineMode)
        }

        // create the network handler
        let network_handler = NetworkHandler::with_api(Arc::clone(&self), daemon_api).await?;
        // start the task
        network_handler.start().await?;
        *self.network_handler.lock().await = Some(network_handler);

        Ok(())
    }

    // set wallet in offline mode: stop communication task if exists
    pub async fn set_offline_mode(&self) -> Result<(), WalletError> {
        trace!("Set offline mode");
        let mut handler = self.network_handler.lock().await;
        if let Some(network_handler) = handler.take() {
            network_handler.stop().await?;
        } else {
            return Err(WalletError::NotOnlineMode)
        }

        Ok(())
    }

    // rescan the wallet from the given topoheight
    // that will delete all transactions above the given topoheight and all balances
    // then it will re-fetch all transactions and balances from daemon
    pub async fn rescan(&self, topoheight: u64) -> Result<(), WalletError> {
        trace!("Rescan wallet from topoheight {}", topoheight);
        if !self.is_online().await {
            // user have to set it online
            return Err(WalletError::NotOnlineMode)
        }

        let mut storage = self.get_storage().write().await;
        if topoheight > storage.get_synced_topoheight()? {
            return Err(WalletError::RescanTopoheightTooHigh)
        }

        let handler = self.network_handler.lock().await;
        if let Some(network_handler) = handler.as_ref() {
            debug!("Stopping network handler!");
            network_handler.stop().await?;
            {
                debug!("set synced topoheight to {}", topoheight);
                storage.set_synced_topoheight(topoheight)?;
                storage.delete_top_block_hash()?;
                // balances will be re-fetched from daemon
                storage.delete_balances().await?;
                storage.delete_assets().await?;

                debug!("Retrieve current wallet nonce");
                let nonce_result = network_handler.get_api()
                    .get_nonce(&self.get_address()).await
                    // User has no transactions/balances yet, set its nonce to 0
                    .map(|v| v.version.get_nonce()).unwrap_or(0);

                storage.set_nonce(nonce_result)?;

                if topoheight == 0 {
                    debug!("Deleting all transactions for full rescan");
                    storage.delete_transactions()?;
                } else {
                    debug!("Deleting transactions above {} for partial rescan", topoheight);
                    storage.delete_transactions_above_topoheight(topoheight)?;
                }
            }
            debug!("Starting again network handler");
            network_handler.start().await.context("Error while restarting network handler")?;
        } else {
            return Err(WalletError::NotOnlineMode)
        }

        Ok(())
    }

    // Check if the wallet is in online mode
    pub async fn is_online(&self) -> bool {
        if let Some(network_handler) = self.network_handler.lock().await.as_ref() {
            network_handler.is_running().await
        } else {
            false
        }
    }

    // this function allow to user to get the network handler in case in want to stay in online mode
    // but want to pause / resume the syncing task through start/stop functions from it
    pub async fn get_network_handler(&self) -> &Mutex<Option<Arc<NetworkHandler>>> {
        &self.network_handler
    }

    // Create a signature of the given data
    pub fn sign_data(&self, data: &[u8]) -> Signature {
        self.keypair.sign(data)
    }

    // Get the public key of the wallet
    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    // Get the address of the wallet using its network used
    pub fn get_address(&self) -> Address {
        self.keypair.get_public_key().to_address(self.get_network().is_mainnet())
    }

    // Get the address with integrated data and using its network used
    pub fn get_address_with(&self, data: DataElement) -> Address {
        self.keypair.get_public_key().to_address_with(self.get_network().is_mainnet(), data)
    }

    // Returns the seed using the language index provided
    pub fn get_seed(&self, language_index: usize) -> Result<String, Error> {
        let words = mnemonics::key_to_words(self.keypair.get_private_key(), language_index)?;
        Ok(words.join(" "))
    }

    // Current account nonce for transactions
    // Nonce is used against replay attacks on-chain
    pub async fn get_nonce(&self) -> u64 {
        let storage = self.storage.read().await;
        storage.get_nonce().unwrap_or(0)
    }

    // Encrypted storage of the wallet
    pub fn get_storage(&self) -> &RwLock<EncryptedStorage> {
        &self.storage
    }

    // Network that the wallet is using
    pub fn get_network(&self) -> &Network {
        &self.network
    }
}

#[cfg(feature = "api_server")]
pub enum XSWDEvent {
    RequestPermission(AppStateShared, RpcRequest, OneshotSender<Result<PermissionResult, Error>>),
    // bool represents if it was signed or not
    RequestApplication(AppStateShared, bool, OneshotSender<Result<PermissionResult, Error>>),
    CancelRequest(AppStateShared, OneshotSender<Result<(), Error>>)
}

#[cfg(feature = "api_server")]
#[async_trait]
impl XSWDPermissionHandler for Arc<Wallet> {
    async fn request_permission(&self, app_state: &AppStateShared, request: PermissionRequest<'_>) -> Result<PermissionResult, Error> {
        if let Some(sender) = self.xswd_channel.read().await.as_ref() {
            // no other way ?
            let app_state = app_state.clone();
            // create a callback channel to receive the answer
            let (callback, receiver) = channel();
            let event = match request {
                PermissionRequest::Application(signed) => XSWDEvent::RequestApplication(app_state, signed, callback),
                PermissionRequest::Request(request) => XSWDEvent::RequestPermission(app_state, request.clone(), callback)
            };

            // Send the XSWD Message
            sender.send(event)?;

            // Wait on the callback
            return receiver.await?;
        }

        Err(WalletError::NoHandlerAvailable.into())
    }

    // there is a lock to acquire so it make it "single threaded"
    // the one who has the lock is the one who is requesting so we don't need to check and can cancel directly
    async fn cancel_request_permission(&self, app: &AppStateShared) -> Result<(), Error> {
        if let Some(sender) = self.xswd_channel.read().await.as_ref() {
            let (callback, receiver) = channel();
            // Send XSWD Message
            sender.send(XSWDEvent::CancelRequest(app.clone(), callback))?;

            // Wait on callback
            return receiver.await?;
        }

        Err(WalletError::NoHandlerAvailable.into())
    }

    async fn get_public_key(&self) -> Result<&DecompressedPublicKey, Error> {
        Ok(self.keypair.get_public_key())
    }
}

#[cfg(feature = "api_server")]
#[async_trait]
impl XSWDNodeMethodHandler for Arc<Wallet> {
    async fn call_node_with(&self, request: RpcRequest) -> Result<Value, RpcResponseError> {
        let network_handler = self.network_handler.lock().await;
        let id = request.id;
        if let Some(network_handler) = network_handler.as_ref() {
            if network_handler.is_running().await {
                let api = network_handler.get_api();
                let response = api.call(&request.method, &request.params).await.map_err(|e| RpcResponseError::new(id, InternalRpcError::Custom(e.to_string())))?;

                return Ok(json!({
                    "jsonrpc": JSON_RPC_VERSION,
                    "id": id,
                    "result": response
                }))
            }
        }

        Err(RpcResponseError::new(id, InternalRpcError::CustomStr("Wallet is not in online mode")))
    }
}