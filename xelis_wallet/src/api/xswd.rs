use std::{sync::Arc, collections::HashMap};
use async_trait::async_trait;
use actix_web::{get, web::{Data, Payload}, HttpRequest, Responder, HttpServer, App, dev::ServerHandle, HttpResponse};
use log::{info, error};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use xelis_common::{rpc_server::{RPCHandler, websocket::{WebSocketHandler, WebSocketSessionShared, WebSocketServer}, RpcRequest, RpcResponseError, InternalRpcError}, crypto::{key::{Signature, SIGNATURE_LENGTH}, hash::hash}, serializer::{Serializer, ReaderError, Reader, Writer}};
use serde::{Deserialize, Serialize};
use crate::{wallet::Wallet, config::XSWD_BIND_ADDRESS};

use super::rpc;

// XSWD Protocol (XELIS Secure WebSocket DApp)
// is a way to communicate with the XELIS Wallet
// from a web browser through a secure websocket.
// The idea is that a token is generated on websocket side
// and send through the WS connection to the wallet.
// The wallet then signs the token and send it back to the WS.
// On browser side we can save it in local storage and use it
// to communicate and request data from wallet.
// Each action will require the validation of the user
// based on the permission configured.
// The token is saved also in wallet side for a reminder of
// all applications allowed.
// For security reasons, in case the signed token leaks, at each connection,
// the wallet will request the authorization of the user
// but will keep already-configured permissions.
pub struct XSWD {
    websocket: Arc<WebSocketServer<XSWDWebSocketHandler>>,
    handle: ServerHandle
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApplicationData {
    // Application ID in hexadecimal format
    pub id: String,
    // Name of the app
    pub name: String,
    // Small description of the app
    pub description: String,
    // URL of the app if exists
    pub url: Option<String>,
    // All permissions for each method
    pub permissions: HashMap<String, Permission>,
    // signature of all data
    pub signature: Option<Signature>
}

// This serializer is only used to sign/verify a signature!
impl Serializer for ApplicationData {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_string()?;
        let name = reader.read_string()?;
        let description = reader.read_string()?;
        let url = reader.read_optional_string()?;
        let permissions_count = reader.read_u8()?;
        let mut permissions = HashMap::with_capacity(permissions_count as usize);
        for _ in 0..permissions_count {
            permissions.insert(reader.read_string()?, Permission::from_id(reader.read_u8()?).ok_or(ReaderError::InvalidValue)?);
        }

        Ok(Self {
            id,
            name,
            description,
            url,
            permissions,
            signature: None
        })
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_string(&self.id);
        writer.write_string(&self.name);
        writer.write_string(&self.description);
        writer.write_optional_string(&self.url);
        writer.write_u8(self.permissions.len() as u8);

        for (method, permission) in &self.permissions {
            writer.write_string(method);
            writer.write_u8(permission.get_id());
        }
    }
}

const PERMISSION_DENIED_ERROR: InternalRpcError = InternalRpcError::CustomStr("Permission denied");

impl XSWD {
    pub fn new(wallet: Arc<Wallet>) -> Result<Self, anyhow::Error> {
        info!("Starting XSWD Server...");
        let mut rpc_handler = RPCHandler::new(wallet);
        rpc::register_methods(&mut rpc_handler);

        let websocket = WebSocketServer::new(XSWDWebSocketHandler::new(rpc_handler));
        let cloned_websocket = websocket.clone();
        let http_server = HttpServer::new(move || {
            let server = Arc::clone(&cloned_websocket);
            App::new()
                .app_data(Data::from(server))
                .service(endpoint)
                .service(index)
        })
        .disable_signals()
        .bind(&XSWD_BIND_ADDRESS)?
        .run();

        let handle = http_server.handle();
        tokio::spawn(http_server);

        info!("XSWD is listening on ws://{}", XSWD_BIND_ADDRESS);

        Ok(Self {
            websocket,
            handle
        })
    }

    pub fn get_applications(&self) -> &XSWDWebSocketHandler {
        self.websocket.get_handler()
    }

    pub async fn stop(&self) {
        info!("Stopping XSWD...");
        self.handle.stop(false).await;
        info!("XSWD has been stopped !");
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub enum Permission {
    Ask,
    AcceptAlways,
    DenyAlways
}

impl Permission {
    pub fn get_id(&self) -> u8 {
        match self {
            Self::Ask => 0,
            Self::AcceptAlways => 1,
            Self::DenyAlways => 2
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        Some(match id {
            0 => Self::Ask,
            1 => Self::AcceptAlways,
            2 => Self::DenyAlways,
            _ => return None
        })
    }
}

pub enum PermissionRequest<'a> {
    // bool tell if it was already signed or not
    Application(bool),
    Request(&'a RpcRequest)
}

pub enum PermissionResult {
    Accept,
    Deny,
    AcceptAlways,
    DenyAlways
}

impl PermissionResult {
    pub fn is_positive(&self) -> bool {
        match self {
            Self::Accept | Self::AcceptAlways => true,
            _ => false
        }
    }
}

pub struct XSWDWebSocketHandler {
    handler: RPCHandler<Arc<Wallet>>,
    applications: Mutex<HashMap<WebSocketSessionShared<Self>, ApplicationData>>
}

impl XSWDWebSocketHandler {
    pub fn new(handler: RPCHandler<Arc<Wallet>>) -> Self {
        Self {
            handler,
            applications: Mutex::new(HashMap::new())
        }
    }

    // This method is used to get the applications HashMap
    // be careful by using it, and if you delete a session, please disconnect it
    pub fn get_applications(&self) -> &Mutex<HashMap<WebSocketSessionShared<Self>, ApplicationData>> {
        &self.applications
    }

    async fn verify_permission_for_request(&self, app: &mut ApplicationData, request: &RpcRequest) -> Result<(), RpcResponseError> {
        if !self.handler.has_method(&request.method) {
            return Err(RpcResponseError::new(request.id.clone(), InternalRpcError::Custom(format!("Method {} was not found", request.method))))
        }

        let permission = app.permissions.get(&request.method).map(|v| *v).unwrap_or(Permission::Ask);
        match permission {
            // Request permission from user
            Permission::Ask => {
                let result = self.handler.get_data()
                .request_permission(app, PermissionRequest::Request(request)).await
                .map_err(|msg| RpcResponseError::new(request.id.clone(), InternalRpcError::Custom(msg.to_string())))?;

                match result {
                    PermissionResult::Accept => Ok(()),
                    PermissionResult::Deny => Err(RpcResponseError::new(request.id.clone(), PERMISSION_DENIED_ERROR)),
                    PermissionResult::AcceptAlways => {
                        app.permissions.insert(request.method.clone(), Permission::AcceptAlways);
                        Ok(())
                    },
                    PermissionResult::DenyAlways => {
                        app.permissions.insert(request.method.clone(), Permission::AcceptAlways);
                        Err(RpcResponseError::new(request.id.clone(), PERMISSION_DENIED_ERROR))
                    }   
                }
            }
            // User has already accepted this method
            Permission::AcceptAlways => Ok(()),
            // User has denied access to this method
            Permission::DenyAlways => Err(RpcResponseError::new(request.id.clone(), PERMISSION_DENIED_ERROR))
        }
    }

    async fn add_application(&self, applications: &mut HashMap<WebSocketSessionShared<Self>, ApplicationData>, session: &WebSocketSessionShared<Self>, message: &[u8]) -> Result<Value, RpcResponseError> {
        // Application is not registered, register it
        let app_data: ApplicationData = serde_json::from_slice::<ApplicationData>(&message)
            .map_err(|_| RpcResponseError::new(None, InternalRpcError::CustomStr("Invalid JSON format for application data")))?;
        // Sanity check
        {
            if app_data.id.len() != 64 {
                return Err(RpcResponseError::new(None, InternalRpcError::CustomStr("Invalid application ID")))
            }

            hex::decode(&app_data.id)
                .map_err(|_| RpcResponseError::new(None, InternalRpcError::CustomStr("Invalid hexadecimal for application ID")))?;

            if app_data.name.len() > 32 {
                return Err(RpcResponseError::new(None, InternalRpcError::CustomStr("Application name is too long")))
            }

            if app_data.description.len() > 255 {
                return Err(RpcResponseError::new(None, InternalRpcError::CustomStr("Application description is too long")))
            }

            if let Some(url) = &app_data.url {
                if url.len() > 255 {
                    return Err(RpcResponseError::new(None, InternalRpcError::CustomStr("Application URL is too long")))
                }
            }

            if app_data.permissions.len() != 0 && app_data.signature.is_none() {
                return Err(RpcResponseError::new(None, InternalRpcError::CustomStr("Application permissions are not signed")))
            }

            if app_data.permissions.len() > 255 {
                return Err(RpcResponseError::new(None, InternalRpcError::CustomStr("Too many permissions")))
            }
        }

        let wallet = self.handler.get_data();
        // verify signature of application data
        if let Some(signature) = &app_data.signature {
            let bytes = app_data.to_bytes();
            let bytes = &bytes[0..bytes.len() - SIGNATURE_LENGTH]; // remove signature bytes for verification
            let key = wallet.get_public_key();

            if !key.verify_signature(&hash(&bytes), signature) {
                return Err(RpcResponseError::new(None, InternalRpcError::CustomStr("Invalid signature for application data")));
            }
        }

        let permission = match wallet.request_permission(&app_data, PermissionRequest::Application(app_data.signature.is_some())).await {
            Ok(v) => v,
            Err(e) => {
                error!("Error while requesting permission: {}", e);
                PermissionResult::Deny
            }
        };

        if !permission.is_positive() {
            session.get_server().delete_session(session, None).await;
            return Err(RpcResponseError::new(None, PERMISSION_DENIED_ERROR))
        }

        applications.insert(session.clone(), app_data);
        Ok(json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "result": true
        }))
    }

    async fn on_message_internal(&self, session: &WebSocketSessionShared<Self>, message: &[u8]) -> Result<Option<Value>, RpcResponseError> {
        let mut applications = self.applications.lock().await;

        // Application is already registered, verify permission and call the method
        if let Some(app) = applications.get_mut(session) {
            let request: RpcRequest = self.handler.parse_request(message)?;
            self.verify_permission_for_request(app, &request).await?;

            self.handler.execute_method(request).await.map(|v| Some(v))
        } else {
            // Application is not registered, register it
            match self.add_application(&mut applications, session, message).await.map(|v| Some(v)) {
                Ok(v) => Ok(v),
                Err(e) => {
                    // Send error message and then close the session
                    if let Err(e) = session.send_text(&e.to_json().to_string()).await {
                        error!("Error while sending error message to session: {}", e);
                    }
                    session.get_server().delete_session(&session, None).await;

                    Ok(None)
                }
            }
        }
    }
}

#[async_trait]
impl WebSocketHandler for XSWDWebSocketHandler {
    async fn on_close(&self, session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        let mut applications = self.applications.lock().await;
        if let Some(app) = applications.remove(session) {            
            info!("Application {} has disconnected", app.name);
        }

        Ok(())
    }

    async fn on_message(&self, session: &WebSocketSessionShared<Self>, message: &[u8]) -> Result<(), anyhow::Error> {
        let response: Value = match self.on_message_internal(session, message).await {
            Ok(result) => match result {
                Some(v) => v,
                None => return Ok(()),
            },
            Err(e) => e.to_json(),
        };

        session.send_text(response.to_string()).await?;
        Ok(())
    }
}

#[get("/")]
async fn index() -> Result<impl Responder, actix_web::Error> {
    Ok(HttpResponse::Ok().body("XSWD is running !"))
}

#[get("/xswd")]
async fn endpoint(server: Data<WebSocketServer<XSWDWebSocketHandler>>, request: HttpRequest, body: Payload) -> Result<impl Responder, actix_web::Error> {
    let response = server.handle_connection(request, body).await?;
    Ok(response)
}