use std::{sync::Arc, collections::HashMap};
use async_trait::async_trait;
use actix_web::{get, web::{Data, Payload}, HttpRequest, Responder, HttpServer, App, dev::ServerHandle, HttpResponse};
use log::info;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use xelis_common::{rpc_server::{RPCHandler, websocket::{WebSocketHandler, WebSocketSessionShared, WebSocketServer}, RpcRequest, RpcResponseError, InternalRpcError}, crypto::key::Signature};
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
    handle: ServerHandle
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApplicationData {
    // Application ID
    pub id: [u8; 32],
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

impl XSWD {
    pub fn new(wallet: Arc<Wallet>) -> Result<Self, anyhow::Error> {
        info!("Starting XSWD Server...");
        let mut rpc_handler = RPCHandler::new(wallet);
        rpc::register_methods(&mut rpc_handler);

        let websocket = WebSocketServer::new(XSWDWebSocketHandler::new(rpc_handler));
        let http_server = HttpServer::new(move || {
            let server = Arc::clone(&websocket);
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
            handle
        })
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

#[derive(PartialEq, Eq)]
pub enum PermissionResult {
    Accept,
    Deny,
    AcceptAlways,
    DenyAlways
}

struct XSWDWebSocketHandler {
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

    async fn verify_permission_for_request(&self, app: &mut ApplicationData, request: &RpcRequest) -> Result<(), RpcResponseError> {
        let permission = app.permissions.get(&request.method).map(|v| *v).unwrap_or(Permission::Ask);
        match permission {
            // Request permission from user
            Permission::Ask => {
                let result = self.handler.get_data()
                .request_permission(app, request).await
                .map_err(|msg| RpcResponseError::new(request.id.clone(), InternalRpcError::Custom(msg.to_string())))?;

                match result {
                    PermissionResult::Accept => Ok(()),
                    PermissionResult::Deny => Err(RpcResponseError::new(request.id.clone(), InternalRpcError::Custom("Permission denied".into()))),
                    PermissionResult::AcceptAlways => {
                        app.permissions.insert(request.method.clone(), Permission::AcceptAlways);
                        Ok(())
                    },
                    PermissionResult::DenyAlways => {
                        app.permissions.insert(request.method.clone(), Permission::AcceptAlways);
                        Err(RpcResponseError::new(request.id.clone(), InternalRpcError::Custom("Permission denied".into())))
                    }   
                }
            }
            // User has already accepted this method
            Permission::AcceptAlways => Ok(()),
            // User has denied access to this method
            Permission::DenyAlways => Err(RpcResponseError::new(request.id.clone(), InternalRpcError::Custom("Permission denied".into())))
        }
    }

    async fn on_message_internal(&self, session: &WebSocketSessionShared<Self>, message: &[u8]) -> Result<Value, RpcResponseError> {
        let mut applications = self.applications.lock().await;

        // Application is already registered, call the method
        if let Some(app) = applications.get_mut(session) {
            let request: RpcRequest = self.handler.parse_request(message)?;
            self.verify_permission_for_request(app, &request).await?;

            Ok(match self.handler.execute_method(request).await {
                Ok(result) => result,
                Err(e) => e.to_json(),
            })
        } else {
            // Application is not registered, register it
            let app_data: ApplicationData = serde_json::from_slice::<ApplicationData>(&message).map_err(|_| RpcResponseError::new(None, InternalRpcError::Custom("Invalid JSON format for application data".into())))?;
            // Sanity check
            {
                if app_data.name.len() > 32 {
                    return Err(RpcResponseError::new(None, InternalRpcError::Custom("Application name is too long".into())))
                }
        
                if app_data.description.len() > 256 {
                    return Err(RpcResponseError::new(None, InternalRpcError::Custom("Application description is too long".into())))
                }
        
                if let Some(url) = &app_data.url {
                    if url.len() > 256 {
                        return Err(RpcResponseError::new(None, InternalRpcError::Custom("Application URL is too long".into())))
                    }
                }

                if app_data.permissions.len() != 0 && app_data.signature.is_none() {
                    return Err(RpcResponseError::new(None, InternalRpcError::Custom("Application permissions are not signed".into())))
                }

                if app_data.permissions.len() > 256 {
                    return Err(RpcResponseError::new(None, InternalRpcError::Custom("Too many permissions".into())))
                }
            }

            // TODO verify signature of application data

            applications.insert(session.clone(), app_data);
            Ok(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "result": true
            }))
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

    async fn on_connection(&self, _: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn on_message(&self, session: &WebSocketSessionShared<Self>, message: &[u8]) -> Result<(), anyhow::Error> {
        let response: Value = match self.on_message_internal(session, message).await {
            Ok(result) => result,
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
    let response = server.handle_connection(&request, body).await?;
    Ok(response)
}