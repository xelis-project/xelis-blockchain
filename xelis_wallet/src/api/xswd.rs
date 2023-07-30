use log::info;

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
    
}

impl XSWD {
    pub async fn stop(&self) {
        info!("Stopping XSWD...");
    }
}