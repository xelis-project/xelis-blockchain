use actix_web::{dev::RequestHead, http::{Uri, header::HeaderMap}};
use reqwest::{Method, Version};
use actix_web::HttpRequest as ActixHttpRequest;

// Copy of actix_web::HttpRequest
// Its done to Copy it & save it in WebSocketSession
pub struct HttpRequest {
    head: RequestHead
}

impl HttpRequest {
    #[inline]
    pub fn head(&self) -> &RequestHead {
        &self.head
    }

    /// Request's uri.
    #[inline]
    pub fn uri(&self) -> &Uri {
        &self.head().uri
    }

    /// Read the Request method.
    #[inline]
    pub fn method(&self) -> &Method {
        &self.head().method
    }

    /// Read the Request Version.
    #[inline]
    pub fn version(&self) -> Version {
    self.head().version
    }

    #[inline]
    /// Returns request's headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.head().headers
    }
}

impl From<ActixHttpRequest> for HttpRequest {
    fn from(req: ActixHttpRequest) -> Self {
        Self {
            head: req.head().clone()
        }
    }
}