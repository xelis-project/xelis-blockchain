use strum::IntoStaticStr;
use thiserror::Error;
use xelis_common::rpc::InternalRpcError;

#[derive(Error, Debug, Clone, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum XSWDError {
    #[error("semaphore error")]
    SemaphoreError,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Permission unknown: method wasn't mentioned during handshake")]
    PermissionUnknown,
    #[error("Application not found")]
    ApplicationNotFound,
    #[error("Invalid application data")]
    InvalidApplicationData,
    #[error("Invalid application ID")]
    InvalidApplicationId,
    #[error("Application ID already used")]
    ApplicationIdAlreadyUsed,
    #[error("Invalid hexadecimal for application ID")]
    InvalidHexaApplicationId,
    #[error("Application name is too long")]
    ApplicationNameTooLong,
    #[error("Application description is too long")]
    ApplicationDescriptionTooLong,
    #[error("Invalid URL format")]
    InvalidURLFormat,
    #[error("Invalid origin")]
    InvalidOrigin,
    #[error("Too many permissions")]
    TooManyPermissions,
    #[error("Unknown method requested in permissions list: {0}")]
    UnknownMethodInPermissionsList(String),
    #[error("Application permissions are not signed")]
    ApplicationPermissionsNotSigned,
    #[error("Invalid signature for application data")]
    InvalidSignatureForApplicationData,
}

impl From<XSWDError> for InternalRpcError {
    fn from(value: XSWDError) -> Self {
        InternalRpcError::Any {
            kind: (&value).into(),
            error: value.into()
        }
    }
}