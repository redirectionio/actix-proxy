use crate::forwarder::ForwardError;
use actix_http::StatusCode;
use actix_web::{Error as ActixError, ResponseError};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ProxyError {
    CannotReadRequestBody(ActixError),
    ForwardError(ForwardError),
    NoPeer,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotReadRequestBody(e) => write!(f, "error when reading request body: {}", e),
            Self::ForwardError(e) => write!(f, "error when forwarding request: {}", e),
            Self::NoPeer => f.write_str("no peer found"),
        }
    }
}

impl Error for ProxyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CannotReadRequestBody(err) => Some(err),
            Self::ForwardError(err) => Some(err),
            Self::NoPeer => None,
        }
    }
}

impl ResponseError for ProxyError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::CannotReadRequestBody(err) => err.as_response_error().status_code(),
            Self::ForwardError(err) => err.status_code(),
            Self::NoPeer => StatusCode::NOT_FOUND,
        }
    }
}
