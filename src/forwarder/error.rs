use actix_http::StatusCode;
use actix_web::ResponseError;
use std::{error::Error, fmt};

/// Errors that can result from using a connector service.
#[derive(Debug)]
pub enum ForwardError {
    /// Failed to build a request from origin
    UriError(actix_web::http::Error),
    /// Failed to connect to upstream
    ConnectUpstreamError(awc::error::ConnectError),
    /// Failed to send request to upstream
    SendRequestUpstreamError(awc::error::SendRequestError),
    /// Failed to read body
    ReadBodyError(actix_web::error::Error),
    /// Body is too large
    BodyTooLarge(actix_http::body::BodyLimitExceeded),
}

impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UriError(_) => f.write_str("could not build request from origin"),
            Self::ConnectUpstreamError(_) => f.write_str("cannot connect to upstream"),
            Self::SendRequestUpstreamError(e) => write!(f, "cannot send request to upstream: {}", e),
            Self::ReadBodyError(_) => f.write_str("cannot read body"),
            Self::BodyTooLarge(_) => f.write_str("body is too large"),
        }
    }
}

impl Error for ForwardError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UriError(err) => Some(err),
            Self::ConnectUpstreamError(err) => Some(err),
            Self::SendRequestUpstreamError(err) => Some(err),
            Self::ReadBodyError(err) => Some(err),
            Self::BodyTooLarge(err) => Some(err),
        }
    }
}

impl ResponseError for ForwardError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UriError(_) => StatusCode::BAD_REQUEST,
            Self::ConnectUpstreamError(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::SendRequestUpstreamError(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::ReadBodyError(_) => StatusCode::BAD_REQUEST,
            Self::BodyTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }
}
