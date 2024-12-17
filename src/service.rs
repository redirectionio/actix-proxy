use crate::error::ProxyError;
use crate::forwarder::Forwarder;
use crate::peer_resolver::HttpPeerResolver;
use actix_service::boxed::BoxService;
use actix_web::{
    body::BoxBody,
    dev::{self, Service, ServiceRequest, ServiceResponse},
    error::Error,
    FromRequest, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use std::ops::Deref;
use std::rc::Rc;

type HttpService = BoxService<ServiceRequest, ServiceResponse, Error>;
type ErrorService = BoxService<ProxyError, HttpResponse, Error>;

#[derive(Clone)]
pub struct ProxyService(pub(crate) Rc<ProxyServiceInner>);

impl Deref for ProxyService {
    type Target = ProxyServiceInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct ProxyServiceInner {
    pub(crate) forwarder: Rc<Forwarder>,
    pub(crate) peer_resolver: Rc<HttpPeerResolver>,
    pub(crate) default: Option<HttpService>,
    pub(crate) error: Option<ErrorService>,
}

impl Service<ServiceRequest> for ProxyService {
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    dev::always_ready!();

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let this = self.clone();

        Box::pin(async move {
            let origin_hostname = req
                .connection_info()
                .host()
                .split(':')
                .next()
                .unwrap_or(req.connection_info().host())
                .to_string();

            let (downstream_request_head, mut request_payload) = req.into_parts();

            let downstream_body = match actix_web::web::Payload::from_request(&downstream_request_head, &mut request_payload).await {
                Ok(payload) => payload,
                Err(err) => {
                    return match this.0.error.as_ref() {
                        Some(error) => error
                            .call(ProxyError::CannotReadRequestBody(err))
                            .await
                            .map(|response| ServiceRequest::from_request(downstream_request_head).into_response(response)),
                        None => Err(Error::from(ProxyError::CannotReadRequestBody(err))),
                    };
                }
            };

            let resolved = this
                .0
                .peer_resolver
                .call(downstream_request_head)
                .await
                .expect("cannot resolve peer, should not happen since we don't return error");

            let http_peer = match resolved.peer {
                Some(peer) => peer,
                None => match this.0.default.as_ref() {
                    Some(default) => {
                        return default.call(ServiceRequest::from_request(resolved.req)).await;
                    }
                    None => {
                        return match this.0.error.as_ref() {
                            Some(error) => error
                                .call(ProxyError::NoPeer)
                                .await
                                .map(|response| ServiceRequest::from_request(resolved.req).into_response(response)),
                            None => Err(Error::from(ProxyError::NoPeer)),
                        };
                    }
                },
            };

            let upstream_response = match this
                .0
                .forwarder
                .forward(&resolved.req, downstream_body, http_peer, origin_hostname)
                .await
            {
                Ok(response) => response,
                Err(err) => {
                    tracing::error!("cannot forward request: {}", err);

                    return match this.0.error.as_ref() {
                        Some(error) => error
                            .call(ProxyError::ForwardError(err))
                            .await
                            .map(|response| ServiceRequest::from_request(resolved.req).into_response(response)),
                        None => Err(Error::from(ProxyError::ForwardError(err))),
                    };
                }
            };

            Ok(ServiceRequest::from_request(resolved.req).into_response(upstream_response))
        })
    }
}
