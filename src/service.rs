use crate::forwarder::Forwarder;
use crate::peer_resolver::PeerResolver;
use actix_service::boxed::BoxService;
use actix_web::{
    body::BoxBody,
    dev::{self, Service, ServiceRequest, ServiceResponse},
    error::Error,
    FromRequest, HttpResponse, ResponseError,
};
use futures_util::future::LocalBoxFuture;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

type HttpService = BoxService<ServiceRequest, ServiceResponse, Error>;

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
    // @TODO: we should retain a better object so we can transfer existing connection on restart
    pub(crate) handlers: Rc<Mutex<Vec<JoinHandle<()>>>>,
    pub(crate) peer_resolver: Arc<dyn PeerResolver>,
    pub(crate) default: Option<HttpService>,
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
                    tracing::error!("cannot read request payload: {}", err);

                    return Ok(
                        ServiceRequest::from_request(downstream_request_head).into_response(HttpResponse::InternalServerError().finish())
                    );
                }
            };

            let http_peer = match this.0.peer_resolver.resolve_peer(&downstream_request_head) {
                Some(peer) => peer,
                None => match this.0.default.as_ref() {
                    Some(default) => {
                        return default.call(ServiceRequest::from_request(downstream_request_head)).await;
                    }
                    None => {
                        tracing::error!("cannot resolve peer for request");

                        return Ok(ServiceRequest::from_request(downstream_request_head)
                            .into_response(HttpResponse::ServiceUnavailable().finish()));
                    }
                },
            };

            let (upstream_response, handler) = match this
                .0
                .forwarder
                .forward(&downstream_request_head, downstream_body, http_peer, origin_hostname)
                .await
            {
                Ok((response, handler)) => (response, handler),
                Err(err) => {
                    tracing::error!("cannot forward request: {}", err);

                    return Ok(ServiceRequest::from_request(downstream_request_head).into_response(err.error_response()));
                }
            };

            if let Some(handler) = handler {
                match this.0.handlers.lock().as_mut() {
                    Ok(h) => {
                        h.push(handler);
                    }
                    Err(err) => {
                        tracing::error!("cannot register upgrade handler: {}", err);

                        handler.abort();
                    }
                }
            }

            Ok(ServiceRequest::from_request(downstream_request_head).into_response(upstream_response))
        })
    }
}
