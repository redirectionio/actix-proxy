use crate::error::ProxyError;
use crate::forwarder::Forwarder;
use crate::peer_resolver::{HttpPeerResolve, HttpPeerResolver};
use crate::service::{ProxyService, ProxyServiceInner};
use crate::HttpPeer;
use actix_service::boxed::BoxServiceFactory;
use actix_service::{boxed, IntoServiceFactory, ServiceFactory, ServiceFactoryExt};
use actix_web::dev::ResourceDef;
use actix_web::{
    dev::{AppService, HttpServiceFactory, ServiceRequest, ServiceResponse},
    guard::Guard,
    Error, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use std::cell::RefCell;
use std::rc::Rc;

type HttpNewService = BoxServiceFactory<(), ServiceRequest, ServiceResponse, Error, ()>;
type ErrorNewService = BoxServiceFactory<(), ProxyError, HttpResponse, Error, ()>;

pub struct Proxy {
    peer_resolver: Rc<HttpPeerResolver>,
    forwarder: Rc<Forwarder>,
    default: Rc<RefCell<Option<Rc<HttpNewService>>>>,
    error: Rc<RefCell<Option<Rc<ErrorNewService>>>>,
    guards: Vec<Rc<dyn Guard>>,
}

impl Proxy {
    pub fn new(peer: HttpPeer) -> Self {
        Self {
            peer_resolver: Rc::new(HttpPeerResolver::Static(Rc::new(peer))),
            forwarder: Rc::new(Forwarder::new()),
            default: Rc::new(RefCell::new(None)),
            error: Rc::new(RefCell::new(None)),
            guards: Vec::new(),
        }
    }

    pub fn new_custom(peer_resolver: Rc<dyn HttpPeerResolve>) -> Self {
        Self {
            peer_resolver: Rc::new(HttpPeerResolver::Custom(peer_resolver)),
            forwarder: Rc::new(Forwarder::new()),
            default: Rc::new(RefCell::new(None)),
            error: Rc::new(RefCell::new(None)),
            guards: Vec::new(),
        }
    }

    /// Adds a routing guard.
    ///
    /// Use this to allow multiple chained file services that respond to strictly different
    /// properties of a request. Due to the way routing works, if a guard check returns true and the
    /// request starts being handled by the file service, it will not be able to back-out and try
    /// the next service, you will simply get a 404 (or 405) error response.
    pub fn guard<G: Guard + 'static>(mut self, guard: G) -> Self {
        self.guards.push(Rc::new(guard));
        self
    }

    /// Sets default handler which is used when no peer could be found.
    pub fn default_handler<F, U>(mut self, f: F) -> Self
    where
        F: IntoServiceFactory<U, ServiceRequest>,
        U: ServiceFactory<ServiceRequest, Config = (), Response = ServiceResponse, Error = Error> + 'static,
    {
        // create and configure default resource
        self.default = Rc::new(RefCell::new(Some(Rc::new(boxed::factory(f.into_factory().map_init_err(|_| ()))))));

        self
    }

    pub fn error_handler<F, U>(mut self, f: F) -> Self
    where
        F: IntoServiceFactory<U, ProxyError>,
        U: ServiceFactory<ProxyError, Config = (), Response = HttpResponse, Error = Error> + 'static,
    {
        // create and configure default resource
        self.error = Rc::new(RefCell::new(Some(Rc::new(boxed::factory(f.into_factory().map_init_err(|_| ()))))));

        self
    }
}

impl HttpServiceFactory for Proxy {
    fn register(mut self, config: &mut AppService) {
        let guards = if self.guards.is_empty() {
            None
        } else {
            let guards = std::mem::take(&mut self.guards);
            Some(
                guards
                    .into_iter()
                    .map(|guard| -> Box<dyn Guard> { Box::new(guard) })
                    .collect::<Vec<_>>(),
            )
        };

        if self.default.borrow().is_none() {
            *self.default.borrow_mut() = Some(config.default_service());
        }

        config.register_service(
            if config.is_root() {
                ResourceDef::root_prefix("")
            } else {
                ResourceDef::prefix("")
            },
            guards,
            self,
            None,
        )
    }
}

impl ServiceFactory<ServiceRequest> for Proxy {
    type Response = ServiceResponse;
    type Error = Error;
    type Config = ();
    type Service = ProxyService;
    type InitError = ();
    type Future = LocalBoxFuture<'static, Result<Self::Service, Self::InitError>>;

    fn new_service(&self, _cfg: Self::Config) -> Self::Future {
        let mut inner = ProxyServiceInner {
            forwarder: self.forwarder.clone(),
            peer_resolver: self.peer_resolver.clone(),
            default: None,
            error: None,
        };

        let default_fut = (*self.default.borrow()).as_ref().map(|default| default.new_service(()));
        let error_fut = (*self.error.borrow()).as_ref().map(|error| error.new_service(()));

        Box::pin(async {
            if let Some(fut_default) = default_fut {
                inner.default = Some(fut_default.await?);
            }

            if let Some(fut_error) = error_fut {
                inner.error = Some(fut_error.await?);
            }

            Ok(ProxyService(Rc::new(inner)))
        })
    }
}
