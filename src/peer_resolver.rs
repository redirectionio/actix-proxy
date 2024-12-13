use crate::peer::HttpPeer;
use actix::fut::ok;
use actix_service::{Service, ServiceFactory};
use actix_web::HttpRequest;
use futures_util::future::{LocalBoxFuture, Ready};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

pub trait HttpPeerResolve {
    /// Given DNS lookup information, returns a future that completes with socket information.
    fn resolve<'a>(&'a self, request: &'a HttpRequest) -> LocalBoxFuture<'a, Option<Rc<HttpPeer>>>;
}

#[derive(Clone)]
pub(crate) enum HttpPeerResolver {
    Static(Rc<HttpPeer>),
    Custom(Rc<dyn HttpPeerResolve>),
}

impl ServiceFactory<HttpRequest> for HttpPeerResolver {
    type Response = HttpPeerResolverResolved;
    type Error = ();
    type Config = ();
    type Service = HttpPeerResolver;
    type InitError = ();
    type Future = Ready<Result<Self::Service, Self::InitError>>;

    fn new_service(&self, _: ()) -> Self::Future {
        ok(self.clone())
    }
}

impl Service<HttpRequest> for HttpPeerResolver {
    type Response = HttpPeerResolverResolved;
    type Error = ();
    type Future = HttpPeerResolverFut;

    actix_service::always_ready!();

    fn call(&self, req: HttpRequest) -> Self::Future {
        match &self {
            HttpPeerResolver::Static(peer) => HttpPeerResolverFut::Resolved(Some(HttpPeerResolverResolved {
                peer: Some(Rc::clone(peer)),
                req,
            })),
            HttpPeerResolver::Custom(resolver) => {
                let resolver = Rc::clone(resolver);

                HttpPeerResolverFut::InResolve(Box::pin(async move {
                    let peer = resolver.resolve(&req).await;

                    Ok(HttpPeerResolverResolved { peer, req })
                }))
            }
        }
    }
}

pub(crate) struct HttpPeerResolverResolved {
    pub(crate) peer: Option<Rc<HttpPeer>>,
    pub(crate) req: HttpRequest,
}

pub(crate) enum HttpPeerResolverFut {
    Resolved(Option<HttpPeerResolverResolved>),
    InResolve(LocalBoxFuture<'static, Result<HttpPeerResolverResolved, ()>>),
}

impl Future for HttpPeerResolverFut {
    type Output = Result<HttpPeerResolverResolved, ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Resolved(req) => Poll::Ready(Ok(req.take().expect("Resolved polled after finished"))),
            Self::InResolve(fut) => fut.as_mut().poll(cx),
        }
    }
}
