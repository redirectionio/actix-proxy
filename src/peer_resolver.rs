use crate::peer::HttpPeer;
use actix_web::HttpRequest;
use std::sync::Arc;

pub trait PeerResolver {
    fn resolve_peer(&self, request: &HttpRequest) -> Option<Arc<HttpPeer>>;
}

pub trait ToPeerResolver {
    fn to_peer_resolver(self) -> Arc<dyn PeerResolver>;
}

impl ToPeerResolver for Arc<dyn PeerResolver> {
    fn to_peer_resolver(self) -> Arc<dyn PeerResolver> {
        self
    }
}

pub struct SamePeerResolver {
    peer: Arc<HttpPeer>,
}

impl ToPeerResolver for HttpPeer {
    fn to_peer_resolver(self) -> Arc<dyn PeerResolver> {
        Arc::new(SamePeerResolver::new(Arc::new(self)))
    }
}

impl SamePeerResolver {
    pub fn new(peer: Arc<HttpPeer>) -> Self {
        Self { peer }
    }
}

impl PeerResolver for SamePeerResolver {
    fn resolve_peer(&self, _request: &HttpRequest) -> Option<Arc<HttpPeer>> {
        Some(self.peer.clone())
    }
}
