use actix_web::{middleware, App, HttpRequest, HttpServer};
use futures_util::future::LocalBoxFuture;
use redirectionio_actix_proxy::{ForwardedFor, HttpPeer, HttpPeerResolve, Proxy};
use std::net::ToSocketAddrs;
use std::rc::Rc;

pub struct PeerResolver;

impl HttpPeerResolve for PeerResolver {
    fn resolve<'a>(&'a self, request: &'a HttpRequest) -> LocalBoxFuture<'a, Option<Rc<HttpPeer>>> {
        Box::pin(async move {
            let host = request.connection_info().host().to_string();

            if host.as_str() == "localhost:8080" {
                let address = "actix.rs:443"
                    .to_socket_addrs()
                    .expect("error getting addresses")
                    .next()
                    .expect("cannot get address");

                return Some(Rc::new(
                    HttpPeer::new(address, "actix.rs")
                        .via("redirection-io-actix-proxy", true, true)
                        .forward_for(ForwardedFor::new_auto("redirection-io-actix-proxy", None))
                        .tls(true),
                ));
            }

            let address = "www.rust-lang.org:443"
                .to_socket_addrs()
                .expect("error getting addresses")
                .next()
                .expect("cannot get address");

            Some(Rc::new(
                HttpPeer::new(address, "www.rust-lang.org")
                    .via("redirection-io-actix-proxy", true, true)
                    .forward_for(ForwardedFor::new_auto("redirection-io-actix-proxy", None))
                    .tls(true),
            ))
        })
    }
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    tls_rustls_0_23::crypto::ring::default_provider()
        .install_default()
        .expect("error installing default provider");

    HttpServer::new(move || {
        App::new()
            .service(Proxy::new_custom(Rc::new(PeerResolver)))
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())
    })
    .bind(("127.0.0.1", 8080))?
    .workers(2)
    .run()
    .await
}
