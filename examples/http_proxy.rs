use actix_web::{guard, middleware, App, HttpServer};
use redirectionio_actix_proxy::{ForwardedFor, HttpPeer, Proxy};
use std::net::ToSocketAddrs;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    tls_rustls_0_23::crypto::ring::default_provider()
        .install_default()
        .expect("error installing default provider");

    let address = "actix.rs:443"
        .to_socket_addrs()
        .expect("error getting addresses")
        .next()
        .expect("cannot get address");

    HttpServer::new(move || {
        App::new()
            .service(
                Proxy::new(
                    HttpPeer::new(address, "actix.rs")
                        .via("redirection-io-actix-proxy", true, true)
                        .forward_for(ForwardedFor::new_auto("redirection-io-actix-proxy", None))
                        .tls(true),
                )
                // will only work on localhost, not 127.0.0.1 by example
                .guard(guard::Host("localhost")),
            )
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())
    })
    .bind(("127.0.0.1", 8080))?
    .workers(2)
    .run()
    .await
}
