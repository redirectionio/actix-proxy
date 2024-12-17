use actix_http::StatusCode;
use actix_service::fn_service;
use actix_web::{middleware, App, HttpResponseBuilder, HttpServer};
use redirectionio_actix_proxy::{HttpPeer, Proxy};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7777);

    HttpServer::new(move || {
        App::new()
            .service(
                Proxy::new(HttpPeer::new(address, "domain.does.not.exist")).error_handler(fn_service(|err| async move {
                    Ok(HttpResponseBuilder::new(StatusCode::OK).body(format!("receive an error: {}", err)))
                })),
            )
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())
    })
    .bind(("127.0.0.1", 8080))?
    .workers(2)
    .run()
    .await
}
