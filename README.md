# Actix proxy service

Proxy service for Actix Web.

Provides a proxy service for Actix Web that can be used to proxy requests to a target server.

## Examples

```rust
use actix_web::{guard, middleware, App, HttpServer};
use redirectionio_actix_proxy::{HttpPeer, Proxy};
use std::net::ToSocketAddrs;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let address = "127.0.0.1:80"
        .to_socket_addrs()
        .expect("error getting addresses")
        .next()
        .expect("cannot get address");

    HttpServer::new(move || {
        App::new()
            .service(Proxy::new(HttpPeer::new(address, "my-proxy.com")))
    })
        .bind(("127.0.0.1", 8080))?
        .workers(2)
        .run()
        .await
}
```

