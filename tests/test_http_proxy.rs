use actix_web::{guard, web, App, HttpRequest, HttpResponse};
use bytes::Bytes;
use redirectionio_actix_proxy::{HttpPeer, Proxy};
use std::net::ToSocketAddrs;

const S: &str = "Hello World ";

#[actix_rt::test]
async fn simple() {
    let backend_srv = actix_test::start(|| App::new().service(web::resource("/").route(web::to(|| async { HttpResponse::Ok().body(S) }))));

    let addr = backend_srv.addr();
    let proxy_srv = actix_test::start(move || App::new().service(Proxy::new(HttpPeer::new(addr, "localhost"))));

    let request = proxy_srv.get("/").send();
    let mut response = request.await.unwrap();

    assert!(response.status().is_success());

    // read response
    let bytes = response.body().await.unwrap();
    assert_eq!(bytes, Bytes::from_static(S.as_ref()));
}

#[actix_rt::test]
async fn test_no_backend() {
    let addr = "127.0.0.1:12345".to_socket_addrs().unwrap().next().unwrap();
    let proxy_srv = actix_test::start(move || App::new().service(Proxy::new(HttpPeer::new(addr, "localhost"))));

    let request = proxy_srv.get("/").send();
    let response = request.await.unwrap();

    assert!(response.status().is_server_error());
}

#[actix_rt::test]
async fn test_via_header() {
    let backend_srv = actix_test::start(|| {
        App::new().default_service(web::route().to(|req: HttpRequest| async move {
            let header = req.headers().get("via");
            let body = if header.is_some() {
                header.unwrap().to_str().unwrap().to_string()
            } else {
                "".to_string()
            };

            HttpResponse::Ok().body(body)
        }))
    });

    let addr = backend_srv.addr();
    let proxy_srv = actix_test::start(move || App::new().service(Proxy::new(HttpPeer::new(addr, "localhost").via("my-proxy", true, true))));

    let request = proxy_srv.get("/").send();
    let mut response = request.await.unwrap();

    assert!(response.status().is_success());

    // read response
    let bytes = response.body().await.unwrap();
    assert_eq!(bytes, Bytes::from_static("HTTP/1.1 my-proxy".as_ref()));

    let header = response.headers().get("via").unwrap().to_str().unwrap();
    assert_eq!(header, "HTTP/1.1 my-proxy");
}

#[actix_rt::test]
async fn test_default_service() {
    let backend_srv =
        actix_test::start(|| App::new().service(web::resource("/").route(web::to(|| async { HttpResponse::Ok().body("backend") }))));

    let addr = backend_srv.addr();

    let proxy_srv = actix_test::start(move || {
        App::new()
            .service(Proxy::new(HttpPeer::new(addr, "localhost")).guard(guard::Host("localhost")))
            .service(web::resource("/").route(web::to(|| async { HttpResponse::Ok().body("proxy") })))
    });

    let request_backend = proxy_srv.get("/").insert_header(("Host", "localhost")).send();
    let mut response_backend = request_backend.await.unwrap();

    assert!(response_backend.status().is_success());
    let bytes = response_backend.body().await.unwrap();
    assert_eq!(bytes, Bytes::from_static("backend".as_ref()));

    let request_proxy = proxy_srv.get("/").insert_header(("Host", "example.com")).send();
    let mut response_proxy = request_proxy.await.unwrap();

    assert!(response_proxy.status().is_success());
    let bytes = response_proxy.body().await.unwrap();
    assert_eq!(bytes, Bytes::from_static("proxy".as_ref()));
}
