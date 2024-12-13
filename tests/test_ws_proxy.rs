use actix::fut::ok;
use actix_codec::Framed;
use actix_http::{body::BodySize, h1, ws, Error, HttpService, Request, Response};
use actix_http_test::test_server;
use actix_web::App;
use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use redirectionio_actix_proxy::{HttpPeer, Proxy};
use std::io;

async fn ws_service(req: ws::Frame) -> Result<ws::Message, io::Error> {
    match req {
        ws::Frame::Ping(msg) => Ok(ws::Message::Pong(msg)),
        ws::Frame::Text(text) => Ok(ws::Message::Text(String::from_utf8(Vec::from(text.as_ref())).unwrap().into())),
        ws::Frame::Binary(bin) => Ok(ws::Message::Binary(bin)),
        ws::Frame::Close(reason) => Ok(ws::Message::Close(reason)),
        _ => Ok(ws::Message::Close(None)),
    }
}

#[actix_rt::test]
async fn test_ws_proxy() {
    let backend_srv = test_server(|| {
        HttpService::build()
            .upgrade(|(req, mut framed): (Request, Framed<_, _>)| {
                async move {
                    let res = ws::handshake_response(req.head()).finish();
                    // send handshake response
                    framed.send(h1::Message::Item((res.drop_body(), BodySize::None))).await?;

                    // start WebSocket service
                    let framed = framed.replace_codec(ws::Codec::new());
                    ws::Dispatcher::with(framed, ws_service).await
                }
            })
            .finish(|_| ok::<_, Error>(Response::not_found()))
            .tcp()
    })
    .await;

    let addr = backend_srv.addr();
    let mut proxy_srv = actix_test::start(move || App::new().service(Proxy::new(HttpPeer::new(addr, "localhost"))));

    // client service
    let mut framed = proxy_srv.ws().await.unwrap();
    framed.send(ws::Message::Text("text".into())).await.unwrap();
    let item = framed.next().await.unwrap().unwrap();
    assert_eq!(item, ws::Frame::Text(Bytes::from_static(b"text")));

    framed.send(ws::Message::Binary("text".into())).await.unwrap();
    let item = framed.next().await.unwrap().unwrap();
    assert_eq!(item, ws::Frame::Binary(Bytes::from_static(b"text")));

    framed.send(ws::Message::Ping("text".into())).await.unwrap();
    let item = framed.next().await.unwrap().unwrap();
    assert_eq!(item, ws::Frame::Pong("text".to_string().into()));

    framed.send(ws::Message::Close(Some(ws::CloseCode::Normal.into()))).await.unwrap();

    let item = framed.next().await.unwrap().unwrap();
    assert_eq!(item, ws::Frame::Close(Some(ws::CloseCode::Normal.into())));
}
