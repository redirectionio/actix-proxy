mod client;
mod error;
pub(crate) mod forward_header;

use crate::peer::HttpPeer;

use crate::forwarder::client::ForwardClient;
pub use crate::forwarder::error::ForwardError;
use actix::prelude::Stream;
use actix_http::body::{BodyStream, MessageBody, SizedStream};
use actix_http::header::{HeaderMap, HeaderName, TryIntoHeaderValue};
use actix_service::Service;
use actix_web::dev::RequestHead;
use actix_web::error::PayloadError;
use actix_web::http::uri::Scheme;
use actix_web::http::{header, header::AsHeaderName, StatusCode, Uri};
use actix_web::web::{Buf, Payload};
use actix_web::{HttpMessage, HttpRequest, HttpResponse, HttpResponseBuilder};
use awc::http::Version;
use awc::Connect;
use bytes::Bytes;
use futures::TryStreamExt;
use std::collections::HashSet;
use std::future::Future;
use std::option::Option::None;
use std::pin::Pin;
use std::rc::Rc;
use std::str::FromStr;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::spawn_local;
use tokio_util::codec::{BytesCodec, FramedRead};

lazy_static! {
    static ref HOP_HEADERS: HashSet<HeaderName> = {
        let mut hop_headers = HashSet::new();

        hop_headers.insert(header::CONNECTION);
        hop_headers.insert(HeaderName::from_str("proxy-connection").unwrap());
        hop_headers.insert(HeaderName::from_str("keep-alive").unwrap());
        hop_headers.insert(header::PROXY_AUTHENTICATE);
        hop_headers.insert(header::PROXY_AUTHORIZATION);
        hop_headers.insert(header::TE);
        hop_headers.insert(header::TRAILER);
        hop_headers.insert(header::TRANSFER_ENCODING);
        hop_headers.insert(header::UPGRADE);

        hop_headers
    };
}

pub struct Forwarder {
    client: ForwardClient,
}

impl Forwarder {
    pub fn new() -> Self {
        Self {
            client: ForwardClient::default(),
        }
    }

    pub async fn forward(
        &self,
        downstream_request_head: &HttpRequest,
        downstream_body: Payload,
        peer: Rc<HttpPeer>,
        origin_hostname: String,
    ) -> Result<HttpResponse, ForwardError> {
        let mut upstream_request_head = RequestHead::default();

        upstream_request_head.method = downstream_request_head.method().clone();
        upstream_request_head.uri = match Uri::builder()
            .path_and_query(match downstream_request_head.uri().path_and_query() {
                Some(path_and_query) => path_and_query.as_str(),
                None => downstream_request_head.uri().path(),
            })
            .authority(origin_hostname.as_str())
            .scheme(if peer.tls { Scheme::HTTPS } else { Scheme::HTTP })
            .build()
        {
            Err(err) => {
                return Err(ForwardError::UriError(err.into()));
            }
            Ok(url) => url,
        };

        let upstream_request_connection_headers = Self::get_connection_headers(downstream_request_head.headers());

        for (name, value) in downstream_request_head.headers() {
            if HOP_HEADERS.contains(name) {
                continue;
            }

            if upstream_request_connection_headers.contains(name.as_str()) {
                continue;
            }

            if name == header::HOST {
                continue;
            }

            if name == header::ACCEPT_ENCODING {
                if let Some(encodings) = &peer.supported_encodings {
                    match value.to_str() {
                        Err(err) => {
                            tracing::error!("error parsing accept encoding header: {}", err);
                        }
                        Ok(v) => {
                            let mut new_value = String::new();

                            for encoding in v.split(',') {
                                if encodings.contains(encoding.trim()) {
                                    if !new_value.is_empty() {
                                        new_value.push(',');
                                    }

                                    new_value.push_str(encoding.trim());
                                }
                            }

                            if !new_value.is_empty() {
                                upstream_request_head.headers.append(name.clone(), new_value.parse().unwrap());
                            }
                        }
                    }

                    continue;
                }
            }

            upstream_request_head.headers_mut().append(name.clone(), value.clone());
        }

        if Self::contain_value(downstream_request_head.headers(), header::TE, "trailers") {
            upstream_request_head
                .headers_mut()
                .insert(header::TE, "trailers".try_into_value().unwrap());
        }

        if let Some(via) = &peer.via {
            if via.add_in_request {
                let version = match downstream_request_head.version() {
                    Version::HTTP_09 => Some("0.9"),
                    Version::HTTP_10 => Some("1.0"),
                    Version::HTTP_11 => Some("1.1"),
                    Version::HTTP_2 => Some("2.0"),
                    Version::HTTP_3 => Some("3.0"),
                    _ => None,
                };

                if let Some(version_str) = version {
                    upstream_request_head
                        .headers_mut()
                        .append(header::VIA, format!("HTTP/{} {}", version_str, via.name).try_into_value().unwrap());
                }
            }
        }

        upstream_request_head
            .headers_mut()
            .insert(header::HOST, peer.request_host.as_str().try_into_value().unwrap());

        if let (Some(client_ip), Ok(scheme)) = (
            downstream_request_head.connection_info().realip_remote_addr(),
            Scheme::from_str(downstream_request_head.connection_info().scheme()),
        ) {
            peer.forward_for
                .apply(upstream_request_head.headers_mut(), client_ip, origin_hostname, scheme);
        }

        let is_upgrade_request = Self::contain_value(downstream_request_head.headers(), header::CONNECTION, "upgrade");

        if is_upgrade_request {
            upstream_request_head
                .headers_mut()
                .insert(header::CONNECTION, "Upgrade".try_into_value().unwrap());

            for val in downstream_request_head.headers().get_all(header::UPGRADE) {
                upstream_request_head
                    .headers_mut()
                    .append(header::UPGRADE, val.try_into_value().unwrap());
            }

            return self.upgrade(peer, upstream_request_head, downstream_body).await;
        }

        let mut upstream_uri_builder = Uri::builder();

        if let Some(path_and_query) = upstream_request_head.uri.path_and_query() {
            upstream_uri_builder = upstream_uri_builder.path_and_query(path_and_query.clone());
        }

        upstream_uri_builder = upstream_uri_builder.authority(peer.sni_host.clone());
        upstream_uri_builder = upstream_uri_builder.scheme(if peer.tls { Scheme::HTTPS } else { Scheme::HTTP });

        let upstream_uri = match upstream_uri_builder.build() {
            Ok(u) => u,
            Err(err) => {
                return Err(ForwardError::UriError(err.into()));
            }
        };

        let mut upstream_request = self
            .client
            .request(
                upstream_request_head.method.clone(),
                upstream_uri.clone(),
                peer.allow_invalid_certificates,
            )
            .no_decompress();

        std::mem::swap(upstream_request.headers_mut(), upstream_request_head.headers_mut());

        upstream_request = upstream_request.address(peer.address);

        if peer.force_close {
            upstream_request = upstream_request.force_close();
        }

        if let Some(timeout) = peer.timeout {
            upstream_request = upstream_request.timeout(timeout);
        }

        let stream = match downstream_request_head
            .headers()
            .get(header::CONTENT_LENGTH)
            .map(|v| v.to_str())
            .map(|v| v.map(|v| v.parse::<u64>()))
        {
            Some(Ok(Ok(content_length))) => SizedStream::new(content_length, downstream_body).boxed(),
            _ => {
                if !downstream_request_head.headers().contains_key(header::TRANSFER_ENCODING)
                    && downstream_request_head.version() < Version::HTTP_2
                {
                    let bytes = match downstream_body.to_bytes_limited(peer.request_body_size_limit).await {
                        Ok(bytes) => match bytes {
                            Ok(bytes) => bytes,
                            Err(err) => {
                                return Err(ForwardError::ReadBodyError(err));
                            }
                        },
                        Err(err) => {
                            return Err(ForwardError::BodyTooLarge(err));
                        }
                    };

                    bytes.boxed()
                } else {
                    BodyStream::new(downstream_body).boxed()
                }
            }
        };

        let mut upstream_response = match upstream_request.send_body(stream).await {
            Ok(body) => body,
            Err(err) => {
                return Err(ForwardError::SendRequestUpstreamError(err));
            }
        };

        let mut response_builder = HttpResponse::build(upstream_response.status());

        Self::map_headers(
            peer,
            &mut response_builder,
            upstream_response.version(),
            upstream_response.status(),
            upstream_response.headers(),
        );

        Ok(response_builder.streaming(upstream_response.take_payload()))
    }

    async fn upgrade(
        &self,
        peer: Rc<HttpPeer>,
        upstream_request_head: RequestHead,
        downstream_body: Payload,
    ) -> Result<HttpResponse, ForwardError> {
        let connector = ForwardClient::new_connector(vec![b"http/1.1".to_vec()], peer.allow_invalid_certificates);

        let connect = Connect {
            uri: upstream_request_head.uri.clone(),
            addr: Some(peer.address),
        };

        let conn_fut = match connector.finish().call(connect).await {
            Err(e) => {
                return Err(ForwardError::ConnectUpstreamError(e));
            }
            Ok(c) => c,
        };

        let (res_head, framed) = match conn_fut.open_tunnel(upstream_request_head).await {
            Err(e) => {
                return Err(ForwardError::SendRequestUpstreamError(e));
            }
            Ok(r) => r,
        };

        let mut response_builder = HttpResponse::build(res_head.status);
        Self::map_headers(peer, &mut response_builder, res_head.version, res_head.status, res_head.headers());

        let (upstream_stream_read, upstream_stream_write) = tokio::io::split(framed.into_parts().io);

        let downstream_stream_read = PayloadIoStream {
            payload: downstream_body,
            state: PayloadIoStreamState::PendingChunk,
        };

        // response_stream : copy upstream read stream to downstream write stream
        let response_stream = into_bytes_stream(upstream_stream_read);
        // copy future : copy downstream read stream to upstream write stream
        let copy_future = CopyFuture {
            reader: downstream_stream_read,
            writer: upstream_stream_write,
            read_done: false,
            pos: 0,
            cap: 0,
            buf: vec![0; 8096].into_boxed_slice(),
        };

        // @TODO Instead of spawning a new task, we could create a specific Body that implements
        // pipelining between the two streams
        spawn_local(copy_future);

        Ok(response_builder.streaming(response_stream))
    }

    fn map_headers(
        peer: Rc<HttpPeer>,
        response_builder: &mut HttpResponseBuilder,
        version: Version,
        status: StatusCode,
        headers: &HeaderMap,
    ) {
        let response_connection_headers = Self::get_connection_headers(headers);

        for (name, value) in headers {
            // Skip headers only when no switching protocols
            if status != StatusCode::SWITCHING_PROTOCOLS {
                if HOP_HEADERS.contains(name) {
                    continue;
                }

                if name == header::CONTENT_LENGTH {
                    continue;
                }

                if response_connection_headers.contains(name.as_str()) {
                    continue;
                }
            }

            response_builder.append_header((name, value));
        }

        if let Some(via) = &peer.via {
            if via.add_in_response {
                let via_version = match version {
                    Version::HTTP_09 => Some("0.9"),
                    Version::HTTP_10 => Some("1.0"),
                    Version::HTTP_11 => Some("1.1"),
                    Version::HTTP_2 => Some("2.0"),
                    Version::HTTP_3 => Some("3.0"),
                    _ => None,
                };

                if let Some(via_version_str) = via_version {
                    response_builder.append_header((header::VIA, format!("HTTP/{} {}", via_version_str, via.name)));
                }
            }
        }
    }

    fn get_connection_headers(header_map: &HeaderMap) -> HashSet<String> {
        let mut connection_headers = HashSet::new();

        for conn_value in header_map.get_all("connection") {
            match conn_value.to_str() {
                Err(_) => (),
                Ok(conn_value_str) => {
                    for value in conn_value_str.split(',') {
                        match HeaderName::from_str(value.trim()) {
                            Err(_) => (),
                            Ok(header_name) => {
                                connection_headers.insert(header_name.as_str().to_lowercase());
                            }
                        }
                    }
                }
            }
        }

        connection_headers
    }

    fn contain_value(map: &HeaderMap, key: impl AsHeaderName, value: &str) -> bool {
        for val in map.get_all(key) {
            match val.to_str() {
                Err(_) => (),
                Ok(vs) => {
                    if value.to_lowercase() == vs.to_lowercase() {
                        return true;
                    }
                }
            }
        }

        false
    }
}

fn into_bytes_stream<R>(r: R) -> impl Stream<Item = tokio::io::Result<bytes::Bytes>>
where
    R: AsyncRead,
{
    FramedRead::new(r, BytesCodec::new()).map_ok(|bytes| bytes.freeze())
}

enum PayloadIoStreamState {
    Ready { chunk: Bytes, chunk_start: usize },
    PendingChunk,
    Eof,
}

struct PayloadIoStream {
    payload: Payload,
    state: PayloadIoStreamState,
}

impl AsyncRead for PayloadIoStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        loop {
            match &mut self.state {
                PayloadIoStreamState::Ready { chunk, chunk_start } => {
                    let chunk = chunk.chunk();
                    let len = std::cmp::min(buf.remaining(), chunk.len() - *chunk_start);

                    buf.put_slice(&chunk[*chunk_start..*chunk_start + len]);
                    *chunk_start += len;

                    if chunk.len() == *chunk_start {
                        self.state = PayloadIoStreamState::PendingChunk;
                    }

                    return Poll::Ready(Ok(()));
                }
                PayloadIoStreamState::PendingChunk => match Pin::new(&mut self.payload).poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(chunk))) => {
                        if !chunk.is_empty() {
                            self.state = PayloadIoStreamState::Ready { chunk, chunk_start: 0 };
                        }
                    }
                    Poll::Ready(Some(Err(err))) => {
                        self.state = PayloadIoStreamState::Eof;

                        let io_err = match err {
                            PayloadError::Io(e) => e,
                            _ => std::io::Error::new(std::io::ErrorKind::Other, err),
                        };

                        return Poll::Ready(Err(io_err));
                    }
                    Poll::Ready(None) => {
                        self.state = PayloadIoStreamState::Eof;

                        return Poll::Ready(Ok(()));
                    }
                },
                PayloadIoStreamState::Eof => {
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

struct CopyFuture<R, W> {
    reader: R,
    writer: W,
    read_done: bool,
    pos: usize,
    cap: usize,
    buf: Box<[u8]>,
}

impl<R, W> Future for CopyFuture<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);

                match Pin::new(&mut me.reader).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => {
                        tracing::error!("[handler] error while reading client stream: {}", err);

                        return Poll::Ready(());
                    }
                }

                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let me = &mut *self;
                let i = match Pin::new(&mut me.writer).poll_write(cx, &me.buf[me.pos..me.cap]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(w)) => w,
                    Poll::Ready(Err(err)) => {
                        tracing::error!("[handler] error while writing to backend: {}", err);

                        return Poll::Ready(());
                    }
                };

                if i == 0 {
                    tracing::error!("[handler] 0 byte writed to backend");

                    return Poll::Ready(());
                } else {
                    self.pos += i;
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                match Pin::new(&mut self.writer).poll_flush(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => (),
                    Poll::Ready(Err(err)) => {
                        tracing::error!("[handler] error while flushing backend: {}", err);
                    }
                }

                return Poll::Ready(());
            }
        }
    }
}
