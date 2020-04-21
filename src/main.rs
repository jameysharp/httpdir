use futures_util::future::poll_fn;
use hyper::client::conn::{handshake, SendRequest};
use hyper::header;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response, StatusCode};
use std::convert::TryInto;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io;
use tokio::net;
use tokio::sync::Mutex;

#[derive(Copy, Clone)]
struct ProxyError(StatusCode);

impl From<io::Error> for ProxyError {
    fn from(_error: io::Error) -> Self {
        ProxyError(StatusCode::BAD_GATEWAY)
    }
}

impl From<hyper::error::Error> for ProxyError {
    fn from(_error: hyper::error::Error) -> Self {
        ProxyError(StatusCode::BAD_GATEWAY)
    }
}

impl ProxyError {
    fn as_response(self) -> Response<Body> {
        Response::builder()
            .status(self.0)
            .body(self.0.canonical_reason().unwrap_or("").into())
            .expect("valid response from constant data")
    }
}

fn get_hostname<B>(req: &Request<B>) -> Option<PathBuf> {
    let mut hosts = req.headers().get_all(header::HOST).into_iter();
    let host = match (hosts.next(), hosts.next()) {
        (Some(host), None) => host.as_bytes(),
        _ => {
            return None;
        }
    };

    // Hostnames are limited to 255 octets with a trailing dot. Enforcing this limit ensures an
    // attacker can't make us heap-allocate much for a hostname we'll never match.
    if host.len() > 255 {
        return None;
    }

    // The following validation rules ensure that we won't return a hostname which could lead to
    // pathname traversal (e.g. "..", "", or "a/b") and that semantically equivalent hostnames are
    // only returned in a canonical form. This does not validate anything else about the hostname,
    // such as length limits on individual labels.

    let mut name = Vec::with_capacity(host.len());
    let mut start_of_label = true;
    for b in host {
        let b = b.to_ascii_lowercase();

        if start_of_label && (b == b'-' || b == b'.') {
            // a hostname label can't start with dot or dash
            return None;
        }

        // the next byte is the start of a label iff this one was a dot
        start_of_label = b'.' == b;

        match b {
            b':' => break, // ignore an optional port number
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' => name.push(b),
            _ => return None,
        }
    }

    // If we're expecting a new label after reading the whole hostname, then either the
    // name was empty or it ended with a dot.
    if start_of_label {
        if let Some(b'.') = name.pop() {
            // Just remove the trailing dot.
        } else {
            return None;
        }
    }

    // safety: every byte was already checked for being a valid subset of UTF-8
    let name = unsafe { String::from_utf8_unchecked(name) };
    Some(name.into())
}

struct Connection {
    hostname: PathBuf,
    backend: SendRequest<Body>,
}

struct ConnectionPool {
    remote: header::HeaderValue,
    connection: Mutex<Option<Connection>>,
}

impl ConnectionPool {
    fn new(remote: header::HeaderValue) -> ConnectionPool {
        ConnectionPool {
            remote,
            connection: Mutex::new(None),
        }
    }

    async fn forward_to(
        &self,
        hostname: PathBuf,
        req: Request<Body>,
    ) -> Result<Response<Body>, ProxyError> {
        if let Some(c) = self.connection.lock().await.as_mut() {
            if c.hostname == hostname {
                if let Ok(()) = poll_fn(|ctx| c.backend.poll_ready(ctx)).await {
                    return Ok(c.backend.send_request(req).await?);
                }
            }
        }

        // The client sent a name and it's been validated to be safe to use as a path. If that path
        // doesn't work, there might be several reasons. If the backend doesn't exist, return a
        // cacheable 404. If the proxy doesn't have permission to connect or the socket isn't
        // listening, return service temporarily unavailable. For anything else, something
        // unexpected happened, so report that the gateway didn't get a valid response.
        let backend = net::UnixStream::connect(hostname.join("http-socket"))
            .await
            .map_err(|e| {
                ProxyError(match e.kind() {
                    io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
                    io::ErrorKind::PermissionDenied | io::ErrorKind::ConnectionRefused => {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                    _ => StatusCode::BAD_GATEWAY,
                })
            })?;

        let (backend, connection) = handshake(backend).await?;
        tokio::spawn(connection);

        let mut connection_guard = self.connection.lock().await;
        *connection_guard = Some(Connection { hostname, backend });
        Ok(connection_guard
            .as_mut()
            .unwrap()
            .backend
            .send_request(req)
            .await?)
    }
}

async fn forward(
    pool: Arc<ConnectionPool>,
    mut req: Request<Body>,
) -> hyper::Result<Response<Body>> {
    match get_hostname(&req) {
        None => Ok(ProxyError(StatusCode::BAD_REQUEST).as_response()),
        Some(hostname) => {
            req.headers_mut()
                .insert("X-Forwarded-For", pool.remote.clone());
            req.headers_mut().remove("X-Forwarded-Proto");
            pool.forward_to(hostname, req)
                .await
                .or_else(|e| Ok(e.as_response()))
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let http = Http::new();

    // safety: the rest of the program must not use stdin
    let listener = unsafe { std::os::unix::io::FromRawFd::from_raw_fd(0) };

    // Assume stdin is an already bound and listening TCP socket.
    let mut listener = net::TcpListener::from_std(listener)?;

    // Asking for the listening socket's local address has the side effect of checking that it is
    // actually a TCP socket.
    let local = listener.local_addr()?;

    println!("listening on {}", local);

    loop {
        let (socket, remote) = listener.accept().await?;
        let remote = format!("{}", remote)
            .try_into()
            .expect("remote sockaddr to be a valid HTTP header value");
        let pool = Arc::new(ConnectionPool::new(remote));
        let service = service_fn(move |req| forward(pool.clone(), req));
        tokio::spawn(http.serve_connection(socket, service));
    }
}
