use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use std::net::SocketAddr;
use std::sync::Arc;
use std::vec::Vec;
use std::{fs, io};
use tokio::task::JoinHandle;

use h3::error::ErrorLevel;
use http::{HeaderValue, Request, Response};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use pki_types::{CertificateDer, PrivateKeyDer};
use quinn_proto::crypto::rustls::QuicServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");

pub struct HttpServer {}

impl HttpServer {
    pub async fn run(
        &self,
        socket_addr: SocketAddr,
        cert_path: String,
        key_path: String,
        request_handler: &'static (dyn Fn(SocketAddr, Request<()>) -> Response<Vec<u8>>
                      + Send
                      + Sync),
    ) {
        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        // Load public certificate.
        let certs: io::Result<Vec<CertificateDer<'static>>> = {
            // Open certificate file.
            let certfile = fs::File::open(cert_path).unwrap();
            let mut reader = io::BufReader::new(certfile);
            // Load and return certificate.
            rustls_pemfile::certs(&mut reader).collect()
        };
        let certs = certs.unwrap();

        // Load private key.
        let key: io::Result<PrivateKeyDer<'static>> = {
            // Open keyfile.
            let keyfile = fs::File::open(key_path).unwrap();
            let mut reader = io::BufReader::new(keyfile);
            // Load and return a single private key.
            rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
        };
        let key = key.unwrap();

        let (certs_http2, key_http2) = (certs.clone(), key.clone_key());
        handles.push(tokio::spawn(async move {
            // Create a TCP listener via tokio.
            let incoming = TcpListener::bind(&socket_addr).await.unwrap();

            // Build TLS configuration.
            let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs_http2, key_http2)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
                .unwrap();
            server_config.alpn_protocols =
                vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
            let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

            loop {
                let result = incoming.accept().await;
                if result.is_err() {
                    break;
                }

                let (tcp_stream, remote_addr) = result.unwrap();
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => tls_stream,
                        Err(err) => {
                            trace!("failed to perform tls handshake: {err:#}");
                            return;
                        }
                    };

                    let svc = service_fn(move |request: Request<Incoming>| {
                        let (parts, _body) = request.into_parts();
                        let new_request = Request::from_parts(parts, ());
                        let return_response = (*request_handler)(remote_addr.clone(), new_request);
                        async move {
                            let (parts, body) = return_response.into_parts();
                            let bytes: Full<Bytes> = Full::from(Bytes::from(body));
                            let mut resp = Response::from_parts(parts, bytes);
                            let server_name = format!("{CARGO_PKG_NAME}/{CARGO_PKG_VERSION}");
                            resp.headers_mut().insert(
                                http::header::SERVER,
                                HeaderValue::from_str(&server_name).unwrap(),
                            );
                            let alt_svc_str = format!(
                                "h3=\":{}\"; ma=3600, h2=\":{}\"; ma=3600",
                                socket_addr.port(),
                                socket_addr.port()
                            );
                            resp.headers_mut().insert(
                                http::header::ALT_SVC,
                                HeaderValue::from_str(&alt_svc_str).unwrap(),
                            );
                            return Result::<
                                hyper::Response<http_body_util::Full<Bytes>>,
                                hyper::Error,
                            >::Ok(resp);
                        }
                    });
                    if let Err(err) = Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls_stream), svc)
                        .await
                    {
                        trace!("failed to serve connection: {err:#}");
                    }
                });
            }
        }));

        let (certs_http3, key_http3) = (certs.clone(), key.clone_key());
        handles.push(tokio::spawn(async move {
            let mut tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs_http3, key_http3)
                .unwrap();

            tls_config.max_early_data_size = u32::MAX;
            tls_config.alpn_protocols = vec![b"h3".to_vec()];

            let server_config = quinn::ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(tls_config).unwrap(),
            ));

            let endpoint = quinn::Endpoint::server(server_config, socket_addr).unwrap();

            // handle incoming connections and requests

            while let Some(new_conn) = endpoint.accept().await {
                trace!("New connection being attempted");

                tokio::spawn(async move {
                    match new_conn.await {
                        Ok(conn) => {
                            info!("new connection established");
                            let remote_address = conn.remote_address();
                            let h3_conn_opt =
                                h3::server::Connection::new(h3_quinn::Connection::new(conn))
                                    .await;
                            if h3_conn_opt.is_err() {
                                error!("new connection failed from: {}, error: {}", remote_address, h3_conn_opt.err().unwrap());
                                return;
                            }

                            let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> = h3_conn_opt.unwrap();

                            loop {
                                match h3_conn.accept().await {
                                    Ok(Some((req, mut stream))) => {
                                        info!(
                                            "new http3 request: {:#?} from: {}",
                                            req, remote_address
                                        );
                                        let return_response = (*request_handler)(remote_address, req);
                                        tokio::spawn(async move {
                                            let mut resp = return_response;
                                            let server_name = format!("{CARGO_PKG_NAME}/{CARGO_PKG_VERSION}");
                                            resp.headers_mut().insert(
                                                http::header::SERVER,
                                                HeaderValue::from_str(&server_name).unwrap(),
                                            );
                                            let alt_svc_str = format!("h3=\":{}\"; ma=3600, h2=\":{}\"; ma=3600", socket_addr.port(), socket_addr.port());
                                            resp.headers_mut().insert(
                                                http::header::ALT_SVC,
                                                HeaderValue::from_str(&alt_svc_str).unwrap(),
                                            );
                                            let (parts, body) = resp.into_parts();
                                            let new_response = http::Response::from_parts(parts, ());
                                            match stream.send_response(new_response).await {
                                                Ok(_) => {
                                                    info!("successfully respond to connection");
                                                }
                                                Err(err) => {
                                                    error!("unable to send response to connection peer: {:?}", err);
                                                }
                                            }

                                            if !body.is_empty() {
                                                if let Err(e) =
                                                    stream.send_data(body.into()).await
                                                {
                                                    error!("http3 send data failed: {}", e);
                                                }
                                            }

                                            // Gracefully terminate the stream
                                            info!("http3 connection complete");
                                            stream.finish().await.unwrap();
                                        });
                                    }

                                    // indicating no more streams to be received
                                    Ok(None) => {
                                        break;
                                    }

                                    Err(err) => {
                                        info!("error on accept: {}, from: {}", err, remote_address);
                                        match err.get_error_level() {
                                            ErrorLevel::ConnectionError => break,
                                            ErrorLevel::StreamError => continue,
                                        }
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            error!("accepting connection failed: {:?}", err);
                        }
                    }
                });
            }

            // shut down gracefully
            // wait for connections to be closed before exiting
            endpoint.wait_idle().await;
        }));
        for handle in handles {
            let _wait_result = handle.await.unwrap();
        }
        warn!("process exit");
    }
}
