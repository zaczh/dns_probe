use byteorder::{NetworkEndian, WriteBytesExt};
use clap::Parser;
use std::io::{self};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::spawn;

#[macro_use]
extern crate log;
extern crate env_logger;

#[derive(Parser)]
struct Cli {
    /// The address of the real DNS server to which this resolver forwards DNS requests.
    #[arg(short, long)]
    forward: String,
    /// The address of the probing server which this resolver notifies.
    #[arg(short, long)]
    probe: String,
}

#[tokio::main]
async fn main() {
    let _ = Cli::parse();

    dns_probe_lib::setup_panic_hook();

    env_logger::init();

    let ipv4_socket = Arc::new(UdpSocket::bind("0.0.0.0:53").await.unwrap());
    let ipv6_socket = Arc::new(UdpSocket::bind("[::]:53").await.unwrap());
    let tcp_ipv4_socket = TcpListener::bind("0.0.0.0:53").await.unwrap();
    let tcp_ipv6_socket = TcpListener::bind("[::]:53").await.unwrap();

    let handles = vec![
        spawn(async move {
            loop {
                let (tcp_stream, _remote_addr) = tcp_ipv4_socket.accept().await.unwrap();
                spawn(process_tcp(tcp_stream));
            }
        }),
        spawn(async move {
            loop {
                let (tcp_stream, _remote_addr) = tcp_ipv6_socket.accept().await.unwrap();
                spawn(process_tcp(tcp_stream));
            }
        }),
        spawn(async move {
            loop {
                let mut buf = [0; dns_probe_lib::PROBE_PAYLOAD_LEN];
                let (n, peer) = ipv4_socket.recv_from(&mut buf).await.unwrap();
                let arc = Arc::clone(&ipv4_socket);
                spawn(process_udp(arc, peer, buf, n));
            }
        }),
        spawn(async move {
            loop {
                let mut buf = [0; dns_probe_lib::PROBE_PAYLOAD_LEN];
                let (n, peer) = ipv6_socket.recv_from(&mut buf).await.unwrap();
                let arc = Arc::clone(&ipv6_socket);
                spawn(process_udp(arc, peer, buf, n));
            }
        }),
    ];

    for handle in handles {
        let _wait_result = handle.await.unwrap();
    }
}

/// Returns `true` if the connection is done.
async fn process_tcp(mut stream: TcpStream) -> io::Result<bool> {
    use byteorder::ReadBytesExt;
    use std::io::Cursor;

    let mut in_buffer: [u8; dns_probe_lib::PROBE_PAYLOAD_LEN] =
        [0; dns_probe_lib::PROBE_PAYLOAD_LEN];
    let mut out_buffer: [u8; dns_probe_lib::PROBE_PAYLOAD_LEN] =
        [0; dns_probe_lib::PROBE_PAYLOAD_LEN];

    let bytes_read = stream.read(&mut in_buffer).await.unwrap_or(0);
    if bytes_read <= 2 {
        error!("bad request from {:?}", stream.peer_addr());
        let _ = stream.shutdown();
        return Ok(false);
    }

    let mut rdr = Cursor::new(&in_buffer[..]);
    let payload_len = ReadBytesExt::read_u16::<NetworkEndian>(&mut rdr).unwrap_or(0);
    debug!(
        "TCP request: Received {} bytes from {:?}, payload_len: {}",
        bytes_read,
        stream.peer_addr(),
        payload_len
    );

    if payload_len != bytes_read as u16 - 2 {
        error!("tcp payload length not match from {:?}", stream.peer_addr());
        let _ = stream.shutdown();
        return Ok(false);
    }

    let remote_addr = stream.peer_addr().unwrap();
    // send probe immediately
    spawn(async move {
        // remove the tcp two bytes header
        send_probe(&in_buffer[2..bytes_read], true, remote_addr).await;
    });

    let request_data = &in_buffer[2..bytes_read];
    let local_dns_lookup_buffer = &mut out_buffer[2..];
    let out_buf_len = dns_lookup(local_dns_lookup_buffer, request_data).await;
    debug!("TCP resolve received {} byte", out_buf_len);

    let mut payload_header = &mut out_buffer[..2];
    let _ = payload_header.write_u16::<NetworkEndian>(out_buf_len as u16);

    let out_data = &mut out_buffer[..out_buf_len + 2];
    let n = stream.write(out_data).await.unwrap_or(0);
    debug!("TCP write {} byte", n);

    Ok(true)
}

async fn dns_lookup(local_dns_lookup_buffer: &mut [u8], request_data: &[u8]) -> usize {
    let local_server_socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("cannot bind local udp server");
    let cli = Cli::parse();
    let forward_server_addr = cli.forward;

    let send_result = local_server_socket
        .send_to(request_data, forward_server_addr)
        .await
        .expect("fail to send to forward server");

    let (nbytes, peer) = local_server_socket
        .recv_from(local_dns_lookup_buffer)
        .await
        .expect("fail to receive from forward server");

    debug!(
        "DNS answer: Send {} bytes, Received {} bytes from {}",
        send_result, nbytes, peer
    );
    return nbytes;
}

async fn send_probe(message: &[u8], is_tcp: bool, remote_src: SocketAddr) {
    let local_server_socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("cannot bind local udp server");
    let probe_payload = dns_probe_lib::ProbePayload {
        remote_addr: remote_src,
        additional_info: vec![if is_tcp { 1u8 } else { 0u8 }],
        request_payload: message.to_vec(),
    };

    let cli = Cli::parse();
    let probe_server_addr = cli.probe;
    let probe_buffer = &probe_payload.to_data();
    let result = local_server_socket
        .send_to(probe_buffer, probe_server_addr)
        .await
        .expect("fail to send probe");

    info!("DNS probe write bytes: {}", result);
}

async fn process_udp(
    socket: Arc<UdpSocket>,
    remote_src: SocketAddr,
    request_data: [u8; dns_probe_lib::PROBE_PAYLOAD_LEN],
    request_data_len: usize,
) {
    debug!(
        "UDP request: Received {} bytes from {} on {}",
        request_data_len,
        remote_src,
        socket.local_addr().unwrap()
    );

    if request_data_len >= dns_probe_lib::PROBE_PAYLOAD_LEN {
        error!("dns payload size too large!");
        return;
    }

    // send probe immediately
    spawn(async move {
        send_probe(&request_data[..request_data_len], false, remote_src).await;
    });

    let mut local_dns_lookup_buffer = [0; dns_probe_lib::PROBE_PAYLOAD_LEN];
    let len = dns_lookup(&mut local_dns_lookup_buffer, &request_data).await;

    let message = &local_dns_lookup_buffer[..len];
    let _ = socket.send_to(message, remote_src).await;
}
