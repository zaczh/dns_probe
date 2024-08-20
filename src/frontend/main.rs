#[macro_use]
extern crate log;
extern crate env_logger;

use clap::Parser;
mod http_server;
use http_server::HttpServer;
mod asns;
use asns::ASNs;
use std::fs::File;
use std::io::Read;

use std::io;
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::vec::Vec;

use hickory_proto::serialize::binary::BinEncodable;
use http::{HeaderValue, Method, Request, Response, StatusCode, Version};
use tokio::spawn;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
struct Cli {
    /// The domain name for the main website
    #[arg(short, long)]
    domain: String,

    /// The socket address which this backend listening on
    #[arg(short, long)]
    listen: String,

    /// The asn file path (e.g. ip2asn-combined.tsv.gz)
    #[arg(short, long)]
    asn_file_path: String,

    /// The root dir for the main page which contains site favicon files, robots.txt, etc.
    #[arg(short, long)]
    site_root_dir: String,

    /// The https certificate of the main domain
    #[arg(long)]
    main_cert_path: String,

    /// The https key file of the main domain
    #[arg(long)]
    main_key_path: String,

    /// The https certificate of the IPv4 probe domain
    #[arg(long)]
    probe_v4_cert_path: String,

    /// The https key file of the IPv4 probe domain
    #[arg(long)]
    probe_v4_key_path: String,

    /// The https certificate of the IPv6 probe domain
    #[arg(long)]
    probe_v6_cert_path: String,

    /// The https key file of the IPv6 probe domain
    #[arg(long)]
    probe_v6_key_path: String,
}

#[derive(Hash, Eq, PartialEq, Debug)]
struct TimingInfo {
    t0: u128,
    t1: u128,
    t2: u128,
    t3: u128,
}

impl TimingInfo {
    fn new(t0: u128, t1: u128, t2: u128, t3: u128) -> TimingInfo {
        TimingInfo { t0, t1, t2, t3 }
    }
}

#[derive(Eq, Hash, PartialEq)]
struct ProbeItem {
    remote_address: String,
    is_tcp_request: bool,
    edns_subnet_enabled: bool,
    edns_subnet: String,
    edns_subnet_prefix_length: u8,
}

impl Clone for ProbeItem {
    fn clone(&self) -> Self {
        return ProbeItem {
            remote_address: self.remote_address.clone(),
            is_tcp_request: self.is_tcp_request,
            edns_subnet_enabled: self.edns_subnet_enabled,
            edns_subnet: self.edns_subnet.clone(),
            edns_subnet_prefix_length: self.edns_subnet_prefix_length,
        };
    }
}

lazy_static::lazy_static! {
    static ref CACHED_PROBE_ITEMS_V4: Mutex<HashMap<String, (TimingInfo, HashSet<ProbeItem>)>> = Mutex::new(HashMap::new());
    static ref CACHED_PROBE_ITEMS_V6: Mutex<HashMap<String, (TimingInfo, HashSet<ProbeItem>)>> = Mutex::new(HashMap::new());
    static ref HTML_TEMPLATE: String = {
        let str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/frontend/template.html"
        )).to_string();
        str
    };
    static ref ASN_HANDLE: ASNs = {
        let asn_file_path = Cli::parse().asn_file_path;
        let _ = File::open(&asn_file_path).expect(&format!("The asn file does not exist: {asn_file_path}"));
        let asn = ASNs::new(&asn_file_path).unwrap();
        asn
    };
}

#[tokio::main]
async fn main() {
    let _ = Cli::parse();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    dns_probe_lib::setup_panic_hook();

    env_logger::init();
    warn!("process start");

    let _ = ASN_HANDLE;
    warn!("asn initialized");

    let handles = vec![
        spawn(async {
            let args = Cli::parse();
            let main_cert = args.main_cert_path;
            let main_key = args.main_key_path;
            warn!("http main ipv4 running on a worker thread");
            let ipv4_addr = Ipv4Addr::new(0, 0, 0, 0);
            let ipv4_socket = SocketAddrV4::new(ipv4_addr, 443);
            let server = HttpServer {};
            server
                .run(
                    SocketAddr::V4(ipv4_socket),
                    main_cert,
                    main_key,
                    &homepage_handler_main,
                )
                .await;
            warn!("http main ipv4 finished");
            io::Result::Ok("")
        }),
        spawn(async {
            let args = Cli::parse();
            let main_cert = args.main_cert_path;
            let main_key = args.main_key_path;
            warn!("http main ipv6 running on a worker thread");
            let ipv6_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
            let ipv6_socket = SocketAddrV6::new(ipv6_addr, 443, 0, 0);
            let server = HttpServer {};
            server
                .run(
                    SocketAddr::V6(ipv6_socket),
                    main_cert,
                    main_key,
                    &homepage_handler_main,
                )
                .await;
            warn!("http main ipv6 finished");
            io::Result::Ok("")
        }),
        spawn(async {
            warn!("dns notify running on a worker thread");
            dns_notify_handler_main().await;
            warn!("dns notify finished");
            io::Result::Ok("")
        }),
        spawn(async {
            let args = Cli::parse();
            let v4_cert = args.probe_v4_cert_path;
            let v4_key = args.probe_v4_key_path;
            let port = 8443;
            warn!("dns http ipv4 on {} running on a worker thread", port);
            let ipv4_addr = Ipv4Addr::new(0, 0, 0, 0);
            let ipv4_socket = SocketAddrV4::new(ipv4_addr, port);
            let server = HttpServer {};
            server
                .run(
                    SocketAddr::V4(ipv4_socket),
                    v4_cert,
                    v4_key,
                    &ip_dns_check_handler_main,
                )
                .await;
            warn!("dns http ipv4 finished");
            io::Result::Ok("")
        }),
        spawn(async {
            let args = Cli::parse();
            let v6_cert = args.probe_v6_cert_path;
            let v6_key = args.probe_v6_key_path;
            let port = 8443;
            warn!("ip dns check ipv6 on {} running on a worker thread", port);
            let ipv6_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
            let ipv6_socket = SocketAddrV6::new(ipv6_addr, 8443, 0, 0);
            let server = HttpServer {};
            server
                .run(
                    SocketAddr::V6(ipv6_socket),
                    v6_cert,
                    v6_key,
                    &ip_dns_check_handler_main,
                )
                .await;
            warn!("ip dns check ipv6 finished");
            io::Result::Ok("")
        }),
        spawn(async {
            let args = Cli::parse();
            let v4_cert = args.probe_v4_cert_path;
            let v4_key = args.probe_v4_key_path;
            let port = 8444;
            warn!("ip dns check ipv4 on {} running on a worker thread", port);
            let ipv4_addr = Ipv4Addr::new(0, 0, 0, 0);
            let ipv4_socket = SocketAddrV4::new(ipv4_addr, port);
            let server = HttpServer {};
            server
                .run(
                    SocketAddr::V4(ipv4_socket),
                    v4_cert,
                    v4_key,
                    &ip_dns_check_handler_main,
                )
                .await;
            warn!("ip dns check ipv4 finished");
            io::Result::Ok("")
        }),
        spawn(async {
            let args = Cli::parse();
            let v6_cert = args.probe_v6_cert_path;
            let v6_key = args.probe_v6_key_path;
            let port = 8444;
            warn!("ip dns check ipv6 on {} running on a worker thread", port);
            let ipv6_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
            let ipv6_socket = SocketAddrV6::new(ipv6_addr, port, 0, 0);
            let server = HttpServer {};
            server
                .run(
                    SocketAddr::V6(ipv6_socket),
                    v6_cert,
                    v6_key,
                    &ip_dns_check_handler_main,
                )
                .await;
            warn!("ip dns check ipv6 finished");
            io::Result::Ok("")
        }),
    ];
    for handle in handles {
        let _wait_result = handle.await.unwrap();
    }
    warn!("process exit");
}

async fn dns_notify_handler_main() {
    use byteorder::{BigEndian, ReadBytesExt};
    use hickory_proto::op::message;
    use tokio::net::UdpSocket;
    let args = Cli::parse();
    let domain = args.domain;
    let addr = args.listen;

    let server_socket = UdpSocket::bind(addr)
        .await
        .expect("couldn't bind to address");

    loop {
        let mut external_client_buf = [0; dns_probe_lib::PROBE_PAYLOAD_LEN];
        let (nbytes, remote_src) = server_socket
            .recv_from(&mut external_client_buf)
            .await
            .expect("couldn't bind to address");

        if nbytes < dns_probe_lib::PROBE_PAYLOAD_LEN {
            error!("bad payload data");
            continue;
        }

        debug!("notify from: {}", remote_src);

        let probe_payload = dns_probe_lib::ProbePayload::from_data(external_client_buf);
        let remote_address = probe_payload.remote_addr.ip().to_string();
        let additional_info = &probe_payload.additional_info;
        let is_tcp_request = if additional_info.len() > 0 {
            additional_info[0] != 0
        } else {
            false
        };
        let dns_message = message::Message::from_vec(&probe_payload.request_payload);
        if !dns_message.is_ok() {
            error!("no dns from: {}", remote_address);
            continue;
        }
        let dns_message = dns_message.unwrap();
        if !dns_message.query().is_some() {
            error!("no query from: {}", remote_address);
            continue;
        }
        let dns_message_query = dns_message.query().unwrap();
        let dns_message_query_name = dns_message_query.name();
        let dns_message_query_name_string = dns_message_query_name.to_string().to_lowercase();

        if dns_message_query_name_string == "ip.v4.".to_string() + domain.as_str() + "."
            || dns_message_query_name_string == "ip.v6.".to_string() + domain.as_str() + "."
        {
            continue;
        }

        if !dns_message_query_name_string
            .ends_with((".v4.".to_string() + domain.as_str() + ".").as_str())
            && !dns_message_query_name_string
                .ends_with((".v6.".to_string() + domain.as_str() + ".").as_str())
        {
            continue;
        }
        let components: Vec<&str> = dns_message_query_name_string.split('.').collect();
        let mut is_verified_request = false;
        if components.len() < 2 {
            error!("bad dns message name: {}", dns_message_query_name);
            continue;
        }

        let totp = components[0];
        let is_v4 = components[1] == "v4";
        {
            let mut hashmap = if is_v4 {
                CACHED_PROBE_ITEMS_V4.lock().unwrap()
            } else {
                CACHED_PROBE_ITEMS_V6.lock().unwrap()
            };
            if let Some(item) = hashmap.get_mut(totp) {
                let timing_info = &mut item.0;
                let t1 = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("wrong time")
                    .as_millis();
                timing_info.t1 = t1;
                is_verified_request = true;
            }
        }

        if !is_verified_request {
            info!(
                "request failed to verify: {}, from: {}",
                dns_message_query_name_string, remote_address
            );
            continue;
        }

        info!(
            "DNS Probe: verified request: {}, from: {}",
            dns_message_query_name_string, probe_payload.remote_addr
        );

        let mut probe_item = ProbeItem {
            remote_address,
            is_tcp_request,
            edns_subnet_enabled: false,
            edns_subnet: "".to_string(),
            edns_subnet_prefix_length: 0,
        };

        if let Some(extensions) = &dns_message.extensions() {
            if let Some(subnet) = extensions.option(hickory_proto::rr::rdata::opt::EdnsCode::Subnet)
            {
                if let hickory_proto::rr::rdata::opt::EdnsOption::Subnet(edns) = subnet {
                    let vec = edns.to_bytes().unwrap();
                    let mut subnet_vec = vec.as_slice();
                    let subnet_option_family = subnet_vec.read_u16::<BigEndian>().unwrap();
                    let subnet_option_source_prefix_length = subnet_vec.read_u8().unwrap();
                    let subnet_option_source_prefix_length_ceiled =
                        ((subnet_option_source_prefix_length as f32) / 8.0).ceil();
                    let _ = subnet_vec.read_u8().unwrap();

                    if subnet_option_family == 1 {
                        let mut ipv4_addr_vec = [0; 4];
                        ipv4_addr_vec[..subnet_option_source_prefix_length_ceiled as usize]
                            .clone_from_slice(
                                &vec[4..4 + subnet_option_source_prefix_length_ceiled as usize],
                            );
                        let ipv4_address = Ipv4Addr::from(ipv4_addr_vec);
                        probe_item.edns_subnet_prefix_length = subnet_option_source_prefix_length;
                        probe_item.edns_subnet_enabled = true;
                        probe_item.edns_subnet = ipv4_address.to_string();
                    } else if subnet_option_family == 2 {
                        let mut ipv6_addr_vec = [0; 16];

                        ipv6_addr_vec[..subnet_option_source_prefix_length_ceiled as usize]
                            .clone_from_slice(
                                &vec[4..4 + subnet_option_source_prefix_length_ceiled as usize],
                            );
                        let ipv6_address = Ipv6Addr::from(ipv6_addr_vec);
                        probe_item.edns_subnet_prefix_length = subnet_option_source_prefix_length;
                        probe_item.edns_subnet_enabled = true;
                        probe_item.edns_subnet = ipv6_address.to_string();
                    } else {
                        error!("unknown subnet_option_family: {}", subnet_option_family)
                    }
                }
            }
        }
        let totp = dns_message_query_name_string
            .split('.')
            .next()
            .unwrap()
            .to_string();
        {
            let mut hashmap = if is_v4 {
                CACHED_PROBE_ITEMS_V4.lock().unwrap()
            } else {
                CACHED_PROBE_ITEMS_V6.lock().unwrap()
            };
            if let Some(values) = hashmap.get_mut(&totp) {
                values.1.insert(probe_item.clone());
            } else {
                error!("unknown dns query: {}", dns_message_query_name_string)
            }
        }
    }
}

fn ip_dns_check_handler_main(addr: SocketAddr, req: Request<()>) -> Response<Vec<u8>> {
    let args = Cli::parse();
    let domain = args.domain;
    let mut response: Response<Vec<u8>> = http::Response::builder()
        .status(StatusCode::OK)
        .body(Vec::new())
        .unwrap();

    // Only allow requests from within the main page
    response.headers_mut().insert(
        http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_str(format!("https://{domain}").as_str()).unwrap(),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_str(format!("max-age={}", dns_probe_lib::PROBE_TOTP_TIME_STEP).as_str())
            .unwrap(),
    );
    let h1_host = req.headers().get("host").map(|s| s.to_str().unwrap());
    let h2_host = req.uri().host();
    let host = h2_host.or(h1_host);
    let path = req.uri().path();
    let query_opt = req.uri().query();
    let method = req.method();
    if method != &Method::GET || host.is_none() {
        error!(
            "illegal request, method: {}, host: {}, path: {}, ip: {}",
            method,
            req.uri().host().unwrap_or("None"),
            path,
            addr.ip()
        );
        *response.status_mut() = StatusCode::FORBIDDEN;
        return response;
    }
    let host = host.unwrap();

    if path != "/" {
        error!(
            "unknown request path, method: {}, host: {}, path: {}",
            method,
            req.uri().host().unwrap_or("None"),
            path,
        );
        *response.status_mut() = StatusCode::NOT_FOUND;
        return response;
    }

    let host_without_colon = host.split(':').next().unwrap().to_lowercase();
    let components: Vec<&str> = host_without_colon.split('.').collect();
    if !host_without_colon.ends_with(domain.as_str()) || components.len() <= 2 {
        error!(
            "bad request, method: {}, host: {}, path: {}, ip: {}",
            method,
            host,
            path,
            addr.ip()
        );
        *response.status_mut() = StatusCode::NOT_FOUND;
        return response;
    }

    let is_ip_checking_request =
        components[0] == "ip" && (components[1] == "v4" || components[1] == "v6");

    let totp = components[0];
    let is_v4 = components[1] == "v4";
    let mut hashmap = if is_v4 {
        CACHED_PROBE_ITEMS_V4.lock().unwrap()
    } else {
        CACHED_PROBE_ITEMS_V6.lock().unwrap()
    };
    let values_opt = hashmap.get_mut(totp);
    if !is_ip_checking_request && values_opt.is_none() {
        info!(
            "unknown request, method: {}, host: {}, path: {}",
            method, host, path,
        );
        *response.status_mut() = StatusCode::NOT_FOUND;
        return response;
    }

    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_str(format!("max-age={}", dns_probe_lib::PROBE_TOTP_TIME_STEP).as_str())
            .unwrap(),
    );

    if is_ip_checking_request {
        // ip checking request
        let is_json_request = if let Some(query) = query_opt {
            query.contains("type=json")
        } else {
            false
        };
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            if is_json_request {
                HeaderValue::from_static("application/json")
            } else {
                HeaderValue::from_static("text/plain")
            },
        );
        let response_str = if is_json_request {
            if let Some(asn) = ASN_HANDLE.lookup_by_ip(addr.ip()) {
                format!(
                        "{{\"ip\": \"{}\",\"number\": \"{}\", \"country\": \"{}\", \"description\": \"{}\"}}",
                        addr.ip().to_string(),
                        asn.number,
                        asn.country,
                        asn.description
                    )
            } else {
                format!("{{\"ip\": \"{}\"}}", addr.ip().to_string())
            }
        } else {
            format!("{}", addr.ip().to_string())
        };

        let mut body_bytes = Vec::from(response_str);
        response.body_mut().append(&mut body_bytes);

        return response;
    }

    // dns probing request
    let values = values_opt.unwrap();
    let is_result_request = if let Some(query) = query_opt {
        query.contains("t=t4")
    } else {
        false
    };
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        if is_result_request {
            HeaderValue::from_static("application/json")
        } else {
            HeaderValue::from_static("text/plain")
        },
    );

    let timing_info = &mut values.0;
    let mut wait_for_t3 = false;

    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wrong time")
        .as_millis();
    if timing_info.t2 == 0 {
        timing_info.t2 = t;
        info!("wait for t3 request: {}", totp);
        wait_for_t3 = true;
    } else if timing_info.t3 == 0 {
        timing_info.t3 = t;
    }

    if !is_result_request {
        return response;
    }

    let delta1 = timing_info.t2 - timing_info.t0;
    let delta2 = timing_info.t3 - timing_info.t2;
    let dns_resolve_latency = if delta1 > delta2 { delta1 - delta2 } else { 0 };
    info!(
        "result request for: {}, wait_for_t3: {}, t0: {}, t1: {}, t2: {}, t3: {}, count: {}",
        totp,
        wait_for_t3,
        timing_info.t0,
        timing_info.t1,
        timing_info.t2,
        timing_info.t3,
        values.1.len()
    );

    let mut dns_response: String = "".to_string();
    let mut values = values.1.clone();

    // Also add the probe items of another internet protocol
    if is_v4 {
        let mut hashmap = CACHED_PROBE_ITEMS_V6.lock().unwrap();
        if let Some(values_opt) = hashmap.get_mut(totp) {
            let set = values_opt.1.clone();
            for v in set {
                values.insert(v);
            }
            values_opt.1.clear();
        }
    } else {
        let mut hashmap = CACHED_PROBE_ITEMS_V4.lock().unwrap();
        if let Some(values_opt) = hashmap.get_mut(totp) {
            let set = values_opt.1.clone();
            for v in set {
                values.insert(v);
            }
            values_opt.1.clear();
        }
    };
    dns_response += "{";
    dns_response += format!("\"latency\": {}, \"resolvers\": ", dns_resolve_latency).as_str();
    dns_response += "[";
    for value in &values {
        let ip: IpAddr = value.remote_address.parse().unwrap();
        if let Some(asn) = ASN_HANDLE.lookup_by_ip(ip) {
            dns_response += format!("{{\"resolver_ip\": \"{}\", \"asn\": {{\"number\": \"{}\", \"country\": \"{}\", \"description\": \"{}\"}}, \"edns_enabled\": {}, \"is_tcp_request\": {}, \"edns_subnet\": \"{}/{}\"}},",
                                        value.remote_address,
                                        asn.number,
                                        asn.country,
                                        asn.description,
                                        value.edns_subnet_enabled,
                                        value.is_tcp_request,
                                        value.edns_subnet,
                                        value.edns_subnet_prefix_length
                                    ).as_str();
        } else {
            dns_response += format!("{{\"resolver_ip\": \"{}\", \"edns_enabled\": {}, \"is_tcp_request\": {}, \"edns_subnet\": \"{}/{}\"}},",
                                            value.remote_address,
                                            value.edns_subnet_enabled,
                                            value.is_tcp_request,
                                            value.edns_subnet,
                                            value.edns_subnet_prefix_length
                                        ).as_str();
        }
    }
    if values.len() > 0 {
        // remove last ','
        let _ = dns_response.pop();
    }
    dns_response += "]";
    dns_response += "}";

    // clear entry
    hashmap.remove(totp);

    let mut body_bytes = Vec::from(dns_response);
    response.body_mut().append(&mut body_bytes);

    response
}

fn notify_id_gen_t0(totp: String, is_ipv6: bool) {
    debug!("id gen received: {}", totp);
    let mut hashmap = if is_ipv6 {
        CACHED_PROBE_ITEMS_V6.lock().unwrap()
    } else {
        CACHED_PROBE_ITEMS_V4.lock().unwrap()
    };
    let t0 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wrong time")
        .as_millis();

    if let Some(item) = hashmap.get_mut(&totp) {
        item.0.t0 = t0;
    } else {
        let values: HashSet<ProbeItem> = HashSet::new();
        hashmap.insert(totp, (TimingInfo::new(t0, 0, 0, 0), values));
    }

    let mut removed: Vec<String> = Vec::new();
    for (k, val) in hashmap.iter() {
        if val.0.t0 > 0 && (t0 - val.0.t0) / 1000 > dns_probe_lib::PROBE_DNS_REQUEST_TIMEOUT as u128
        {
            removed.push(k.clone());
        }
    }
    let removed_count = removed.len();
    for k in removed {
        hashmap.remove(&k);
    }
    if removed_count > 0 {
        info!("remove {} lagacy entry", removed_count);
    }
}

fn homepage_handler_main(socket: SocketAddr, req: Request<()>) -> Response<Vec<u8>> {
    let args = Cli::parse();
    let domain = args.domain;
    let mut site_root = args.site_root_dir;
    while site_root.ends_with("/") {
        site_root.pop();
    }
    let h1_host = req.headers().get("host").map(|s| s.to_str().unwrap());
    let h2_host = req.uri().host();
    let host = h2_host.or(h1_host);
    let path = req.uri().path();
    let method = req.method();

    let mut resp: Response<Vec<u8>> = http::Response::builder()
        .status(StatusCode::OK)
        .body(Vec::new())
        .unwrap();
    if method != &Method::GET || host.is_none() {
        error!(
            "illegal request, method: {}, host: {}, path: {}, ip: {}",
            method,
            req.uri().host().unwrap_or("None"),
            path,
            socket.ip()
        );
        *resp.status_mut() = StatusCode::FORBIDDEN;
        return resp;
    }

    let host = host.unwrap();
    let host_without_colon = host.split(':').next().unwrap().to_lowercase();
    if domain != host_without_colon {
        error!(
            "unknown host, method: {}, host: {}, path: {}, ip: {}",
            method,
            host,
            path,
            socket.ip()
        );
        *resp.status_mut() = StatusCode::NOT_FOUND;
        return resp;
    }

    if path != "/" {
        if path.contains("..") {
            error!(
                "illegal request path, method: {}, host: {}, path: {}",
                method,
                req.uri().host().unwrap_or("None"),
                path,
            );
            *resp.status_mut() = StatusCode::NOT_FOUND;
            return resp;
        }

        // resource request
        let request_file_path = site_root + path;
        let f_opt = File::open(request_file_path);
        if f_opt.is_err() {
            error!(
                "file not found, method: {}, host: {}, path: {}",
                method, host, path,
            );
            *resp.status_mut() = StatusCode::NOT_FOUND;
            return resp;
        }

        let mut f = f_opt.unwrap();
        let mut data = vec![];
        f.read_to_end(&mut data).unwrap();

        let file_ext = path.split(".").last().unwrap().to_lowercase();
        let file_type = match file_ext.as_str() {
            "ico" => {
                format!("image/vnd.microsoft.icon")
            }
            "jpg" | "jpeg" => {
                format!("image/jpeg")
            }
            "svg" => {
                format!("image/svg+xml")
            }
            "png" | "gif" => {
                format!("image/{file_ext}")
            }
            "webmanifest" => {
                format!("application/manifest+json")
            }
            "xml" => {
                format!("application/xml")
            }
            "txt" => {
                format!("text/plain")
            }
            _ => {
                format!("text/plain")
            }
        };
        resp.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(&file_type).unwrap(),
        );

        resp.headers_mut().insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_str("max-age=6048000").unwrap(),
        );

        resp.body_mut().append(&mut data);
        return resp;
    }

    resp.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_str(format!("max-age={}", dns_probe_lib::PROBE_TOTP_TIME_STEP).as_str())
            .unwrap(),
    );
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );

    // Write the response
    let totp_v4 = dns_probe_lib::generate_rand_str();
    // To get full dns resolver ip list, we use the same key here.
    let totp_v6 = totp_v4.clone();

    let body: String = HTML_TEMPLATE
        .replace(
            "${0}",
            format!(
                "You are connecting to this site using HTTP/{}.",
                match req.version() {
                    Version::HTTP_09 => "0.9",
                    Version::HTTP_10 => "1.0",
                    Version::HTTP_11 => "1.1",
                    Version::HTTP_2 => "2.0",
                    Version::HTTP_3 => "3.0",
                    _ => "unknown",
                }
            )
            .as_str(),
        )
        .replace("${1}", totp_v4.as_str())
        .replace("${2}", totp_v6.as_str());
    let mut body_bytes = Vec::from(body);
    resp.body_mut().append(&mut body_bytes);

    notify_id_gen_t0(totp_v4, false);
    notify_id_gen_t0(totp_v6, true);

    resp
}
