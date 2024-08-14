pub const HEADER_LEN: usize = 12;
pub const PROBE_PAYLOAD_LEN: usize = 4096;

pub const PROBE_TOTP_SHARED_SECRET: &str = "E0750706-F5E3-43C5-9805-55014AE85BC2";
pub const PROBE_TOTP_SHARED_KEY: &str = "11112222";
pub const PROBE_TOTP_TIME_STEP: u64 = 5;
pub const PROBE_DNS_REQUEST_TIMEOUT: u64 = 30;
pub const PROBE_DNS_ANSWER_DELAY: u64 = 5;

pub const PROBE_FRONTEND_UDP_ID_GEN_NOTIFY_SEND_TIMEOUT: u64 = 1;
pub const PROBE_FRONTEND_UDP_ID_GEN_MAX_RETRIES: u64 = 5;

pub struct ProbePayload {
    pub remote_addr: std::net::SocketAddr,
    pub additional_info: Vec<u8>,
    pub request_payload: Vec<u8>,
}

impl ProbePayload {
    pub fn to_data(self: &Self) -> [u8; PROBE_PAYLOAD_LEN] {
        use byteorder::{BigEndian, WriteBytesExt};

        // send probe packet
        let mut probe_buffer = [0; PROBE_PAYLOAD_LEN];

        // Part 1: header (4 + 4 + 4 = 12bytes)
        let mut header_buffer = [0; HEADER_LEN];
        let mut header_vec = &mut header_buffer[..HEADER_LEN];

        // Part 2: remote address (50bytes)
        header_vec
            .write_u32::<BigEndian>(self.remote_addr.to_string().len() as u32)
            .unwrap();

        // Part 3: Additional information (414bytes)
        header_vec
            .write_u32::<BigEndian>(self.additional_info.len() as u32)
            .unwrap();

        // Part 4: DNS payload (512bytes)
        header_vec
            .write_u32::<BigEndian>(self.request_payload.len() as u32)
            .unwrap();

        probe_buffer[..HEADER_LEN].clone_from_slice(&header_buffer);
        probe_buffer[HEADER_LEN..HEADER_LEN + self.remote_addr.to_string().len()]
            .clone_from_slice(&self.remote_addr.to_string().as_bytes());
        probe_buffer[HEADER_LEN + self.remote_addr.to_string().len()
            ..HEADER_LEN + self.remote_addr.to_string().len() + self.additional_info.len()]
            .clone_from_slice(&self.additional_info);
        probe_buffer[HEADER_LEN + self.remote_addr.to_string().len() + self.additional_info.len()
            ..HEADER_LEN
                + self.remote_addr.to_string().len()
                + self.additional_info.len()
                + self.request_payload.len()]
            .clone_from_slice(&self.request_payload);
        return probe_buffer;
    }

    pub fn from_data(data: [u8; PROBE_PAYLOAD_LEN]) -> Self {
        use byteorder::{BigEndian, ReadBytesExt};
        use std::str;

        let _dns_probe_payload = &data[..PROBE_PAYLOAD_LEN];
        let mut header_vec = &data[..HEADER_LEN];

        let remote_address_buffer_len = header_vec.read_u32::<BigEndian>().unwrap() as usize;
        let additional_buffer_len = header_vec.read_u32::<BigEndian>().unwrap() as usize;
        let dns_payload_buffer_len = header_vec.read_u32::<BigEndian>().unwrap() as usize;

        let remote_address_vec = &data[HEADER_LEN..HEADER_LEN + remote_address_buffer_len as usize];
        let addtional_vec = &data[HEADER_LEN + remote_address_buffer_len
            ..HEADER_LEN + remote_address_buffer_len + additional_buffer_len];
        let dns_payload = &data[HEADER_LEN + remote_address_buffer_len + additional_buffer_len
            ..HEADER_LEN
                + remote_address_buffer_len
                + additional_buffer_len
                + dns_payload_buffer_len as usize];

        let remote_address_str = str::from_utf8(remote_address_vec).unwrap().to_string();
        let remote_address_socket: std::net::SocketAddr =
            remote_address_str.parse().expect("failed to convert");

        return ProbePayload {
            remote_addr: remote_address_socket,
            additional_info: addtional_vec.to_vec(),
            request_payload: dns_payload.to_vec(),
        };
    }
}

pub fn generate_rand_str() -> String {
    use rand::distributions::{Alphanumeric, DistString};
    let string = Alphanumeric
        .sample_string(&mut rand::thread_rng(), 8)
        .to_lowercase();
    return string;
}

#[macro_use]
extern crate log;
extern crate env_logger;
pub fn setup_panic_hook() {
    use std::panic;
    use std::process;

    // take_hook() returns the default hook in case when a custom one is not set
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            error!("panic occurred: {s:?}");
        } else {
            error!("panic occurred");
        }
        orig_hook(panic_info);
        process::exit(1);
    }));
}

#[cfg(test)]
mod tests {
    use super::generate_rand_str;
    use std::str::FromStr;

    #[test]
    fn rand_str() {
        let mut ne = true;
        let mut i = 999;
        while i > 0 {
            let str1 = generate_rand_str();
            let str2 = generate_rand_str();
            if str1 == str2 {
                ne = false;
                break;
            }
            i = i - 1;
        }

        assert_eq!(ne, true);

        use byteorder::{BigEndian, WriteBytesExt};
        use std::io::Write;

        let id = generate_rand_str();
        let mut id_gen_buffer = [0; 256];
        let mut id_gen_vec = &mut id_gen_buffer[..];
        id_gen_vec.write_u32::<BigEndian>(id.len() as u32).unwrap();
        let _ = id_gen_vec.write_fmt(format_args!("{}", id));
    }

    #[test]
    fn test_socket() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        let socket_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 71, 217, 59)), 36463);
        let socket_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080);

        assert_eq!(SocketAddr::from_str("172.71.217.59:36463"), Ok(socket_v4));
        assert_eq!(SocketAddr::from_str("[::1]:8080"), Ok(socket_v6));
    }
}
