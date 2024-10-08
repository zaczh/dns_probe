use flate2::read::GzDecoder;
use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::prelude::*;
use std::net::IpAddr;
use std::ops::Bound::{Included, Unbounded};
use std::str::FromStr;

#[derive(Debug)]
pub struct ASN {
    pub first_ip: IpAddr,
    pub last_ip: IpAddr,
    pub number: u32,
    pub country: String,
    pub description: String,
}

impl PartialEq for ASN {
    fn eq(&self, other: &ASN) -> bool {
        self.first_ip == other.first_ip
    }
}

impl Eq for ASN {}

impl Ord for ASN {
    fn cmp(&self, other: &Self) -> Ordering {
        self.first_ip.cmp(&other.first_ip)
    }
}

impl PartialOrd for ASN {
    fn partial_cmp(&self, other: &ASN) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ASN {
    fn from_single_ip(ip: IpAddr) -> ASN {
        ASN {
            first_ip: ip,
            last_ip: ip,
            number: 0,
            country: String::new(),
            description: String::new(),
        }
    }
}

pub struct ASNs {
    asns: BTreeSet<ASN>,
}

impl ASNs {
    pub fn new(file_path: &str) -> Result<ASNs, &'static str> {
        info!("Loading the database");
        let f = File::open(file_path).expect("wrong asn db file path");
        let mut data = String::new();
        GzDecoder::new(f).read_to_string(&mut data).unwrap();
        let mut asns = BTreeSet::new();
        for line in data.split_terminator('\n') {
            let mut parts = line.split('\t');
            let first_ip = IpAddr::from_str(parts.next().unwrap()).unwrap();
            let last_ip = IpAddr::from_str(parts.next().unwrap()).unwrap();
            let number = u32::from_str(parts.next().unwrap()).unwrap();
            let country = parts.next().unwrap().to_owned();
            let description = parts.next().unwrap().to_owned();
            let asn = ASN {
                first_ip,
                last_ip,
                number,
                country,
                description,
            };
            asns.insert(asn);
        }
        info!("Database loaded");
        Ok(ASNs { asns })
    }

    pub fn lookup_by_ip(&self, ip: IpAddr) -> Option<&ASN> {
        let fasn = ASN::from_single_ip(ip);
        match self.asns.range((Unbounded, Included(&fasn))).next_back() {
            Some(found) if ip <= found.last_ip && found.number > 0 => Some(found),
            _ => None,
        }
    }
}
