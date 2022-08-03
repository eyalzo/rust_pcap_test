use std::net::Ipv4Addr;
use std::time::Instant;

pub struct Conn {
    /// When the structure was initialized
    start_time: Instant,
    /// Sequence of the connection
    pub(crate) sequence: u16,
    /// Total number of TCP payload bytes so far. May contain duplicates in case of retransmissions
    pub(crate) total_bytes: u64,
}

impl Conn {
    pub(crate) fn new(sequence: u16) -> Self {
        Self { start_time: Instant::now(), sequence, total_bytes: 0 }
    }

    pub fn sign_by_tuple(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> u128 {
        let sign: u128 = (u32::from_be_bytes(src_ip.octets()) as u128) |
            (src_port as u128) << 32 |
            (u32::from_be_bytes(dst_ip.octets()) as u128) << 48 |
            (dst_port as u128) << 80;
        return sign;
    }

    pub fn add_bytes(&mut self, byte_count: u64) {
        self.total_bytes += byte_count;
    }
}