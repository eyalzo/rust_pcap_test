use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Instant;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::Packet;

#[derive(Debug, Clone)]
pub struct Connections {
    /// Active connection list
    conn_list: HashMap<u128, Conn>,
    /// All time counter of connections added to list, including removed ones
    conn_count: u32,
    /// All time packets count, including errors, duplicates, etc.
    packet_count: u64,
    /// Number of times the packet was not processed because capture was too short
    packet_len_error_count: u64,
}

impl Connections {
    pub fn new() -> Connections {
        Connections {
            conn_list: HashMap::new(),
            conn_count: 0,
            packet_count: 0,
            packet_len_error_count: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet) {
        self.packet_count += 1;
        if (packet.len() as u32) < packet.header.len {
            self.packet_len_error_count += 1;
            return;
        }

        // Parse
        match SlicedPacket::from_ethernet(packet) {
            Err(value) => println!("Err {:?}", value),
            Ok(value) => {
                // For TCP packets, there should be link, ip and transport values
                if !value.ip.is_some() || !value.transport.is_some() { return; }

                // IP addresses
                match value.ip.unwrap() {
                    InternetSlice::Ipv4(ip_header, _) => {
                        match value.transport.unwrap() {
                            TransportSlice::Tcp(tcp) => {
                                // IP payload is already calculated, while TCP header is that 32-bit units (see RFC)
                                let tcp_payload_len = ip_header.payload_len() - 4 * tcp.data_offset() as u16;
                                let conn_sign = Conn::sign_by_tuple(ip_header.source_addr(),
                                                                    tcp.source_port(),
                                                                    ip_header.destination_addr(),
                                                                    tcp.destination_port());
                                let new_seq = self.conn_list.len() as u16 + 1;
                                let conn = self.conn_list.entry(conn_sign).or_insert(Conn::new(new_seq));
                                // A little odd way to count connections but it works for now
                                if conn.packet_count == 0 { self.conn_count += 1; }
                                conn.add_bytes(tcp_payload_len as u64);
                                println!("      TCP {}: {:?}:{} => {:?}:{}, len {}, {:?}",
                                         conn.sequence,
                                         ip_header.source_addr(),
                                         tcp.source_port(),
                                         ip_header.destination_addr(),
                                         tcp.destination_port(),
                                         tcp_payload_len,
                                         conn);
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Conn {
    /// When the structure was initialized
    start_time: Instant,
    /// Sequence of the connection
    pub(crate) sequence: u16,
    /// Total number of TCP payload bytes so far. May contain duplicates in case of retransmissions
    pub(crate) total_bytes: u64,
    /// Number of packets. Can be empty packets or overlap sequences
    pub(crate) packet_count: u32,
}

impl Conn {
    pub(crate) fn new(sequence: u16) -> Self {
        Self { start_time: Instant::now(), sequence, total_bytes: 0, packet_count: 0 }
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
        self.packet_count += 1;
    }
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "packets: {}, bytes: {}, time: {}ms", self.packet_count, self.total_bytes, self.start_time.elapsed().as_millis())
    }
}