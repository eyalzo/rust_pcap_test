use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Instant;
use log::{Level, log, warn};
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::Packet;
use crate::connections::PacketDir::SrcLowAddr;
use crate::utils::tcp_flags_to_string;

/// Hold TCP connections, along with statistics per connection and timeouts
#[derive(Debug, Clone)]
pub struct Connections {
    /// Active connection list
    /// Mapped by the 4-tuple, where the lower address is always considered "source" or xxx_1 in field names.
    conn_list: HashMap<u128, Conn>,
    /// All time counter of connections added to list, including removed ones
    /// Each connection holds everything related to both directions
    conn_alltime_count: u32,
    /// All time packets count, including all other packet_xxx_count fields, such as errors, duplicates, etc.
    packet_count: u64,
    /// Number of times the packet was not processed because capture was too short
    packet_len_error_count: u32,
    /// Number of times the packet was not processed because of parsing error
    packet_parsing_error_count: u32,
    /// Number of times the packet was not a TCP/IP, which is normal and pretty high if capturing UDP, ICMP etc
    packet_not_tcp_count: u32,
}

impl Connections {
    /// Create connections object only once
    /// Holds all the connections and related statistics
    pub fn new() -> Connections {
        Connections {
            conn_list: HashMap::new(),
            conn_alltime_count: 0,
            packet_count: 0,
            packet_len_error_count: 0,
            packet_parsing_error_count: 0,
            packet_not_tcp_count: 0,
        }
    }

    /// Get an existing connection by signature (TCP 4 tuple), or return a new connection
    fn get_connection_or_add_new(&mut self, conn_sign: u128) -> &mut Conn {
        match self.conn_list.entry(conn_sign) {
            Occupied(o) => { o.into_mut() }
            Vacant(v) => {
                self.conn_alltime_count += 1;
                v.insert(Conn::new(self.conn_alltime_count))
            }
        }
    }

    /// Process a pcap packet.
    /// It identifies the connection and handles everything related to statistics, state, etc.
    pub fn process_packet(&mut self, packet: &Packet) {
        self.packet_count += 1;
        // Check if the captured packet is complete
        if (packet.len() as u32) < packet.header.len {
            self.packet_len_error_count += 1;
            return;
        }

        // Parse
        match SlicedPacket::from_ethernet(packet) {
            Err(value) => {
                self.packet_parsing_error_count += 1;
                warn!("*** Parsing error: {:?}", value);
                return;
            }
            Ok(value) => {
                // For TCP packets, there should be link, ip and transport values
                if !value.ip.is_some() || !value.transport.is_some() {
                    self.packet_not_tcp_count += 1;
                    return;
                }

                // IP addresses
                match value.ip.unwrap() {
                    InternetSlice::Ipv4(ip_header, _) => {
                        match value.transport.unwrap() {
                            TransportSlice::Tcp(tcp) => {
                                // IP payload is already calculated, while TCP header is that 32-bit units (see RFC)
                                let tcp_payload_len = ip_header.payload_len() - 4 * tcp.data_offset() as u16;
                                let (conn_sign, packet_dir) = Conn::sign_by_tuple(ip_header.source_addr(),
                                                                                  tcp.source_port(),
                                                                                  ip_header.destination_addr(),
                                                                                  tcp.destination_port());
                                let conn = self.get_connection_or_add_new(conn_sign);
                                // Check for RST or ACK to a second (the other party) FIN
                                if tcp.rst() || matches!(&conn.state,ConnState::FinWait2(wait_dir, wait_ack)
                                    if wait_dir != &packet_dir && tcp.ack() && tcp.sequence_number() == *wait_ack)
                                {
                                    // With RST we don't care who sent first and we no longer handle data
                                    conn.state = ConnState::Closed(packet_dir.to_owned());
                                } else if tcp.fin() {
                                    match &conn.state {
                                        // Normal - one side signals that it wants to close
                                        ConnState::Established(_) => {
                                            conn.state = ConnState::FinWait1(packet_dir.to_owned(), tcp.sequence_number() + 1)
                                        }
                                        // The other side might also sent a FIN
                                        ConnState::FinWait1(wait_dir, _) => {
                                            if wait_dir != &packet_dir {
                                                conn.state = ConnState::FinWait2(packet_dir.to_owned(), tcp.sequence_number() + 1)
                                            }
                                        }
                                        // This can happen but normally should not
                                        _ => {}
                                    }
                                } else {
                                    // Check if connection is new and we still look for SYN
                                    match &conn.state {
                                        ConnState::Created => {
                                            // A SYN without ACK
                                            if tcp.syn() && !tcp.ack() {
                                                conn.state = ConnState::SynSent(packet_dir.to_owned(), tcp.sequence_number() + 1);
                                            }
                                        }
                                        ConnState::SynSent(syn_dir, expected_tcp_ack) => {
                                            if tcp.syn() && tcp.ack() && syn_dir != &packet_dir && tcp.acknowledgment_number() == *expected_tcp_ack {
                                                conn.state = ConnState::Established(syn_dir.to_owned());
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                conn.add_bytes(tcp_payload_len as u64, &packet_dir);
                                // Determine log level by connection's state
                                let log_level = match conn.state {
                                    ConnState::Established(_) => {
                                        // If it was just established now by one of the parties
                                        if tcp.syn() { Level::Debug } else { Level::Trace }
                                    }
                                    ConnState::Created => {
                                        // This state after at least one packet, means that the first packet was not SYN
                                        // It probably means that we watch an already established connection so we should ignore it
                                        Level::Trace
                                    }
                                    _ => { Level::Debug }
                                };
                                log!(log_level, "TCP {}: {:?}:{} => {:?}:{}, len {}, {} {:?}",
                                         conn.conn_sequence,
                                         ip_header.source_addr(),
                                         tcp.source_port(),
                                         ip_header.destination_addr(),
                                         tcp.destination_port(),
                                         tcp_payload_len,
                                    tcp_flags_to_string(&tcp),
                                         conn);
                            }
                            _ => {
                                self.packet_not_tcp_count += 1;
                                return;
                            }
                        }
                    }
                    _ => {
                        self.packet_not_tcp_count += 1;
                        return;
                    }
                }
            }
        }
    }
}

/// Hold a TCP connections, along with statistics
/// The lower address is always considered "source" or xxx_1 in field names.
#[derive(Clone)]
pub struct Conn {
    /// When the structure was initialized
    start_time: Instant,
    /// Connection state
    state: ConnState,
    /// Sequence of the connection (all time counter)
    pub(crate) conn_sequence: u32,
    /// Total number of TCP payload bytes so far, from lower to higher address
    /// May contain duplicates in case of retransmissions
    pub(crate) total_bytes_1: u64,
    /// Total number of TCP payload bytes so far, from higher to lower address
    /// May contain duplicates in case of retransmissions
    pub(crate) total_bytes_2: u64,
    /// Number of packets. Can be empty packets or overlap sequences, from lower to higher address
    pub(crate) packet_count_1: u32,
    /// Number of packets. Can be empty packets or overlap sequences, from higher to lower address
    pub(crate) packet_count_2: u32,
}

impl Conn {
    pub(crate) fn new(conn_sequence: u32) -> Self {
        Self {
            state: ConnState::Created,
            start_time: Instant::now(),
            conn_sequence,
            total_bytes_1: 0,
            total_bytes_2: 0,
            packet_count_1: 0,
            packet_count_2: 0,
        }
    }

    /// Connection signature by 4-tuple, sorted by address, so both directions get the same deterministic signature
    /// Return the signature, along with the direction to be used later for statistics
    pub fn sign_by_tuple(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> (u128, PacketDir) {
        if src_ip < dst_ip || src_port < dst_port {
            let sign = (u32::from_be_bytes(src_ip.octets()) as u128) |
                (src_port as u128) << 32 |
                (u32::from_be_bytes(dst_ip.octets()) as u128) << 48 |
                (dst_port as u128) << 80;
            return (sign, PacketDir::SrcLowAddr);
        }
        let sign = (u32::from_be_bytes(dst_ip.octets()) as u128) |
            (dst_port as u128) << 32 |
            (u32::from_be_bytes(src_ip.octets()) as u128) << 48 |
            (src_port as u128) << 80;
        return (sign, PacketDir::DstLowAddr);
    }

    pub fn add_bytes(&mut self, byte_count: u64, packet_dir: &PacketDir) {
        match packet_dir {
            SrcLowAddr => {
                self.total_bytes_1 += byte_count;
                self.packet_count_1 += 1;
            }
            PacketDir::DstLowAddr => {
                self.total_bytes_2 += byte_count;
                self.packet_count_2 += 1;
            }
        }
    }
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "state: {:?}, packets: {}/{}, bytes: {}/{}, time: {}ms", self.state, self.packet_count_1,
               self.packet_count_2, self.total_bytes_1, self.total_bytes_2,
               self.start_time.elapsed().as_millis())
    }
}

#[derive(Clone, Debug)]
enum ConnState {
    /// No SYN packets were detected yet
    Created,
    /// A SYN was detected, sent by the specified direction, carrying the specified TCP sequence
    SynSent(PacketDir, u32),
    /// Who sent the first SYN
    Established(PacketDir),
    /// Who sent the first FIN, along with the expected ack sequence from the other direction
    FinWait1(PacketDir, u32),
    /// Who sent the response FIN, along with the expected ack sequence from the other direction
    FinWait2(PacketDir, u32),
    /// Last one to send the RST or FIN
    Closed(PacketDir),
}

/// State direction is required because each connection handles both directions of traffic.
#[derive(Clone, Debug, PartialEq)]
pub enum PacketDir {
    /// The sender of the related packet is the connection's source address
    SrcLowAddr,
    /// The sender of the related packet is the connection's destination address
    DstLowAddr,
}