use std::fmt;
use std::net::Ipv4Addr;
use std::time::Instant;

/// Hold a TCP connections, along with statistics
/// The lower address is always considered "source" or xxx_1 in field names.
#[derive(Clone)]
pub struct Conn {
    /// When the structure was initialized
    start_time: Instant,
    /// Connection state
    pub(crate) state: ConnState,
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

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "state: {:?}, packets: {}/{}, bytes: {}/{}, time: {}ms", self.state, self.packet_count_1,
               self.packet_count_2, self.total_bytes_1, self.total_bytes_2,
               self.start_time.elapsed().as_millis())
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ConnState {
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
            PacketDir::SrcLowAddr => {
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