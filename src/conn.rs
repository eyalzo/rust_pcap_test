use std::fmt;
use std::net::Ipv4Addr;
use std::time::Instant;
use crate::flow_buff::FlowBuff;

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
    /// Buffer and statistics for flow from low to high address
    pub(crate) flow_src_low: FlowBuff,
    /// Buffer and statistics for flow from high to low address
    pub(crate) flow_src_high: FlowBuff,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "state: {:?}, packets: {}/{}, bytes: {}/{}, time: {}ms", self.state, self.flow_src_low.packet_count,
               self.flow_src_high.packet_count, self.flow_src_low.byte_count, self.flow_src_high.byte_count,
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
    /// The sender of the related packet is the lower address (IP, then port)
    SrcLowAddr,
    /// The sender of the related packet is the higher address (IP, then port)
    SrcHighAddr,
}

impl Conn {
    pub(crate) fn new(conn_sequence: u32) -> Self {
        Self {
            state: ConnState::Created,
            start_time: Instant::now(),
            conn_sequence,
            flow_src_low: FlowBuff::new(),
            flow_src_high: FlowBuff::new(),
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
        return (sign, PacketDir::SrcHighAddr);
    }

    pub fn add_bytes(&mut self, byte_count: u64, packet_dir: &PacketDir) {
        match packet_dir {
            PacketDir::SrcLowAddr => {
                self.flow_src_low.add_bytes(byte_count);
            }
            PacketDir::SrcHighAddr => {
                self.flow_src_high.add_bytes(byte_count);
            }
        }
    }
}