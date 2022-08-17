use std::fmt;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::time::Instant;
use etherparse::{TcpHeaderSlice};
use log::{Level, log, log_enabled};
use crate::flow_buff::FlowBuff;
use crate::utils::tcp_flags_to_string;

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
    /// Signature made of IPs and ports
    conn_sign: u128,
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
    pub(crate) fn new(conn_sequence: u32, conn_sign: u128) -> Self {
        Self {
            state: ConnState::Created,
            start_time: Instant::now(),
            conn_sequence,
            conn_sign,
            flow_src_low: FlowBuff::new(),
            flow_src_high: FlowBuff::new(),
        }
    }

    /// Save the ISN per flow, to be used later for sequence tracing and buffering.
    pub fn set_initial_sequence_number(&mut self, packet_dir: &PacketDir, initial_sequence_number: u32) {
        match packet_dir {
            PacketDir::SrcLowAddr => { self.flow_src_low.set_initial_sequence_number(initial_sequence_number) }
            PacketDir::SrcHighAddr => { self.flow_src_high.set_initial_sequence_number(initial_sequence_number) }
        }
    }

    /// Get the "IP:port" of the lower or higher address.
    pub fn addresses_as_str(&self, low_address: bool) -> String {
        // Each IP is 4*8=32 bits, and port is 16 bits
        // The higher IP:port gets the higher bits
        if low_address {
            return format!("{}.{}.{}.{}:{}", (self.conn_sign >> 40) as u8, (self.conn_sign >> 32) as u8,
                           (self.conn_sign >> 24) as u8, (self.conn_sign >> 16) as u8, self.conn_sign as u16);
        }
        return format!("{}.{}.{}.{}:{}", (self.conn_sign >> 88) as u8, (self.conn_sign >> 80) as u8,
                       (self.conn_sign >> 72) as u8, (self.conn_sign >> 64) as u8, (self.conn_sign >> 56) as u16);
    }

    /// Connection signature by 4-tuple, sorted by address, so both directions get the same deterministic signature
    /// Return the signature, along with the direction to be used later for statistics
    pub fn sign_by_tuple(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> (u128, PacketDir) {
        if src_ip < dst_ip || src_port < dst_port {
            let sign = (u32::from_be_bytes(src_ip.octets()) as u128) << 16 |
                (src_port as u128) |
                (u32::from_be_bytes(dst_ip.octets()) as u128) << 64 |
                (dst_port as u128) << 48;
            return (sign, PacketDir::SrcLowAddr);
        }
        let sign = (u32::from_be_bytes(dst_ip.octets()) as u128) << 16|
            (dst_port as u128) |
            (u32::from_be_bytes(src_ip.octets()) as u128) << 64 |
            (src_port as u128) << 48;
        return (sign, PacketDir::SrcHighAddr);
    }

    pub fn add_bytes(&mut self, tcp_seq: u32, byte_count: u64, packet_dir: &PacketDir) {
        match packet_dir {
            PacketDir::SrcLowAddr => {
                self.flow_src_low.add_bytes(tcp_seq, byte_count);
            }
            PacketDir::SrcHighAddr => {
                self.flow_src_high.add_bytes(tcp_seq, byte_count);
            }
        }
    }

    pub(crate) fn log(&self, tcp: &TcpHeaderSlice, tcp_payload_len: u16, packet_dir: &PacketDir) {
        // Determine log level by connection's state
        let log_level = match self.state {
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
        if log_enabled!(log_level) {
            log!(log_level, "TCP {}: {} {} {}, len {}, {} {:?}",
                                         self.conn_sequence,
                                         self.addresses_as_str(true),
                match packet_dir { PacketDir::SrcLowAddr => {"=>"}, _=>{"<="} },
                                         self.addresses_as_str(false),
                                         tcp_payload_len,
                                    tcp_flags_to_string(&tcp),
                                         self);
        }
    }
}