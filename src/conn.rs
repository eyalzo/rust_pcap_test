use std::fmt;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::time::Instant;
use etherparse::{TcpHeaderSlice, TcpOptionElement};
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
        let sign = (u32::from_be_bytes(dst_ip.octets()) as u128) << 16 |
            (dst_port as u128) |
            (u32::from_be_bytes(src_ip.octets()) as u128) << 64 |
            (src_port as u128) << 48;
        return (sign, PacketDir::SrcHighAddr);
    }

    pub fn add_bytes(&mut self, tcp_seq: u32, byte_count: usize, packet_dir: &PacketDir, data: &[u8]) {
        match packet_dir {
            PacketDir::SrcLowAddr => {
                self.flow_src_low.add_bytes(tcp_seq, byte_count, data);
            }
            PacketDir::SrcHighAddr => {
                self.flow_src_high.add_bytes(tcp_seq, byte_count, data);
            }
        }
    }

    /// Check if this connection has bytes ready to process in one of the directions.
    /// This means that at least the number of requested bytes are present in a buffer from the current position.
    pub(crate) fn has_ready_bytes(&self, min_ready_bytes: usize) -> bool {
        return self.flow_src_low.has_ready_bytes(min_ready_bytes) || self.flow_src_high.has_ready_bytes(min_ready_bytes);
    }

    /// Get a direction that has a significant buffer ready to process, or if the connection is closed and has something to process.
    pub(crate) fn pop_ready_buffer(&self, closed_connection: bool, min_ready_bytes: usize) -> Option<&FlowBuff> {
        if self.flow_src_low.has_ready_buffer(closed_connection, min_ready_bytes) { return Some(&self.flow_src_low); }
        if self.flow_src_high.has_ready_buffer(closed_connection, min_ready_bytes) { return Some(&self.flow_src_high); }
        return None;
    }

    fn relative_seq(&self, packet_dir: &PacketDir, seq: u32) -> u64 {
        let flow = match packet_dir {
            PacketDir::SrcLowAddr => { &self.flow_src_low }
            _ => { &self.flow_src_high }
        };

        flow.relative_seq(seq)
    }

    fn relative_ack(&self, packet_dir: &PacketDir, ack: u32) -> u64 {
        let flow = match packet_dir {
            PacketDir::SrcLowAddr => { &self.flow_src_high }
            _ => { &self.flow_src_low }
        };

        flow.relative_seq(ack)
    }

    fn scaled_window(&self, packet_dir: &PacketDir, window: u16) -> u32 {
        match packet_dir {
            PacketDir::SrcLowAddr => { self.flow_src_high.scaled_window(window) }
            _ => { self.flow_src_low.scaled_window(window) }
        }
    }

    /// Process TCP options. To be called when detecting a proper SYN packet.
    /// For now, it only looks for window scaling for later display.
    pub(crate) fn process_tcp_options(&mut self, packet_dir: &PacketDir, tcp: &TcpHeaderSlice) {
        let flow = match packet_dir {
            PacketDir::SrcLowAddr => { &mut self.flow_src_low }
            _ => { &mut self.flow_src_high }
        };

        for option in tcp.options_iterator() {
            match option {
                Ok(element) => {
                    match element {
                        TcpOptionElement::MaximumSegmentSize(_) => {
                            //TODO save MSS and use it when opening connections
                        }
                        TcpOptionElement::WindowScale(window_scale) => {
                            if window_scale >= 1 && window_scale <= 14 {
                                flow.window_scale = 2u16.pow(window_scale as u32);
                            }
                        }
                        _ => {}
                    }
                }
                Err(_) => {}
            }
        }
    }

    pub(crate) fn log(&self, tcp: &TcpHeaderSlice, tcp_payload_len: u16, packet_dir: &PacketDir) {
        let log_level: Option<Level>;
        // Determine log level by connection's state
        match self.state {
            ConnState::Established(_) => {
                // If it was just established now by one of the parties
                if tcp.syn() {
                    log_level = Some(Level::Debug);
                } else {
                    if !log_enabled!(Level::Trace) { return; }
                    log_level = Some(Level::Trace);
                    if tcp_payload_len == 0 {
                        if tcp.ack() {
                            log!(Level::Trace, "TCP {}: {} ack {}, win {}",
                                         self.conn_sequence,
                match packet_dir { PacketDir::SrcLowAddr => {"=>"}, _=>{"<="} },
                                         self.relative_ack(packet_dir, tcp.acknowledgment_number()),
                            self.scaled_window(packet_dir, tcp.window_size()));
                            return;
                        }
                    } else {
                        log!(Level::Trace, "TCP {}: {} seq {}, len {}",
                                         self.conn_sequence,
                match packet_dir { PacketDir::SrcLowAddr => {"=>"}, _=>{"<="} },
                                         self.relative_seq(packet_dir, tcp.sequence_number()),
                            tcp_payload_len);
                        return;
                    }
                }
            }
            ConnState::Created => {
                // This state after at least one packet, means that the first packet was not SYN
                // It probably means that we watch an already established connection so we should ignore it
                log_level = Some(Level::Trace)
            }
            _ => { log_level = Some(Level::Debug) }
        };
        if log_enabled!(log_level.unwrap()) {
            log!(log_level.unwrap(), "TCP {}: {} {} {}, len {}, {} {:?}",
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