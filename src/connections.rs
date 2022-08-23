use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use log::{warn};
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::Packet;
use crate::conn::Conn;
use crate::conn::ConnState;

/// Hold TCP connections, along with statistics per connection and timeouts
#[derive(Clone)]
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
                v.insert(Conn::new(self.conn_alltime_count, conn_sign))
            }
        }
    }

    /// Get all the connections that are closed or have a significant buffer ready to process.
    /// Result may be empty if no connections match.
    pub fn get_connections_by_rules(&mut self, closed: bool, min_ready_bytes: usize) -> Vec<&Conn> {
        let mut result: Vec<&Conn> = Vec::new();

        for (_, conn) in &self.conn_list {
            if closed {
                if matches!(conn.state, ConnState::Closed(_)) {
                    result.push(conn);
                    continue;
                }
            }

            if conn.has_ready_bytes(min_ready_bytes) {
                result.push(conn);
            }
        }

        return result;
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
                                                conn.set_initial_sequence_number(&packet_dir, tcp.sequence_number());
                                                conn.process_tcp_options(&packet_dir, &tcp);
                                            }
                                        }
                                        ConnState::SynSent(syn_dir, expected_tcp_ack) => {
                                            if tcp.syn() && tcp.ack() && syn_dir != &packet_dir && tcp.acknowledgment_number() == *expected_tcp_ack {
                                                conn.state = ConnState::Established(syn_dir.to_owned());
                                                conn.set_initial_sequence_number(&packet_dir, tcp.sequence_number());
                                                conn.process_tcp_options(&packet_dir, &tcp);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                conn.add_bytes(tcp.sequence_number(), tcp_payload_len as usize, &packet_dir, packet);
                                conn.log(&tcp, tcp_payload_len, &packet_dir);
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
