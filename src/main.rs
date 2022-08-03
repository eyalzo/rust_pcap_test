mod connections;

use std::collections::HashMap;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use log::{debug, info, trace};
use pcap::Device;
use crate::connections::{Conn};

fn main() {
    info!("Start pcap_test...");

    // Connection list
    let mut conn_list: HashMap<u128, Conn> = HashMap::new();

    let device_list = Device::list().expect("Failed to get device list");
    info!("Device list has {} elements. Those with addresses:", device_list.len());
    for cur_device in device_list {
        if cur_device.addresses.len() <= 0 { continue; }
        debug!("   Device '{}' = {} ({} addresses)", cur_device.name,
                 cur_device.desc.unwrap_or(String::from("unknown")),
                 cur_device.addresses.len());
        for cur_addr in cur_device.addresses {
            trace!("      {}", cur_addr.addr);
        }
    }

    // Get the default device
    let mut cap = Device::lookup().unwrap().open().unwrap();

    info!("Default device: {:?} ({:?})", cap.get_datalink().get_name().unwrap(),
             cap.get_datalink().get_description().unwrap());

    let mut packet_count = 0;
    while let Ok(packet) = cap.next() {
        packet_count += 1;
        // println!("received packet! {:?}", packet);
        trace!("   Packet {}, caplen: {}, packetlen: {}", packet_count, packet.len(), packet.header.len);
        // Parse
        match SlicedPacket::from_ethernet(&packet) {
            Err(value) => println!("Err {:?}", value),
            Ok(value) => {
                // For TCP packets, there should be link, ip and transport values
                if !value.ip.is_some() || !value.transport.is_some() { continue; }

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
                                let new_seq = conn_list.len() as u16 + 1;
                                let conn = conn_list.entry(conn_sign).or_insert(Conn::new(new_seq));
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

    println!("End pcap_test.");
}
