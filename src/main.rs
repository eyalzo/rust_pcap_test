use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use log::{debug, info, trace};
use pcap::Device;

fn main() {
    info!("Start pcap_test...");

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
                                println!("      TCP: {:?}:{} => {:?}:{}, len {}", ip_header.source_addr(),
                                         tcp.source_port(), ip_header.destination_addr(),
                                         tcp.destination_port(),
                                         tcp_payload_len);
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
