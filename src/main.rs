use etherparse::{SlicedPacket, TransportSlice};
use pcap::Device;

fn main() {
    println!("Start pcap_test...");

    let device_list = Device::list().expect("Failed to get device list");
    println!("Device list has {} elements. Those with addresses:", device_list.len());
    for cur_device in device_list {
        if cur_device.addresses.len() <= 0 { continue; }
        println!("   Device '{}' = {} ({} addresses)", cur_device.name,
                 cur_device.desc.unwrap_or(String::from("unknown")),
                 cur_device.addresses.len());
        for cur_addr in cur_device.addresses {
            println!("      {}", cur_addr.addr);
        }
    }

    let mut cap = Device::lookup().unwrap().open().unwrap();

    println!("Default device name: {:?}", cap.get_datalink().get_name().unwrap());
    println!("Default device description: {:?}", cap.get_datalink().get_description().unwrap());

    let mut packet_count = 0;
    while let Ok(packet) = cap.next() {
        packet_count += 1;
        // println!("received packet! {:?}", packet);
        println!("   Packet {}, caplen: {}, packetlen: {}", packet_count, packet.len(), packet.header.len);
        // Parse
        match SlicedPacket::from_ethernet(&packet) {
            Err(value) => println!("Err {:?}", value),
            Ok(value) => {
                println!("   link: {:?}", value.link);
                println!("   vlan: {:?}", value.vlan);
                println!("   ip: {:?}", value.ip);
                println!("   transport: {:?}", value.transport);
                match value.transport {
                    None => {}
                    Some(trans) => {
                        match trans {
                            TransportSlice::Icmpv4(_) => {}
                            TransportSlice::Icmpv6(_) => {}
                            TransportSlice::Udp(_) => {}
                            TransportSlice::Tcp(tcp) => {
                                println!("      TCP: src {}, dst {}", tcp.source_port(), tcp.destination_port())
                            }
                            TransportSlice::Unknown(_) => {}
                        }
                    }
                }
            }
        }
    }

    println!("End pcap_test.");
}
