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
        println!("   Packet {}, len: {}, header: {}", packet_count, packet.len(), packet.header.len);
    }

    println!("End pcap_test.");
}
