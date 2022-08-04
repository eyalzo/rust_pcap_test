mod connections;

use log::{debug, info, trace};
use pcap::Device;
use crate::connections::{Connections};

fn main() {
    info!("Start pcap_test...");

    // Connection list
    // let mut conn_list: HashMap<u128, Conn> = HashMap::new();

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

    let mut connections = Connections::new();

    while let Ok(packet) = cap.next() {
        connections.process_packet(&packet);
    }

    println!("End pcap_test.");
}
