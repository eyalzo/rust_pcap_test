mod connections;

use env_logger::Env;
use log::{debug, info, trace};
use pcap::{Active, Capture, Device};
use crate::connections::{Connections};

fn main() {
    // If RUST_LOG is not set, then default to INFO level
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
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
    let mut cap: Capture<Active> =
        match Device::lookup() {
            Err(error) => { panic!("Failed to get default pcap device: {}", error) }
            Ok(device) => {
                info!("Default device: {:?}", device);
                for cur_addr in &device.addresses {
                    trace!("      {}", cur_addr.addr);
                }
                match device.open() {
                    Err(error) => { panic!("Failed to open default pcap device: {}", error) }
                    Ok(cap) => {
                        info!("Default capture data-link: {{name: {:?},desc: {:?}}}", cap.get_datalink().get_name().unwrap(),
                            cap.get_datalink().get_description().unwrap());
                        cap
                    }
                }
            }
        };

    let mut connections = Connections::new();

    while let Ok(packet) = cap.next() {
        connections.process_packet(&packet);
    }

    info!("End pcap_test.");
}
