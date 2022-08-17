mod connections;
mod utils;

use env_logger::Env;
use log::{debug, info, trace};
use pcap::{Active, Capture, Device, Direction};
use clap::Parser;
use crate::connections::{Connections};

#[derive(Parser)]
#[clap(author, version, about)]
struct Cli {
    /// Filter in BPF (pcap) format.
    /// See http://biot.com/capstats/bpf.html for more information about this syntax.
    #[clap(short, long, value_parser, default_value = "tcp")]
    filter: String,
    /// Device name to capture ("interface" in tcpdump terminology).
    /// Defaults to the main device
    #[clap(short, long, value_parser)]
    device: Option<String>,
}

fn main() {
    let args = Cli::parse();

    // If RUST_LOG is not set, then default to INFO level
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("Start pcap_test...");

    // Get the default device name, to be used later when looking at the device list
    let mut main_device_name =
        match Device::lookup() {
            Err(error) => { panic!("Failed to get default pcap device: {}", error) }
            Ok(device) => {
                device.name
            }
        };

    if args.device.is_some() {
        main_device_name = String::from(args.device.unwrap());
    }

    let mut main_device: Option<Device> = None;
    let device_list = Device::list().expect("Failed to get device list");
    info!("Device list has {} elements. Those with addresses:", device_list.len());
    for cur_device in device_list {
        if cur_device.name.eq(&main_device_name) { main_device = Some(cur_device.to_owned()); }
        if cur_device.addresses.len() <= 0 { continue; }
        debug!("   Device '{}' = {} ({} addresses)", cur_device.name,
                 cur_device.desc.unwrap_or(String::from("unknown")),
                 cur_device.addresses.len());
        for cur_addr in cur_device.addresses {
            trace!("      {}", cur_addr.addr);
        }
    }

    if main_device.is_none() {
        panic!("Failed to find a (specified or default) device. \
        Consider running with RUST_LOG=\"trace\" and watch the device list carefully.");
    }

    let mut cap: Capture<Active> =
        {
            match Capture::from_device(main_device.unwrap()).unwrap()
                .promisc(true)
                .immediate_mode(true)
                .snaplen(65535)
                .buffer_size(10000000)
                .open() {
                Err(error) => { panic!("Failed to open default pcap device: {}", error) }
                Ok(cap) => {
                    info!("Default capture data-link: {{name: {:?},desc: {:?}}}",
                        cap.get_datalink().get_name().unwrap(),
            cap.get_datalink().get_description().unwrap());
                    cap
                }
            }
        };

    // Prepare filter (optional)
    cap.filter(&args.filter, false).expect("Failed to apply pcap filter");
    cap.direction(Direction::InOut).expect("Failed to set pcap direction");

    let mut connections = Connections::new();

    while let Ok(packet) = cap.next() {
        connections.process_packet(&packet);
    }

    info!("End pcap_test.");
}
