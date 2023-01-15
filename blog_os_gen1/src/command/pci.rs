use alloc::format;
use pci_types::{EndpointHeader, HeaderType, PciAddress, PciHeader};

use crate::{
    pci::{lookup, IoConfiguration},
    println,
    virtio::transport::VirtioPciTransport,
};

pub fn lspci_fn(_: &str) {
    for bus in 0..=255 {
        check_bus(bus);
    }
}

fn check_bus(bus: u8) {
    for device in 0..32 {
        check_device(bus, device);
    }
}

fn check_device(bus: u8, device: u8) {
    let address = PciAddress::new(0, bus, device, 0);
    let header = PciHeader::new(address);

    let cra = IoConfiguration::new();

    if let Some(endpoint) = EndpointHeader::from_header(header, &cra) {
        use pci_types::Bar::*;
        let (vendor_id, device_id) = endpoint.header().id(&cra);

        let header_type = endpoint.header().header_type(&cra);

        println!(
            "{}:{}.0 {:x}:{:x} ${}",
            bus,
            device,
            vendor_id,
            device_id,
            match endpoint.bar(0, &cra) {
                Some(Memory32 { address, size, .. }) => format!("{:#0x}[{}]", address, size),
                Some(Memory64 { address, size, .. }) => format!("{:#0x}[{}]", address, size),
                Some(Io { port }) => format!("IO({:#0x})", port),
                None => "<no BAR>".into(),
            }
        );

        if let Some((vendor_name, device_name)) = lookup::lookup(vendor_id, device_id) {
            println!("  Vendor     : {}", vendor_name);
            println!("  Description: {}", device_name);
        } else {
            println!("  (Unknown Vendor/Device)");
        }

        if vendor_id == 0x1af4 {
            let transport = unsafe { VirtioPciTransport::new(address) };

            transport.get_capabilities(&cra)
        }
    }
}
