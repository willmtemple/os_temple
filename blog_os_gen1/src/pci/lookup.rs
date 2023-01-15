use alloc::collections::BTreeMap;

lazy_static::lazy_static! {
    pub static ref INTEL_CORP: BTreeMap<u16, DeviceDescription> = {
        let mut m = BTreeMap::new();

        m.insert(0x100e, "Gigabit Ethernet Controller");
        m.insert(0x1237, "82441FX PMC");
        m.insert(0x2668, "High Definition Audio Controller");
        m.insert(0x7000, "PIIX3 ISA");

        m
    };

    pub static ref REDHAT_VIRTIO: BTreeMap<u16, DeviceDescription> = {
        let mut m = BTreeMap::new();

        m.insert(0x1050, "VirtIO GPU");
        m.insert(0x1000, "VirtIO Network Device");
        m.insert(0x1001, "VirtIO Block Device");

        m
    };

    pub static ref VENDORS: BTreeMap<u16, (DeviceVendor, &'static BTreeMap<u16, DeviceDescription>)> = {
        let mut m = BTreeMap::new();

        m.insert(0x8086, ("Intel Corp.", &*INTEL_CORP));
        m.insert(0x1af4, ("Red Hat Corp.", &*REDHAT_VIRTIO));

        m
    };
}

pub type DeviceVendor = &'static str;
pub type DeviceDescription = &'static str;

pub fn lookup(vendor_id: u16, device_id: u16) -> Option<(DeviceVendor, DeviceDescription)> {
    match VENDORS.get(&vendor_id) {
        Some((vendor, table)) => {
            if let Some(device) = table.get(&device_id) {
                Some((vendor, device))
            } else {
                None
            }
        }
        None => None,
    }
}
