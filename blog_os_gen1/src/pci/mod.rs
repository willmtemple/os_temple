use acpi::PciConfigRegions;

pub mod capabilities;
pub mod lookup;

const PCI_CONFIG_ADDRESS_PORT: u16 = 0xCF8;
const PCI_CONFIG_DATA_PORT: u16 = 0xCFC;

bitfield::bitfield! {
    struct PciConfigAddress(u32);
    impl Debug;

    u16, offset, set_offset: 7, 0;
    u8, function, set_function: 10, 8;
    u8, device, set_device: 15, 11;
    u8, bus, set_bus: 23, 16;
    enable, set_enable: 31;
}

impl PciConfigAddress {
    fn from_address_offset(address: pci_types::PciAddress, offset: u16) -> Self {
        let mut s = Self(0);

        s.set_offset(offset);
        s.set_function(address.function());
        s.set_device(address.device());
        s.set_bus(address.bus());
        s.set_enable(true);

        s
    }

    fn to_address_offset(self) -> (pci_types::PciAddress, u16) {
        (
            pci_types::PciAddress::new(0, self.bus(), self.device(), self.function()),
            self.offset(),
        )
    }

    unsafe fn write_config_address(&self) {
        x86_64::instructions::port::PortWrite::write_to_port(PCI_CONFIG_ADDRESS_PORT, self.0);
    }
}

#[non_exhaustive]
pub struct IoConfiguration;

impl IoConfiguration {
    pub fn new() -> Self {
        Self
    }
}

impl pci_types::ConfigRegionAccess for IoConfiguration {
    fn function_exists(&self, address: pci_types::PciAddress) -> bool {
        let vendor_id = (unsafe { self.read(address, 0) } & 0xFFFF) as u16;

        return vendor_id != 0xFFFF;
    }

    unsafe fn read(&self, address: pci_types::PciAddress, offset: u16) -> u32 {
        PciConfigAddress::from_address_offset(address, offset).write_config_address();

        x86_64::instructions::port::PortRead::read_from_port(PCI_CONFIG_DATA_PORT)
    }

    unsafe fn write(&self, address: pci_types::PciAddress, offset: u16, value: u32) {
        PciConfigAddress::from_address_offset(address, offset).write_config_address();

        x86_64::instructions::port::PortWrite::write_to_port(PCI_CONFIG_DATA_PORT, value);
    }
}

pub struct ExtendedConfiguration {
    regions: PciConfigRegions,
    physical_memory_offset: usize,
}

impl ExtendedConfiguration {
    /// # Safety
    /// Caller must ensure that `physical_memory_offset` is the virtual memory address where the full physical memory
    /// begins.
    pub unsafe fn new(regions: PciConfigRegions, physical_memory_offset: usize) -> Self {
        Self {
            regions,
            physical_memory_offset,
        }
    }
    unsafe fn calc_address(&self, address: pci_types::PciAddress, offset: u16) -> usize {
        let mut physical_offset = self
            .regions
            .physical_address(
                address.segment(),
                address.bus(),
                address.device(),
                address.function(),
            )
            .expect("failed to map PCI address to physical");

        let ptr_offset = self.physical_memory_offset + physical_offset as usize + offset as usize;

        ptr_offset
    }
}

impl pci_types::ConfigRegionAccess for ExtendedConfiguration {
    fn function_exists(&self, address: pci_types::PciAddress) -> bool {
        self.regions
            .physical_address(
                address.segment(),
                address.bus(),
                address.device(),
                address.function(),
            )
            .is_some()
    }

    unsafe fn read(&self, address: pci_types::PciAddress, offset: u16) -> u32 {
        core::ptr::read_volatile(unsafe { self.calc_address(address, offset) as *const u32 })
    }

    unsafe fn write(&self, address: pci_types::PciAddress, offset: u16, value: u32) {
        core::ptr::write_volatile(
            unsafe { self.calc_address(address, offset) as *mut u32 },
            value,
        );
    }
}
