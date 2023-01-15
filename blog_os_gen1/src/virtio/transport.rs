use pci_types::{ConfigRegionAccess, PciAddress};

pub struct VirtioPciTransport {
    address: PciAddress,
}

impl VirtioPciTransport {
    /// # Safety
    /// This might crash the system if the address isn't a VirtIO Endpoint.
    pub unsafe fn new(address: PciAddress) -> Self {
        Self { address }
    }

    pub fn get_capabilities(&self, access: &impl ConfigRegionAccess) {
        let capabilities_offset = (unsafe { access.read(self.address, 0x34) } & 0x000000FC) as u16;

        let cap_first_dword = unsafe { access.read(self.address, capabilities_offset) };

        crate::println!("Read CAP: {:#0x}", cap_first_dword);
    }
}

unsafe trait VirtioTransport {}

unsafe impl VirtioTransport for VirtioPciTransport {}
