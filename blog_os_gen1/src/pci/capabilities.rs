use core::convert::TryFrom;

use alloc::format;
use bitfield::BitRange;
use pci_types::{ConfigRegionAccess, EndpointHeader, PciAddress, PciHeader, HEADER_TYPE_ENDPOINT};

use super::{IoConfiguration, PciConfigAddress};

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Copy, Clone)]
enum PciCapabilityId {
    PowerManagement = 0x01,
    AGP = 0x02,
    VPD = 0x03,
    SlotId = 0x04,
    MSI = 0x05,
    CpciHotswap = 0x06,
    PCIX = 0x07,
    HYPERTRANSPORT = 0x08,
    VendorSpecific = 0x09,
    DebugPort = 0x0A,
    CpciResCtrl = 0x0B,
    SHPC = 0x0C,
    P2pSsid = 0x0D,
    AgpTarget = 0x0E,
    SECURE = 0x0F,
    PciExpress = 0x10,
    MSIX = 0x11,
    SataConfig = 0x12,
    AdvancedFeatures = 0x13,
}

impl TryFrom<u8> for PciCapabilityId {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use PciCapabilityId::*;
        Ok(match value {
            0x01 => PowerManagement,
            0x02 => AGP,
            0x03 => VPD,
            0x04 => SlotId,
            0x05 => MSI,
            0x06 => CpciHotswap,
            0x07 => PCIX,
            0x08 => HYPERTRANSPORT,
            0x09 => VendorSpecific,
            0x0A => DebugPort,
            0x0B => CpciResCtrl,
            0x0C => SHPC,
            0x0D => P2pSsid,
            0x0E => AgpTarget,
            0x0F => SECURE,
            0x10 => PciExpress,
            0x11 => MSIX,
            0x12 => SataConfig,
            0x13 => AdvancedFeatures,
            _ => return Err(()),
        })
    }
}

bitflags::bitflags! {
    pub struct PciStatus: u16 {
        const INTERRUPT_STATUS     = 0b0000000000001000u16;
        const CAPABILITIES_LIST    = 0b0000000000000100u16;
        const CAPABLE_66MHZ        = 0b0000000000010000u16;
        const FAST_B2B_CAPABLE     = 0b0000000001000000u16;
    }
}

#[non_exhaustive]
pub struct Capabilities(PciAddress);

impl Capabilities {
    pub fn from_address(address: PciAddress, access: &impl ConfigRegionAccess) -> Option<Self> {
        let status_value = PciStatus::from_bits(
            ((unsafe { access.read(address, 0x4) } >> 16) & 0x0000FFFF) as u16,
        )
        .unwrap();

        crate::println!("{:?}", status_value);

        let header_type = PciHeader::new(address).header_type(access);

        if header_type != HEADER_TYPE_ENDPOINT
            || !status_value.contains(PciStatus::CAPABILITIES_LIST)
        {
            None
        } else {
            Some(Self(address))
        }
    }

    pub fn get_capabilities(&self, access: &impl ConfigRegionAccess) -> Option<CapabilityEntry> {
        let capabilities_offset = (unsafe { access.read(self.0, 0x34) } & 0x000000FC) as u16;
        None
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CapabilityEntry {
    id: PciCapabilityId,
    next_offset: u8,
    len: u8,
}

impl CapabilityEntry {
    fn from_address(
        cap_structure_address: PciConfigAddress,
        access: &impl ConfigRegionAccess,
    ) -> Self {
        let (address, offset) = cap_structure_address.to_address_offset();
        let cap_header = unsafe { access.read(address, offset) };

        let id: u8 = cap_header.bit_range(31, 24);
        let next_offset = cap_header.bit_range(23, 16);
        let len = cap_header.bit_range(15, 8);

        Self {
            id: PciCapabilityId::try_from(id).expect(&format!("unknown PCI capability ID: {}", id)),
            next_offset,
            len,
        }
    }
}
