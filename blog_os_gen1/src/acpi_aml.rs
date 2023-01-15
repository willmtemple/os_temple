use core::ptr::NonNull;

use acpi::AcpiHandler;
use aml::AmlContext;
use conquer_once::spin::OnceCell;
use spin::mutex::Mutex;

use crate::println;

static AML_CONTEXT: OnceCell<Mutex<AmlContext>> = OnceCell::uninit();

pub fn init(cx: AmlContext) {
    AML_CONTEXT
        .try_init_once(|| Mutex::new(cx))
        .expect("ACPI/AML context already initialized");
}

pub fn aml_context() -> &'static Mutex<AmlContext> {
    AML_CONTEXT
        .try_get()
        .expect("ACPI/AML context was not initialized")
}

// Turns out most of this fucking garbage is not necessary at all.
impl aml::Handler for Handler {
    fn read_u8(&self, address: usize) -> u8 {
        todo!()
    }

    fn read_u16(&self, address: usize) -> u16 {
        todo!()
    }

    fn read_u32(&self, address: usize) -> u32 {
        todo!()
    }

    fn read_u64(&self, address: usize) -> u64 {
        todo!()
    }

    fn write_u8(&mut self, address: usize, value: u8) {
        todo!()
    }

    fn write_u16(&mut self, address: usize, value: u16) {
        todo!()
    }

    fn write_u32(&mut self, address: usize, value: u32) {
        todo!()
    }

    fn write_u64(&mut self, address: usize, value: u64) {
        todo!()
    }

    fn read_io_u8(&self, port: u16) -> u8 {
        todo!()
    }

    fn read_io_u16(&self, port: u16) -> u16 {
        todo!()
    }

    fn read_io_u32(&self, port: u16) -> u32 {
        todo!()
    }

    fn write_io_u8(&self, port: u16, value: u8) {
        todo!()
    }

    fn write_io_u16(&self, port: u16, value: u16) {
        todo!()
    }

    fn write_io_u32(&self, port: u16, value: u32) {
        todo!()
    }

    fn read_pci_u8(&self, segment: u16, bus: u8, device: u8, function: u8, offset: u16) -> u8 {
        todo!()
    }

    fn read_pci_u16(&self, segment: u16, bus: u8, device: u8, function: u8, offset: u16) -> u16 {
        todo!()
    }

    fn read_pci_u32(&self, segment: u16, bus: u8, device: u8, function: u8, offset: u16) -> u32 {
        todo!()
    }

    fn write_pci_u8(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
        value: u8,
    ) {
        todo!()
    }

    fn write_pci_u16(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
        value: u16,
    ) {
        todo!()
    }

    fn write_pci_u32(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
        value: u32,
    ) {
        todo!()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Handler(usize);

impl Handler {
    pub fn new(physical_memory_offset: usize) -> Self {
        Self(physical_memory_offset)
    }
}

impl AcpiHandler for Handler {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> acpi::PhysicalMapping<Self, T> {
        //debug_assert!(size >= core::mem::size_of::<T>());

        println!("ACPI: mapping physical address {:#0}", physical_address);

        acpi::PhysicalMapping::new(
            physical_address,
            NonNull::new((self.0 + physical_address) as *mut T).unwrap(),
            size,
            size,
            *self,
        )
    }

    fn unmap_physical_region<T>(region: &acpi::PhysicalMapping<Self, T>) {
        // We're using the mapping of the full physical memory, so no unmapping is required
        println!(
            "ACPI: unmapping physical address {:#0}",
            region.physical_start()
        );
    }
}
