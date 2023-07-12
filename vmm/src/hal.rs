use std::error::Error;
use thiserror::Error;
use x86_64::{PhysAddr, VirtAddr};

#[derive(Debug, Error)]
pub enum VirtualMachineError<E: Error> {
    #[error("failed to initialize virtual machine provider: {0}")]
    Init(E),
    #[error("failed to create virtual machine: {0}")]
    CreateVm(E),
    #[error("failed to allocate physical memory: {0}")]
    AllocRam(E),
    #[error("failed to create virtusl CPU: {0}")]
    CreateVCPU(E),
}

#[non_exhaustive]
pub struct GuestMemory {
    pub guest_addr: u64,
    pub(crate) ptr: usize,
    pub(crate) len: usize,
}

impl GuestMemory {
    pub unsafe fn new(guest_addr: u64, ptr: usize, len: usize) -> Self {
        Self {
            guest_addr,
            ptr,
            len,
        }
    }
    #[inline(always)]
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }

    #[inline(always)]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr as *mut u8
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr(), self.len) }
    }
}

pub trait VirtualMachine: Sized {
    type CPU: VirtualCpu;
    type E: Error;

    const VIRTUAL_2GIB_PBASE_OFFSET: VirtAddr =
        unsafe { VirtAddr::new_unsafe(0xffff_ffff_8000_0000) };
    const KERN_PHYS_OFFSET: PhysAddr = PhysAddr::new(0x20000);

    fn initialize() -> Result<Self, VirtualMachineError<Self::E>>;

    fn allocate_guest_memory(
        &mut self,
        guest_addr: u64,
        len: usize,
    ) -> Result<GuestMemory, VirtualMachineError<Self::E>>;

    fn create_vcpu(&mut self, memory: &mut [u8])
        -> Result<Self::CPU, VirtualMachineError<Self::E>>;
}

pub trait VirtualCpu {
    type Exit;

    fn set_rip(&mut self, rip: u64);

    fn run(&mut self) -> Self::Exit;

    fn handle_exit(&mut self, exit: Self::Exit) -> Result<(), String>;
}
