#![feature(once_cell)]

mod elf;
pub(crate) mod ffi;
mod kvm;

mod display;

use std::{env::args, ffi::c_void, sync::mpsc::channel, thread};

use log::info;
use thiserror::Error;

use kvm::{CpuHandle, KvmError, VmHandle};

struct VirtualMachine<'m> {
    kvm: kvm::KVM,
    vm_handle: VmHandle,
    memory: &'m mut [u8],
}

#[derive(Error, Debug)]
pub enum VirtualMachineError {
    #[error("failed to initialize KVM: {0}")]
    Init(KvmError),
    #[error("failed to create virtual machine: {0}")]
    CreateVm(KvmError),
    #[error("failed to allocate physical memory: {0}")]
    AllocRam(KvmError),
    #[error("failed to create VCPU: {0}")]
    CreateVCPU(KvmError),
}

impl<'m> VirtualMachine<'m> {
    fn init() -> Result<Self, VirtualMachineError> {
        let kvm = kvm::KVM::open().map_err(VirtualMachineError::Init)?;
        let vm_handle = kvm.create_vm().map_err(VirtualMachineError::CreateVm)?;

        let memory = vm_handle
            .alloc_primary_memory(0xc00000)
            .map_err(VirtualMachineError::AllocRam)?;

        Ok(VirtualMachine {
            kvm,
            vm_handle,
            memory: unsafe { std::slice::from_raw_parts_mut(memory as *mut u8, 0xc00000) },
        })
    }

    pub fn create_vcpu(&mut self) -> Result<VCPU, VirtualMachineError> {
        Ok(VCPU {
            cpu: CpuHandle::new(&self.vm_handle, self.kvm.fd)
                .map_err(VirtualMachineError::CreateVCPU)?,
        })
    }
}

pub struct VCPU {
    cpu: CpuHandle,
}

fn main() {
    env_logger::init();
    let mut vm = VirtualMachine::init().expect("failed to initialize virtual machine");

    info!("KVM: initialized");

    let mut cpu = vm.create_vcpu().expect("failed to create vCPU");

    info!("Created vCPU.");

    info!("Loading and executing 64-bit payload.");

    let elf_file = args()
        .nth(1)
        .expect("expected an argument with the path to a binary");

    let video_buffer = (vm.memory.as_ptr() as usize) + (3 << 20);

    let (send, recv) = channel::<()>();

    let display_thread = thread::spawn(move || display::start(send, video_buffer));

    kvm::run(
        recv,
        &mut cpu.cpu,
        vm.memory.as_ptr() as *mut c_void,
        vm.memory.len(),
        &elf_file,
    )
    .expect("encountered an error running virtual machine");

    info!("All CPUs suspended. VM halting.");

    display_thread
        .join()
        .expect("failed to join display thread");
}
