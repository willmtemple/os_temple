#![feature(once_cell)]

mod elf;
pub(crate) mod ffi;
mod kvm;

use std::ffi::c_void;

use elfloader::ElfBinary;
use log::info;
use thiserror::Error;

use kvm::{CpuHandle, KvmError, VmHandle};

struct VirtualMachine {
    kvm: kvm::KVM,
    vm_handle: VmHandle,
    memory: *mut c_void,
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

impl VirtualMachine {
    fn init() -> Result<Self, VirtualMachineError> {
        let kvm = kvm::KVM::open().map_err(VirtualMachineError::Init)?;
        let vm_handle = kvm.create_vm().map_err(VirtualMachineError::CreateVm)?;

        let memory = vm_handle
            .alloc_primary_memory(0x400000)
            .map_err(VirtualMachineError::AllocRam)?;

        Ok(VirtualMachine {
            kvm,
            vm_handle,
            memory,
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

    kvm::run(&mut cpu.cpu, vm.memory, 0x201120)
        .expect("encountered an error running virtual machine");

    info!("Virtual machine halted.")
}
