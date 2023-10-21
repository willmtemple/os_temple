mod elf;
pub(crate) mod ffi;
#[cfg(target_os = "linux")]
mod kvm;

#[cfg(target_os = "windows")]
mod whp;

#[cfg(target_os = "windows")]
type VM = whp::WhpVirtualMachine;

mod hal;

mod util;

mod display;

use std::{
    env::args,
    sync::mpsc::channel,
    thread::{self},
};

use crate::hal::{VirtualCpu, VirtualMachine};
use elfloader::ElfBinary;
use log::{error, info};

// use kvm::{CpuHandle, KvmError, VmHandle};

// struct VirtualMachine<'m> {
//     // kvm: kvm::KVM,
//     vm_handle: VmHandle,
//     memory: &'m mut [u8],
// }

// #[derive(Error, Debug)]
// pub enum VirtualMachineError {
//     #[error("failed to initialize KVM: {0}")]
//     Init(KvmError),
//     #[error("failed to create virtual machine: {0}")]
//     CreateVm(KvmError),
//     #[error("failed to allocate physical memory: {0}")]
//     AllocRam(KvmError),
//     #[error("failed to create VCPU: {0}")]
//     CreateVCPU(KvmError),
// }

// impl<'m> VirtualMachine<'m> {
//     fn init() -> Result<Self, VirtualMachineError> {
//         let kvm = kvm::KVM::open().map_err(VirtualMachineError::Init)?;
//         let vm_handle = kvm.create_vm().map_err(VirtualMachineError::CreateVm)?;

//         let memory = vm_handle
//             .alloc_primary_memory(0x1000000)
//             .map_err(VirtualMachineError::AllocRam)?;

//         Ok(VirtualMachine {
//             kvm,
//             vm_handle,
//             memory: unsafe { std::slice::from_raw_parts_mut(memory as *mut u8, 0x1000000) },
//         })
//     }

//     pub fn create_vcpu(&mut self) -> Result<VCPU, VirtualMachineError> {
//         Ok(VCPU {
//             cpu: CpuHandle::new(&self.kvm, &self.vm_handle, self.kvm.fd)
//                 .map_err(VirtualMachineError::CreateVCPU)?,
//         })
//     }
// }

// pub struct VCPU {
//     cpu: CpuHandle,
// }

#[cfg(target_os = "windows")]
use whp::get_platform_virtualization_provider;

fn main() {
    env_logger::init();

    let elf_file = args()
        .nth(1)
        .expect("expected an argument with the path to a binary");

    let mut vm =
        get_platform_virtualization_provider().expect("failed to initialize virtual machine");

    info!("virtual machine initialized");

    let mut memory = vm
        .allocate_guest_memory(0x0, 0x1000000)
        .expect("failed to map guest memory");

    info!("memory mapped at {:p}", memory.as_ptr());

    let mut elf_loader = elf::BasicLoader::new::<VM>(unsafe { memory.as_mut_ptr() });

    let kernel_binary = std::fs::read(elf_file).expect("failed to open kernel ELF");

    let elf = ElfBinary::new(&kernel_binary.as_slice())
        .expect("failed to parse kernel ELF (is it an ELF file)");

    elf.load(&mut elf_loader)
        .expect("failed to load ELF file into memory");

    let initial_rip =
        elf.entry_point() + VM::KERN_PHYS_OFFSET.as_u64() + VM::VIRTUAL_2GIB_PBASE_OFFSET.as_u64();

    info!("Entrypoint: {:#x}", initial_rip);

    let video_buffer_ptr = unsafe { memory.as_mut_ptr().add(0x300000) };

    let (send, recv) = channel::<()>();

    let mut cpu = vm
        .create_vcpu(memory.as_mut_slice())
        .expect("failed to create vCPU");

    info!("added vcpu");

    let handle = thread::spawn(move || {
        info!("CPU 0 thread started.");

        cpu.set_rip(initial_rip);

        info!("CPU thread started: 0");
        recv.recv().unwrap();
        loop {
            let exit = cpu.run();
            let result = cpu.handle_exit(exit);
            match result {
                Ok(_) => {
                    continue;
                }
                Err(s) => {
                    error!("{}", s);
                    break;
                }
            }
        }
    });

    display::start(send, unsafe {
        core::slice::from_raw_parts_mut(video_buffer_ptr, 1920 * 1080 * 4)
    });

    handle.join().expect("failed to join CPU thread");

    info!("All CPUs suspended. VM halting.");
}
