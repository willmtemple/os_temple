use std::{ffi::c_void, mem, ptr::null_mut};

use elfloader::ElfBinary;
use log::info;
use nix::{
    errno::{errno, Errno},
    fcntl::OFlag,
    ioctl_read, ioctl_write_int_bad, ioctl_write_ptr,
    libc::{
        madvise, memcpy, mmap, MADV_MERGEABLE, MAP_ANONYMOUS, MAP_FAILED, MAP_NORESERVE,
        MAP_PRIVATE, MAP_SHARED, PROT_READ, PROT_WRITE,
    },
    request_code_none,
    sys::stat::Mode,
};

use thiserror::Error;
use x86_64::{
    structures::paging::{Mapper, OffsetPageTable, PageTable, PageTableFlags, PhysFrame},
    PhysAddr, VirtAddr,
};

use crate::ffi::kvm::{
    kvm_regs, kvm_run, kvm_segment, kvm_sregs, kvm_userspace_memory_region, CR0_AM, CR0_ET, CR0_MP,
    CR0_NE, CR0_PE, CR0_PG, CR0_WP, CR4_PAE, EFER_LMA, EFER_LME, KVMIO, KVM_EXIT_HLT, KVM_EXIT_IO,
    KVM_EXIT_IO_OUT, KVM_EXIT_SHUTDOWN, PDE64_PRESENT, PDE64_PS, PDE64_RW, PDE64_USER,
};

pub struct KVM {
    pub fd: i32,
}

#[derive(Debug, Error)]
pub enum KvmError {
    #[error("the KVM API version {0} does not match ours")]
    WrongVersion(u32),

    #[error("open /dev/kvm: {0}")]
    CouldNotOpen(Errno),

    #[error("failed ioctl {0}: {1}")]
    FailedIoctl(&'static str, Errno),

    #[error("failed to allocate memory for {0}: {1}")]
    FailedAlloc(&'static str, Errno),

    #[error("failed syscall {0}: {1}")]
    FailedSyscall(&'static str, Errno),

    #[error("unhandled KVM exit reason {0}")]
    UnexpectedExit(u32),

    #[error("unhandled IO operation: {0} {1}")]
    UnhandledIo(u32, u16),
}

pub trait IntoIoctlError {
    type Ok;
    fn map_err_kvm(self, name: &'static str) -> Result<Self::Ok, KvmError>;
}

impl<T> IntoIoctlError for Result<T, Errno> {
    type Ok = T;
    fn map_err_kvm(self, name: &'static str) -> Result<T, KvmError> {
        self.map_err(|e| KvmError::FailedIoctl(name, e))
    }
}

ioctl_write_int_bad!(kvm_get_api_version, request_code_none!(KVMIO, 0));

ioctl_write_int_bad!(kvm_create_vm, request_code_none!(KVMIO, 1));

ioctl_write_ptr!(
    kvm_set_user_memory_region,
    KVMIO,
    0x46,
    kvm_userspace_memory_region
);

ioctl_write_int_bad!(kvm_get_vcpu_mmap_size, request_code_none!(KVMIO, 0x04));

ioctl_write_int_bad!(kvm_create_vcpu, request_code_none!(KVMIO, 0x41));

ioctl_write_int_bad!(kvm_set_tss_addr, request_code_none!(KVMIO, 0x47));

ioctl_write_int_bad!(kvm_run, request_code_none!(KVMIO, 0x80));

ioctl_read!(kvm_get_regs, KVMIO, 0x81, kvm_regs);

ioctl_write_ptr!(kvm_set_regs, KVMIO, 0x82, kvm_regs);

ioctl_read!(kvm_get_sregs, KVMIO, 0x83, kvm_sregs);

ioctl_write_ptr!(kvm_set_sregs, KVMIO, 0x84, kvm_sregs);

const PAYLOAD: &[u8] = include_bytes!("../simple_bin/payload64.text");

impl KVM {
    pub fn open() -> Result<Self, KvmError> {
        let sys_fd = nix::fcntl::open("/dev/kvm", OFlag::O_RDWR, Mode::empty())
            .map_err(KvmError::CouldNotOpen)?;

        let api_version = unsafe { kvm_get_api_version(sys_fd, 0) }
            .map_err(|e| KvmError::FailedIoctl("kvm_get_api_version", e))?
            as u32;

        if api_version != crate::ffi::kvm::KVM_API_VERSION {
            return Err(KvmError::WrongVersion(api_version));
        }

        Ok(Self { fd: sys_fd })
    }

    pub fn create_vm(&self) -> Result<VmHandle, KvmError> {
        let vm_fd = unsafe { kvm_create_vm(self.fd, 0) }.map_err_kvm("kvm_create_vm")?;

        // TODO: may want to configure this
        #[allow(overflowing_literals)]
        unsafe { kvm_set_tss_addr(vm_fd, 0xfffbd000_i32) }.map_err_kvm("kvm_set_tss_addr")?;

        Ok(VmHandle { fd: vm_fd })
    }
}

pub struct VmHandle {
    fd: i32,
}

impl VmHandle {
    pub fn alloc_primary_memory(&self, size: usize) -> Result<*mut c_void, KvmError> {
        let ptr = unsafe {
            mmap(
                null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                -1,
                0,
            )
        };

        if ptr == MAP_FAILED {
            return Err(KvmError::FailedAlloc("vm memory", Errno::from_i32(errno())));
        }

        // This might not be desirable if the VM is the only/primary thing running on the machine
        let madv_result = unsafe { madvise(ptr, size, MADV_MERGEABLE) };
        if madv_result < 0 {
            return Err(KvmError::FailedSyscall("madvise", Errno::from_i32(errno())));
        }

        let mut memreg = kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: size as u64,
            userspace_addr: ptr as u64,
        };

        unsafe { kvm_set_user_memory_region(self.fd, &mut memreg) }
            .map_err_kvm("kvm_set_user_memory_region")?;

        Ok(ptr)
    }
}

pub struct CpuHandle {
    fd: i32,
    kvm_run: *mut crate::ffi::kvm::kvm_run,
}

impl CpuHandle {
    pub fn new(vm: &VmHandle, sys_fd: i32) -> Result<Self, KvmError> {
        let cpu_fd = unsafe { kvm_create_vcpu(vm.fd, 0) }.map_err_kvm("kvm_create_vcpu")?;

        let vcpu_mmap_size =
            unsafe { kvm_get_vcpu_mmap_size(sys_fd, 0) }.map_err_kvm("kvm_get_vcpu_mmap_size")?;

        let kvm_run = unsafe {
            mmap(
                null_mut(),
                vcpu_mmap_size as usize,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                cpu_fd,
                0,
            )
        } as *mut kvm_run;

        if kvm_run as *mut c_void == MAP_FAILED {
            return Err(KvmError::FailedAlloc("kvm_run", Errno::from_i32(errno())));
        }

        Ok(Self {
            fd: cpu_fd,
            kvm_run,
        })
    }
}

pub fn run(cpu: &mut CpuHandle, memory: *mut c_void, start_addr: u64) -> Result<(), KvmError> {
    #[inline]
    unsafe fn setup_long_mode(memory: *mut c_void, sregs: &mut kvm_sregs, start_addr: u64) {
        // TODO: I am just manually mapping two bigpages here. Need a full allocator for proper elf loading.
        let pml4_addr = 0x2000_u64;
        let pml4 = memory.add(pml4_addr as usize) as *mut u64;

        let pdpt_addr = 0x3000_u64;
        let pdpt = memory.add(pdpt_addr as usize) as *mut u64;

        let pd_addr = 0x4000_u64;
        let pd = memory.add(pd_addr as usize) as *mut u64;

        *pml4 = ((PDE64_PRESENT | PDE64_RW | PDE64_USER) as u64) | pdpt_addr;
        *pdpt = ((PDE64_PRESENT | PDE64_RW | PDE64_USER) as u64) | pd_addr;
        *pd = (PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS) as u64;
        *(pd.add(1)) = ((PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS) as u64) | (2 << 20);

        sregs.cr3 = pml4_addr as u64;
        sregs.cr4 = CR4_PAE as u64;
        sregs.cr0 = (CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG) as u64;

        sregs.efer = (EFER_LME | EFER_LMA) as u64;

        info!("Set up paging.");

        let l4 = &mut *(memory.add(pml4_addr as usize) as *mut PageTable);
        for entry in l4.iter() {
            if (entry.flags().bits() & (PDE64_PRESENT as u64)) != 0 {
                info!("{:?}", entry);
            }
        }

        setup_64bit_code_segment(sregs, start_addr);
    }

    #[inline]
    unsafe fn setup_64bit_code_segment(sregs: &mut kvm_sregs, start_addr: u64) {
        let mut segment = kvm_segment {
            base: start_addr,
            limit: 0xffffffff,
            selector: 1 << 3,
            present: 1,
            type_: 11, // execute, read, accessed
            dpl: 0,
            db: 0,
            s: 1,
            l: 1,
            g: 1,
            ..mem::zeroed()
        };

        sregs.cs = segment.clone();

        segment.type_ = 3;
        segment.selector = 2 << 3;

        sregs.ds = segment;
        sregs.es = segment;
        sregs.fs = segment;
        sregs.gs = segment;
        sregs.ss = segment;
    }

    let mut sregs = unsafe { mem::zeroed::<kvm_sregs>() };
    let mut regs = unsafe { mem::zeroed::<kvm_regs>() };

    unsafe { kvm_get_sregs(cpu.fd, &mut sregs) }.map_err_kvm("kvm_get_sregs")?;

    unsafe {
        setup_long_mode(memory, &mut sregs, start_addr);
    }

    unsafe { kvm_set_sregs(cpu.fd, &mut sregs) }.map_err_kvm("kvm_set_sregs")?;

    regs.rflags = 2;
    regs.rip = start_addr;
    regs.rsp = 4 << 20;

    unsafe { kvm_set_regs(cpu.fd, &mut regs) }.map_err_kvm("kvm_set_regs")?;

    // unsafe { memcpy(memory, PAYLOAD.as_ptr() as *const c_void, PAYLOAD.len()) };

    let kernel_binary = std::fs::read("../target/x86_64-custom/release/vmm_test_bin")
        .expect("failed to open kernel ELF");

    let elf = ElfBinary::new(&kernel_binary.as_slice())
        .expect("failed to parse kernel ELF (is it an ELF file)");

    let mut loader = crate::elf::ExampleLoader::new(memory, 0x0000);

    elf.load(&mut loader).expect("failed to load kernel");

    run_loop(cpu, memory)
}

fn run_loop(cpu: &mut CpuHandle, memory: *mut c_void) -> Result<(), KvmError> {
    loop {
        unsafe { kvm_run(cpu.fd, 0) }.map_err_kvm("kvm_run")?;

        match unsafe { *cpu.kvm_run }.exit_reason {
            // guest called HLT
            KVM_EXIT_HLT => break,
            // guest called port IO IN/OUT
            KVM_EXIT_IO => {
                let direction = unsafe { (*cpu.kvm_run).__bindgen_anon_1.io.direction } as u32;
                let port = unsafe { (*cpu.kvm_run).__bindgen_anon_1.io.port };

                if direction == KVM_EXIT_IO_OUT && port == 0xE9 {
                    print!("{}", unsafe {
                        char::from_u32_unchecked(
                            *(cpu.kvm_run as *const u8)
                                .add((*cpu.kvm_run).__bindgen_anon_1.io.data_offset as usize)
                                as u32,
                        )
                    });
                } else {
                    // TODO: fault the vcpu or something other than killing the process
                    return Err(KvmError::UnhandledIo(direction, port));
                }
            }
            e => {
                return Err(KvmError::UnexpectedExit(e));
            }
        }
    }

    let mut regs = unsafe { mem::zeroed::<kvm_regs>() };
    unsafe {
        kvm_get_regs(cpu.fd, &mut regs).map_err_kvm("kvm_get_regs")?;
    }

    info!("At exit %rax was {:#X}", regs.rax);
    info!("At exit *0x400 was {}", unsafe {
        *((memory.add(0x400)) as *const u64)
    });

    Ok(())
}
