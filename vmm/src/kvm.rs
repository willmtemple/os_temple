use std::{ffi::c_void, fmt::Display, mem, ptr::null_mut, sync::mpsc::Receiver};

use elfloader::ElfBinary;
use log::{error, info};
use nix::{
    errno::{errno, Errno},
    fcntl::OFlag,
    libc::{
        madvise, mmap, MADV_MERGEABLE, MAP_ANONYMOUS, MAP_FAILED, MAP_NORESERVE, MAP_PRIVATE,
        MAP_SHARED, PROT_READ, PROT_WRITE,
    },
    sys::stat::Mode,
};

use thiserror::Error;
use x86_64::structures::paging::PageTable;

use crate::ffi::kvm::{
    kvm_irqchip, kvm_lapic_state, kvm_pit_config, kvm_regs, kvm_run, kvm_segment, kvm_sregs,
    kvm_userspace_memory_region, CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP, CR4_PAE,
    EFER_LMA, EFER_LME, KVM_EXIT_IO_OUT, PDE64_PRESENT, PDE64_PS, PDE64_RW,
};

use self::ioctls::kvm_get_irqchip;

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
    UnexpectedExit(KvmExit),

    #[error("unhandled IO operation: {0} 0x{1:#04x}")]
    UnhandledIo(KvmIoDirection, u16),
}

#[repr(u32)]
#[derive(Debug)]
pub enum KvmExit {
    Unknown = 0,
    Exception = 1,
    Io = 2,
    Hypercall = 3,
    Debug = 4,
    Hlt = 5,
    Mmio = 6,
    IrqWindowOpen = 7,
    Shutdown = 8,
    FailEntry = 9,
    Intr = 10,
    SetTpr = 11,
    TprAccess = 12,
    S390Sieic = 13,
    S390Reset = 14,
    Dcr = 15, /* deprecated */
    Nmi = 16,
    InternalError = 17,
    Osi = 18,
    PaprHcall = 19,
    S390Ucontrol = 20,
    Watchdog = 21,
    S390Tsch = 22,
    Epr = 23,
    SystemEvent = 24,
    S390Stsi = 25,
    IoapicEoi = 26,
    Hyperv = 27,
    ArmNisv = 28,
    X86Rdmsr = 29,
    X86Wrmsr = 30,
    DirtyRingFull = 31,
    ApResetHold = 32,
    X86BusLock = 33,
    Xen = 34,
    RiscvSbi = 35,
}

impl KvmExit {
    pub unsafe fn from_u32_unchecked(value: u32) -> Self {
        std::mem::transmute(value)
    }

    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0..=35 => Some(unsafe { Self::from_u32_unchecked(value) }),
            _ => None,
        }
    }
}

impl Default for KvmExit {
    fn default() -> Self {
        KvmExit::Unknown
    }
}

impl Display for KvmExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                KvmExit::Unknown => "UNKNOWN",
                KvmExit::Exception => "EXCEPTION",
                KvmExit::Io => "IO",
                KvmExit::Hypercall => "HYPERCALL",
                KvmExit::Debug => "DEBUG",
                KvmExit::Hlt => "HLT",
                KvmExit::Mmio => "MMIO",
                KvmExit::IrqWindowOpen => "IRQ_WINDOW_OPEN",
                KvmExit::Shutdown => "SHUTDOWN",
                KvmExit::FailEntry => "FAIL_ENTRY",
                KvmExit::Intr => "INTR",
                KvmExit::SetTpr => "SET_TPR",
                KvmExit::TprAccess => "TPR_ACCESS",
                KvmExit::S390Sieic => "S390_SIEIC",
                KvmExit::S390Reset => "S390_RESET",
                KvmExit::Dcr => "DCR",
                KvmExit::Nmi => "NMI",
                KvmExit::InternalError => "INTERNAL_ERROR",
                KvmExit::Osi => "OSI",
                KvmExit::PaprHcall => "PAPR_HCALL",
                KvmExit::S390Ucontrol => "S390_UCONTROL",
                KvmExit::Watchdog => "WATCHDOG",
                KvmExit::S390Tsch => "S390_TSCH",
                KvmExit::Epr => "EPR",
                KvmExit::SystemEvent => "SYSTEM_EVENT",
                KvmExit::S390Stsi => "S390_STSI",
                KvmExit::IoapicEoi => "IOAPIC_EOI",
                KvmExit::Hyperv => "HYPERV",
                KvmExit::ArmNisv => "ARM_NISV",
                KvmExit::X86Rdmsr => "X86_RDMSR",
                KvmExit::X86Wrmsr => "X86_WRMSR",
                KvmExit::DirtyRingFull => "DIRTY_RING_FULL",
                KvmExit::ApResetHold => "AP_RESET_HOLD",
                KvmExit::X86BusLock => "X86_BUS_LOCK",
                KvmExit::Xen => "XEN",
                KvmExit::RiscvSbi => "RISCV_SBI",
            }
        )
    }
}

#[derive(Debug)]
#[repr(u32)]
pub enum KvmIoDirection {
    In = 0,
    Out = 1,
}

impl KvmIoDirection {
    pub unsafe fn from_u32_unchecked(value: u32) -> Self {
        std::mem::transmute(value)
    }

    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(KvmIoDirection::In),
            1 => Some(KvmIoDirection::Out),
            _ => None,
        }
    }
}

impl Display for KvmIoDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                KvmIoDirection::In => "IN",
                KvmIoDirection::Out => "OUT",
                #[allow(unreachable_patterns)]
                _ => "UNKNOWN",
            }
        )
    }
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

mod ioctls {
    use nix::{
        ioctl_read, ioctl_readwrite, ioctl_write_int_bad, ioctl_write_ptr, request_code_none,
    };

    use crate::ffi::kvm::{
        kvm_irqchip, kvm_lapic_state, kvm_pit_config, kvm_regs, kvm_sregs,
        kvm_userspace_memory_region, KVMIO,
    };

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

    ioctl_write_int_bad!(kvm_create_irqchip, request_code_none!(KVMIO, 0x60));

    ioctl_readwrite!(kvm_get_irqchip, KVMIO, 0x62, kvm_irqchip);

    ioctl_read!(kvm_set_irqchip, KVMIO, 0x63, kvm_irqchip);

    ioctl_read!(kvm_get_lapic, KVMIO, 0x8e, kvm_lapic_state);

    ioctl_write_ptr!(kvm_set_lapic, KVMIO, 0x8f, kvm_lapic_state);

    ioctl_write_ptr!(kvm_create_pit2, KVMIO, 0x77, kvm_pit_config);
}

impl KVM {
    pub fn open() -> Result<Self, KvmError> {
        let sys_fd = nix::fcntl::open("/dev/kvm", OFlag::O_RDWR, Mode::empty())
            .map_err(KvmError::CouldNotOpen)?;

        let api_version = unsafe { ioctls::kvm_get_api_version(sys_fd, 0) }
            .map_err(|e| KvmError::FailedIoctl("kvm_get_api_version", e))?
            as u32;

        if api_version != crate::ffi::kvm::KVM_API_VERSION {
            return Err(KvmError::WrongVersion(api_version));
        }

        Ok(Self { fd: sys_fd })
    }

    pub fn create_vm(&self) -> Result<VmHandle, KvmError> {
        let vm_fd = unsafe { ioctls::kvm_create_vm(self.fd, 0) }.map_err_kvm("kvm_create_vm")?;

        // TODO: may want to configure this
        #[allow(overflowing_literals)]
        unsafe { ioctls::kvm_set_tss_addr(vm_fd, 0xfffbd000_i32) }
            .map_err_kvm("kvm_set_tss_addr")?;

        // Always necessary, I think
        unsafe { ioctls::kvm_create_irqchip(vm_fd, 0) }.map_err_kvm("kvm_create_irqchip")?;

        unsafe {
            let mut pic1 = kvm_irqchip {
                chip_id: 0,
                ..mem::zeroed()
            };
            let mut pic2 = kvm_irqchip {
                chip_id: 1,
                ..mem::zeroed()
            };
            ioctls::kvm_get_irqchip(vm_fd, &mut pic1).map_err_kvm("kvm_get_irqchip")?;
            ioctls::kvm_get_irqchip(vm_fd, &mut pic2).map_err_kvm("kvm_get_irqchip")?;

            pic1.chip.pic.irq_base = 0x20;
            pic2.chip.pic.irq_base = 0x20;

            // pic1.chip.pic.imr = 0xFF;
            // pic2.chip.pic.imr = 0xFF;

            ioctls::kvm_set_irqchip(vm_fd, &mut pic1).map_err_kvm("kvm_set_irqchip")?;
            ioctls::kvm_set_irqchip(vm_fd, &mut pic2).map_err_kvm("kvm_set_irqchip")?;

            let mut ioapic = kvm_irqchip {
                chip_id: 2,
                ..mem::zeroed()
            };

            ioctls::kvm_get_irqchip(vm_fd, &mut ioapic).map_err_kvm("kgm_get_irqchip")?;

            info!("IOAPIC: {:#?}", ioapic.chip.ioapic.base_address);
        }

        unsafe {
            ioctls::kvm_create_pit2(
                vm_fd,
                &kvm_pit_config {
                    flags: 0,
                    pad: Default::default(),
                },
            )
            .map_err_kvm("kvm_create_pit2")?;
        }

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

        unsafe { ioctls::kvm_set_user_memory_region(self.fd, &mut memreg) }
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
        let cpu_fd = unsafe { ioctls::kvm_create_vcpu(vm.fd, 0) }.map_err_kvm("kvm_create_vcpu")?;

        let vcpu_mmap_size = unsafe { ioctls::kvm_get_vcpu_mmap_size(sys_fd, 0) }
            .map_err_kvm("kvm_get_vcpu_mmap_size")?;

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

        // unsafe { (*kvm_run).apic_base = 0xfee00000 };

        if kvm_run as *mut c_void == MAP_FAILED {
            return Err(KvmError::FailedAlloc("kvm_run", Errno::from_i32(errno())));
        }

        unsafe {
            let mut lapic = kvm_lapic_state { ..mem::zeroed() };

            ioctls::kvm_get_lapic(cpu_fd, &mut lapic).map_err_kvm("kvm_get_lapic")?;

            info!("{:#?}", lapic);
        }

        Ok(Self {
            fd: cpu_fd,
            kvm_run,
        })
    }
}

pub fn run(
    signal: Receiver<()>,
    cpu: &mut CpuHandle,
    memory: *mut c_void,
    memory_size: usize,
    path: &str,
) -> Result<(), KvmError> {
    #[inline]
    unsafe fn setup_long_mode(memory: *mut c_void, sregs: &mut kvm_sregs, base: u64) {
        // TODO: I am just manually mapping two bigpages here. Need a full allocator for proper elf loading.
        let pml4_addr = 0x2000_u64;
        let pml4 = memory.add(pml4_addr as usize) as *mut u64;

        let pdpt_addr = 0x3000_u64;
        let pdpt = memory.add(pdpt_addr as usize) as *mut u64;

        let pd_addr = 0x4000_u64;
        let pd = memory.add(pd_addr as usize) as *mut u64;

        let pd3_addr = 0x5000_u64;
        let pd3 = memory.add(pd3_addr as usize) as *mut u64;

        let pe503_addr = 0x6000_u64;
        let pe503 = memory.add(pe503_addr as usize) as *mut u64;

        *pml4 = ((PDE64_PRESENT | PDE64_RW) as u64) | pdpt_addr;
        *pdpt = ((PDE64_PRESENT | PDE64_RW) as u64) | pd_addr;
        *(pdpt.add(0b11usize)) = ((PDE64_PRESENT | PDE64_RW) as u64) | pd3_addr;

        *pd = (PDE64_PRESENT | PDE64_RW | PDE64_PS) as u64;
        *(pd.add(1)) = ((PDE64_PRESENT | PDE64_RW | PDE64_PS) as u64) | (2 << 20);
        *(pd.add(2)) = ((PDE64_PRESENT | PDE64_RW | PDE64_PS) as u64) | (4 << 20);
        *(pd.add(3)) = ((PDE64_PRESENT | PDE64_RW | PDE64_PS) as u64) | (6 << 20);
        *(pd.add(4)) = ((PDE64_PRESENT | PDE64_RW | PDE64_PS) as u64) | (8 << 20);
        *(pd.add(5)) = ((PDE64_PRESENT | PDE64_RW | PDE64_PS) as u64) | (0xa << 20);
        *(pd.add(6)) = ((PDE64_PRESENT | PDE64_RW | PDE64_PS) as u64) | (0xc << 20);
        *(pd.add(7)) = ((PDE64_PRESENT | PDE64_RW | PDE64_PS) as u64) | (0xe << 20);

        *(pd3.add(0b111110111usize)) = ((PDE64_PRESENT | PDE64_RW) as u64) | pe503_addr;

        *pe503 = ((PDE64_PRESENT | PDE64_RW) as u64)
            | 0b0000000000000000_000000000_000000011_111110111_000000000_0000_0000_0000;

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

        setup_64bit_code_segment(sregs, base);
    }

    #[inline]
    unsafe fn setup_64bit_code_segment(sregs: &mut kvm_sregs, base: u64) {
        let mut segment = kvm_segment {
            base,
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

    let kernel_binary = std::fs::read(path).expect("failed to open kernel ELF");

    let elf = ElfBinary::new(&kernel_binary.as_slice())
        .expect("failed to parse kernel ELF (is it an ELF file)");

    let relo = 0x200000;

    let mut loader = crate::elf::BasicLoader::new(memory, relo);

    elf.load(&mut loader).expect("failed to load kernel");

    let start_addr = elf.entry_point() + relo;
    let base = relo;

    info!("ELF entry point is: {start_addr:#x}");

    let mut sregs = unsafe { mem::zeroed::<kvm_sregs>() };
    let mut regs = unsafe { mem::zeroed::<kvm_regs>() };

    unsafe { ioctls::kvm_get_sregs(cpu.fd, &mut sregs) }.map_err_kvm("kvm_get_sregs")?;

    unsafe {
        setup_long_mode(memory, &mut sregs, base);
    }

    unsafe { ioctls::kvm_set_sregs(cpu.fd, &mut sregs) }.map_err_kvm("kvm_set_sregs")?;

    regs.rflags = 2;
    regs.rip = start_addr;
    regs.rsp = memory_size as u64;

    unsafe { ioctls::kvm_set_regs(cpu.fd, &mut regs) }.map_err_kvm("kvm_set_regs")?;

    signal.recv().unwrap();

    info!("Display is ready: starting VM.");

    run_loop(cpu, memory)
}

fn run_loop(cpu: &mut CpuHandle, _memory: *mut c_void) -> Result<(), KvmError> {
    'outer: loop {
        unsafe { ioctls::kvm_run(cpu.fd, 0) }.map_err_kvm("kvm_run")?;

        match KvmExit::from_u32(unsafe { *cpu.kvm_run }.exit_reason).unwrap_or_default() {
            // guest called HLT
            KvmExit::Hlt => {
                info!("hlt");
                break 'outer;
            }
            // guest called port IO IN/OUT
            KvmExit::Io => {
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
                    let mut regs = unsafe { mem::zeroed::<kvm_regs>() };
                    unsafe {
                        ioctls::kvm_get_regs(cpu.fd, &mut regs)
                            .expect(&format!("unexpected io ({port}) failed to get regs"));
                    }

                    error!("Unexpected exit:{:#?}", regs);
                    return Err(KvmError::UnhandledIo(
                        unsafe { KvmIoDirection::from_u32_unchecked(direction) },
                        port,
                    ));
                }
            }
            KvmExit::Mmio => unsafe {
                let mmio = (*cpu.kvm_run).__bindgen_anon_1.mmio;
                panic!(
                    "Exit MMIO: apic_base={:#08x}, {:#016x}",
                    (*cpu.kvm_run).apic_base,
                    mmio.phys_addr
                );
            },
            e => {
                let mut regs = unsafe { mem::zeroed::<kvm_regs>() };

                unsafe {
                    ioctls::kvm_get_regs(cpu.fd, &mut regs)
                        .expect(&format!("unexpected exit ({e}) failed to get regs"));
                }

                error!("Unexpected exit: {:#?}", regs);
                return Err(KvmError::UnexpectedExit(e));
            }
        }
    }

    println!(
        "kvm_run apic_base: {:016x}",
        unsafe { *cpu.kvm_run }.apic_base
    );

    println!("Done.");

    Ok(())
}
