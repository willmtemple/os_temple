use crate::hal::GuestMemory;
use crate::hal::{VirtualCpu, VirtualMachine, VirtualMachineError};

use libwhp::Partition;
use log::debug;
use log::error;
use log::info;
use thiserror::Error;

pub fn get_platform_virtualization_provider(
) -> Result<WhpVirtualMachine, VirtualMachineError<WhpError>> {
    WhpVirtualMachine::initialize()
}

pub struct WhpVirtualMachine {
    partition: Partition,
    cpu_info: CpuInfo,
    phys_memories: Vec<VirtualMemory>,
    mappings: Vec<GPARangeMapping>,
}

#[derive(Debug, Error)]
pub enum WhpError {
    #[error("the Windows Hypervisor Platform is not present on the system")]
    NotPresent,
    #[error("{0}")]
    HypervisorPlatformError(WHPError),
    #[error("failed to set registers of virtual CPU")]
    SetRegisters(WHPError),
    #[error("failed to map primary memory")]
    MapMemory(WHPError),
}

impl VirtualMachine for WhpVirtualMachine {
    type CPU = WhpVCPU;

    type E = WhpError;

    fn initialize() -> Result<Self, crate::hal::VirtualMachineError<Self::E>> {
        check_hypervisor().map_err(VirtualMachineError::Init)?;

        let mut partition = Partition::new().unwrap();

        let apic_present = is_apic_present();

        let mut cpu_info = CpuInfo {
            apic_enabled: false,
        };

        setup_partition(&mut partition, &mut cpu_info, apic_present)
            .map_err(VirtualMachineError::CreateVm)?;

        Ok(Self {
            partition,
            cpu_info,
            mappings: vec![],
            phys_memories: vec![],
        })
    }

    fn create_vcpu(
        &mut self,
        memory: &mut [u8],
    ) -> Result<Self::CPU, crate::hal::VirtualMachineError<Self::E>> {
        let mut vp = self.partition.create_virtual_processor(0).unwrap();

        setup_long_mode(&mut vp, memory).map_err(VirtualMachineError::CreateVCPU)?;

        let processor = Arc::new(Mutex::new(vp));

        let callbacks = SampleCallbacks { processor };

        let emulator = Emulator::<SampleCallbacks>::new().unwrap();

        if self.cpu_info.apic_enabled {
            // Set the APIC base and send an interrupt to the VCPU
            set_apic_base(&mut callbacks.processor.lock().unwrap());
            // send_ipi(&mut callbacks.processor.borrow_mut(), INT_VECTOR);
            // set_delivery_notifications(&mut callbacks.processor.borrow_mut());
        }

        Ok(WhpVCPU {
            emulator,
            callbacks,
        })
    }

    fn allocate_guest_memory(
        &mut self,
        guest_address: u64,
        len: usize,
    ) -> Result<crate::hal::GuestMemory, VirtualMachineError<Self::E>> {
        let memory = VirtualMemory::new(len).unwrap();

        let mapping = self
            .partition
            .map_gpa_range(
                &memory,
                guest_address,
                memory.get_size() as UINT64,
                WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead
                    | WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagWrite
                    | WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagExecute,
            )
            .map_err(|e| VirtualMachineError::AllocRam(WhpError::MapMemory(e)))?;

        info!(
            "Memory map: {:#x}->{:#p} [0x{:x}]",
            mapping.get_guest_address(),
            mapping.get_source_address(),
            mapping.get_size()
        );

        let guest_mem = unsafe {
            GuestMemory::new(
                mapping.get_guest_address(),
                memory.as_ptr() as usize,
                memory.get_size(),
            )
        };

        self.phys_memories.push(memory);
        self.mappings.push(mapping);

        Ok(guest_mem)
    }
}

pub struct WhpVCPU {
    callbacks: SampleCallbacks,
    emulator: Emulator<SampleCallbacks>,
}

impl VirtualCpu for WhpVCPU {
    type Exit = WHV_RUN_VP_EXIT_CONTEXT;

    fn run(&mut self) -> Self::Exit {
        let r = self.callbacks.processor.lock().unwrap().run().unwrap();

        r
    }

    fn handle_exit(&mut self, exit: Self::Exit) -> Result<(), String> {
        match exit.ExitReason {
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Halt => {
                info!("All done!");
                Err("finished".into())
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonException => Ok(()),
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonMemoryAccess => {
                debug!("Memory access exit.");
                handle_mmio_exit(&mut self.emulator, &mut self.callbacks, &exit);
                Ok(())
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64IoPortAccess => {
                // debug!("IO port access exit.");
                handle_io_port_exit(&mut self.emulator, &mut self.callbacks, &exit);
                Ok(())
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Cpuid => {
                debug!("CPUID exit.");
                handle_cpuid_exit(&mut self.callbacks.processor.lock().unwrap(), &exit);
                Ok(())
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64MsrAccess => {
                debug!("MSR exit.");
                handle_msr_exit(&mut self.callbacks.processor.lock().unwrap(), &exit);
                Ok(())
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64ApicEoi => {
                info!("ApicEoi");
                Ok(())
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64InterruptWindow => {
                info!("Interrupt window");
                Err("Interrupt window".into())
            }
            _ => Err(format!("Unexpected exit type: {:?}", exit.ExitReason)),
        }
    }

    fn set_rip(&mut self, rip: u64) {
        let mut reg_names: [WHV_REGISTER_NAME; 1] = Default::default();
        let mut reg_values: [WHV_REGISTER_VALUE; 1] = Default::default();

        reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterRip;
        reg_values[0].Reg64 = rip;

        self.callbacks
            .processor
            .lock()
            .unwrap()
            .set_registers(&reg_names[..], &reg_values[..])
            .unwrap();
    }
}

use ::x86_64::structures::paging::PageTable;
use libwhp::instruction_emulator::*;
use libwhp::memory::*;
use libwhp::*;

use std::io::{self, Write};
use std::process::exit;

use std::sync::{Arc, Mutex};

const CPUID_EXT_HYPERVISOR: UINT32 = 1 << 31;

const PDE64_PRESENT: u64 = 1;
const PDE64_RW: u64 = 1 << 1;
const PDE64_USER: u64 = 1 << 2;
const PDE64_PS: u64 = 1 << 7;
const CR4_PAE: u64 = 1 << 5;
const CR4_PSE: u64 = 1 << 4;
// const CR4_OSFXSR: u64 = 1 << 9;
// const CR4_OSXMMEXCPT: u64 = 1 << 10;

const CR0_PE: u64 = 1;
const CR0_MP: u64 = 1 << 1;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_WP: u64 = 1 << 16;
const CR0_AM: u64 = 1 << 18;
const CR0_PG: u64 = 1 << 31;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

// const INT_VECTOR: u32 = 0x35;

#[allow(non_snake_case)]
#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
struct CpuInfo {
    apic_enabled: bool,
}

fn set_apic_base(vp: &mut VirtualProcessor) {
    // Page table translations for this guest only cover the first 1GB of memory,
    // and the default APIC base falls above that. Set the APIC base to
    // something lower, within our range of virtual memory

    // Get the default APIC base register value to start
    const NUM_REGS: usize = 1;
    let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS] = Default::default();
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterApicBase;

    // Get the registers as a baseline
    vp.get_registers(&reg_names, &mut reg_values).unwrap();
    let mut flags = unsafe { reg_values[0].Reg64 };

    // Mask off the bottom 12 bits, which are used to store flags
    flags = flags & 0xfff;

    // Set the APIC base to something lower within our translatable address
    // space
    let new_apic_base = 0xfee0_0000;
    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterApicBase;
    reg_values[0].Reg64 = new_apic_base | flags;
    vp.set_registers(&reg_names, &reg_values).unwrap();
}

// fn send_msi(vp: &mut VirtualProcessor, message: &WHV_MSI_ENTRY) {
//     let addr: UINT32 = unsafe { message.anon_struct.Address };
//     let data: UINT32 = unsafe { message.anon_struct.Data };

//     let dest = (addr & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
//     let vector = (data & MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT;
//     let dest_mode = (addr >> MSI_ADDR_DEST_MODE_SHIFT) & 0x1;
//     let trigger_mode = (data >> MSI_DATA_TRIGGER_SHIFT) & 0x1;
//     let delivery = (data >> MSI_DATA_DELIVERY_MODE_SHIFT) & 0x7;

//     let mut interrupt: WHV_INTERRUPT_CONTROL = Default::default();

//     interrupt.set_InterruptType(delivery as UINT64);

//     if dest_mode == 0 {
//         interrupt.set_DestinationMode(
//             WHV_INTERRUPT_DESTINATION_MODE::WHvX64InterruptDestinationModePhysical as UINT64,
//         );
//     } else {
//         interrupt.set_DestinationMode(
//             WHV_INTERRUPT_DESTINATION_MODE::WHvX64InterruptDestinationModeLogical as UINT64,
//         );
//     }

//     interrupt.set_TriggerMode(trigger_mode as UINT64);

//     interrupt.Destination = dest;
//     interrupt.Vector = vector;

//     vp.request_interrupt(&mut interrupt).unwrap();
// }

// fn send_ipi(vp: &mut VirtualProcessor, vector: u32) {
//     info!("Send IPI from the host to the guest");

//     let mut message: WHV_MSI_ENTRY = Default::default();

//     // - Trigger mode is 'Edge'
//     // - Interrupt type is 'Fixed'
//     // - Destination mode is 'Physical'
//     // - Destination is 0. Since Destination Mode is Physical, bits 56-59
//     //   contain the APIC ID of the target processor (APIC ID = 0)
//     // Level = 1 and Destination Shorthand = 1, but the underlying API will
//     // actually ignore this.
//     message.anon_struct.Data = (0x00044000 | vector) as UINT32;
//     message.anon_struct.Address = 0;

//     send_msi(vp, &message);
// }

// fn set_delivery_notifications(vp: &mut VirtualProcessor) {
//     const NUM_REGS: usize = 1;
//     let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();
//     let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS] = Default::default();

//     let mut notifications: WHV_X64_DELIVERABILITY_NOTIFICATIONS_REGISTER = Default::default();
//     notifications.set_InterruptNotification(1);
//     reg_values[0].DeliverabilityNotifications = notifications;
//     reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterDeliverabilityNotifications;
//     vp.set_registers(&reg_names, &reg_values).unwrap();
// }

fn handle_msr_exit(vp: &mut VirtualProcessor, exit_context: &WHV_RUN_VP_EXIT_CONTEXT) {
    let msr_access = unsafe { exit_context.anon_union.MsrAccess };

    const NUM_REGS: UINT32 = 3;
    let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize] = Default::default();
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize] = Default::default();

    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterRip;
    reg_names[1] = WHV_REGISTER_NAME::WHvX64RegisterRax;
    reg_names[2] = WHV_REGISTER_NAME::WHvX64RegisterRdx;

    reg_values[0].Reg64 =
        exit_context.VpContext.Rip + exit_context.VpContext.InstructionLength() as u64;

    match msr_access.MsrNumber {
        1 => {
            if msr_access.AccessInfo.IsWrite() == 1 {
                info!(
                    "MSR write. Number: 0x{:x}, Rax: 0x{:x}, Rdx: 0x{:x}",
                    msr_access.MsrNumber, msr_access.Rax, msr_access.Rdx
                );
            } else {
                let rax = 0x2000;
                let rdx = 0x2001;
                reg_values[1].Reg64 = rax;
                reg_values[2].Reg64 = rdx;
                info!(
                    "MSR read. Number: 0x{:x}, Rax: 0x{:x}, Rdx: 0x{:x}",
                    msr_access.MsrNumber, rax, rdx
                );
            }
        }
        _ => {
            info!("Unknown MSR number: {:#x}", msr_access.MsrNumber);
        }
    }

    let mut num_regs_set = NUM_REGS as usize;
    if msr_access.AccessInfo.IsWrite() == 1 {
        num_regs_set = 1;
    }

    vp.set_registers(&reg_names[0..num_regs_set], &reg_values[0..num_regs_set])
        .unwrap();
}

fn handle_cpuid_exit(vp: &mut VirtualProcessor, exit_context: &WHV_RUN_VP_EXIT_CONTEXT) {
    let cpuid_access = unsafe { exit_context.anon_union.CpuidAccess };
    info!("Got CPUID leaf: {}", cpuid_access.Rax);

    const NUM_REGS: UINT32 = 5;
    let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize] = Default::default();
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize] = Default::default();

    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterRip;
    reg_names[1] = WHV_REGISTER_NAME::WHvX64RegisterRax;
    reg_names[2] = WHV_REGISTER_NAME::WHvX64RegisterRbx;
    reg_names[3] = WHV_REGISTER_NAME::WHvX64RegisterRcx;
    reg_names[4] = WHV_REGISTER_NAME::WHvX64RegisterRdx;

    reg_values[0].Reg64 =
        exit_context.VpContext.Rip + exit_context.VpContext.InstructionLength() as u64;
    reg_values[1].Reg64 = cpuid_access.DefaultResultRax;
    reg_values[2].Reg64 = cpuid_access.DefaultResultRbx;
    reg_values[3].Reg64 = cpuid_access.DefaultResultRcx;
    reg_values[4].Reg64 = cpuid_access.DefaultResultRdx;

    match cpuid_access.Rax {
        1 => {
            reg_values[3].Reg64 = CPUID_EXT_HYPERVISOR as UINT64;
        }
        _ => {
            info!("Unknown CPUID leaf: {}", cpuid_access.Rax);
        }
    }

    vp.set_registers(&reg_names, &reg_values).unwrap();
}

fn handle_mmio_exit<T: EmulatorCallbacks>(
    e: &mut Emulator<T>,
    context: &mut T,
    exit_context: &WHV_RUN_VP_EXIT_CONTEXT,
) {
    let mem_access_ctx = unsafe { &exit_context.anon_union.MemoryAccess };
    debug!("Memory access ctx: {:#?}", mem_access_ctx);
    let _status = e
        .try_mmio_emulation(context, &exit_context.VpContext, mem_access_ctx)
        .unwrap();

    debug!("{}", _status.to_string());
}

fn handle_io_port_exit<T: EmulatorCallbacks>(
    e: &mut Emulator<T>,
    context: &mut T,
    exit_context: &WHV_RUN_VP_EXIT_CONTEXT,
) {
    let io_port_access_ctx = unsafe { &exit_context.anon_union.IoPortAccess };
    let _status = e
        .try_io_emulation(context, &exit_context.VpContext, io_port_access_ctx)
        .unwrap();
}

fn setup_partition(
    p: &mut Partition,
    cpu_info: &mut CpuInfo,
    apic_present: bool,
) -> Result<(), WhpError> {
    let mut property: WHV_PARTITION_PROPERTY = Default::default();

    property.ProcessorCount = 1;

    p.set_property(
        WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
        &property,
    )
    .map_err(WhpError::HypervisorPlatformError)?;

    property = Default::default();

    unsafe {
        property.ExtendedVmExits.set_X64CpuidExit(1);
        property.ExtendedVmExits.set_X64MsrExit(1);
        property.ExtendedVmExits.set_ExceptionExit(1);
    }

    p.set_property(
        WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeExtendedVmExits,
        &property,
    )
    .map_err(WhpError::HypervisorPlatformError)?;

    let cpuids: [UINT32; 1] = [1];
    p.set_property_cpuid_exits(&cpuids)
        .map_err(WhpError::HypervisorPlatformError)?;

    let mut cpuid_results: [WHV_X64_CPUID_RESULT; 1] = Default::default();

    cpuid_results[0].Function = 0x40000000;
    let mut id_reg_values: [UINT32; 3] = [0; 3];
    let id = "libwhp\0";
    unsafe {
        std::ptr::copy_nonoverlapping(id.as_ptr(), id_reg_values.as_mut_ptr() as *mut u8, id.len());
    }
    cpuid_results[0].Ebx = id_reg_values[0];
    cpuid_results[0].Ecx = id_reg_values[1];
    cpuid_results[0].Edx = id_reg_values[2];

    p.set_property_cpuid_results(&cpuid_results)
        .map_err(WhpError::HypervisorPlatformError)?;

    if apic_present != false {
        enable_apic(p, cpu_info);
    }

    p.setup().map_err(WhpError::HypervisorPlatformError)
}

fn is_apic_present() -> bool {
    let capability: WHV_CAPABILITY =
        get_capability(WHV_CAPABILITY_CODE::WHvCapabilityCodeFeatures).unwrap();
    let features: WHV_CAPABILITY_FEATURES = unsafe { capability.Features };

    if features.LocalApicEmulation() != 0 {
        true
    } else {
        false
    }
}

fn enable_apic(p: &mut Partition, cpu_info: &mut CpuInfo) {
    let mut property: WHV_PARTITION_PROPERTY = Default::default();
    property.LocalApicEmulationMode =
        WHV_X64_LOCAL_APIC_EMULATION_MODE::WHvX64LocalApicEmulationModeXApic;

    p.set_property(
        WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeLocalApicEmulationMode,
        &property,
    )
    .unwrap();

    cpu_info.apic_enabled = true;
}

fn initialize_address_space(payload_mem: &mut [u8]) -> u64 {
    info!("Initializing address space {:p}.", payload_mem.as_ptr());
    let memory = payload_mem.as_ptr();
    unsafe {
        let pml4_addr = 0x2000_u64;
        let pml4 = memory.add(pml4_addr as usize) as *mut u64;

        let pdpt_addr = 0x3000_u64;
        let pdpt = memory.add(pdpt_addr as usize) as *mut u64;

        let pd3_addr = 0x4000_u64;
        let pd3 = memory.add(pd3_addr as usize) as *mut u64;

        // PE503 identity-maps the default physical address of the Local APIC (0xfee00000)
        let pe503_addr = 0x5000_u64;
        let pe503 = memory.add(pe503_addr as usize) as *mut u64;

        *pml4 = ((PDE64_PRESENT | PDE64_RW) as u64) | pdpt_addr;
        *(pdpt.add(0b11usize)) = ((PDE64_PRESENT | PDE64_RW) as u64) | pd3_addr;

        *(pd3.add(0b111110111usize)) =
            ((PDE64_PRESENT | PDE64_USER | PDE64_RW) as u64) | pe503_addr;

        *pe503 = ((PDE64_PRESENT | PDE64_RW) as u64)
            | 0b0000000000000000_000000000_000000011_111110111_000000000_0000_0000_0000;

        // Map the whole first 2GiB of physical memory to the physical base. We don't set the USER bit so that the
        // kernel can make effective use of this space.
        let hh_pml4_idx = (WhpVirtualMachine::VIRTUAL_2GIB_PBASE_OFFSET.as_u64()
            & 0b0000000000000000_111111111_000000000_000000000_000000000_000000000000u64)
            >> 39;

        let hh_pdpt_idx = (WhpVirtualMachine::VIRTUAL_2GIB_PBASE_OFFSET.as_u64()
            & 0b0000000000000000_000000000_111111111_000000000_000000000_000000000000u64)
            >> 30;

        let hh_pdp_addr = 0x6000_u64;
        let hh_pdp = memory.add(hh_pdp_addr as usize) as *mut u64;

        *(pml4.add(hh_pml4_idx as usize)) = ((PDE64_PRESENT | PDE64_RW) as u64) | hh_pdp_addr;
        *(hh_pdp.add(hh_pdpt_idx as usize)) = ((PDE64_PRESENT | PDE64_RW | PDE64_PS) as u64) | 0x0;
        *(hh_pdp.add(hh_pdpt_idx as usize + 1)) =
            ((PDE64_PRESENT | PDE64_RW | PDE64_PS) as u64) | (1 * 1024 * 1024 * 1024);

        info!("Wrote page table.");

        let l4 = &mut *(memory.add(pml4_addr as usize) as *mut PageTable);
        for entry in l4.iter() {
            if (entry.flags().bits() & (PDE64_PRESENT as u64)) != 0 {
                info!("{:?}", entry);
            }
        }

        info!("PML4 loaded at {:016x}", pml4_addr);

        pml4_addr
    }
}

fn setup_long_mode(vp: &mut VirtualProcessor, payload_mem: &mut [u8]) -> Result<(), WhpError> {
    let pml4_addr = initialize_address_space(payload_mem);

    info!("PML4 loaded at {:#x}", pml4_addr);

    const NUM_REGS: UINT32 = 13;
    let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize] = Default::default();
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize] = Default::default();

    // Setup paging
    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterCr3;
    reg_values[0].Reg64 = pml4_addr;
    reg_names[1] = WHV_REGISTER_NAME::WHvX64RegisterCr4;
    reg_values[1].Reg64 = CR4_PAE | CR4_PSE; //  | CR4_OSFXSR | CR4_OSXMMEXCPT;

    reg_names[2] = WHV_REGISTER_NAME::WHvX64RegisterCr0;
    reg_values[2].Reg64 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    reg_names[3] = WHV_REGISTER_NAME::WHvX64RegisterEfer;
    reg_values[3].Reg64 = EFER_LME | EFER_LMA;

    reg_names[4] = WHV_REGISTER_NAME::WHvX64RegisterCs;
    unsafe {
        let segment = &mut reg_values[4].Segment;
        segment.Base = 00000;
        segment.Limit = 0xffffffff;
        segment.Selector = 1 << 3;
        segment.set_SegmentType(11);
        segment.set_NonSystemSegment(1);
        segment.set_Present(1);
        segment.set_Long(1);
        segment.set_Granularity(1);
    }

    reg_names[5] = WHV_REGISTER_NAME::WHvX64RegisterDs;
    unsafe {
        let segment = &mut reg_values[5].Segment;
        segment.Base = 00000;
        segment.Limit = 0xffffffff;
        segment.Selector = 2 << 3;
        segment.set_SegmentType(3);
        segment.set_NonSystemSegment(1);
        segment.set_Present(1);
        segment.set_Long(1);
        segment.set_Granularity(1);
    }

    reg_names[6] = WHV_REGISTER_NAME::WHvX64RegisterEs;
    reg_values[6] = reg_values[5];

    reg_names[7] = WHV_REGISTER_NAME::WHvX64RegisterFs;
    reg_values[7] = reg_values[5];

    reg_names[8] = WHV_REGISTER_NAME::WHvX64RegisterGs;
    reg_values[8] = reg_values[5];

    reg_names[9] = WHV_REGISTER_NAME::WHvX64RegisterSs;
    reg_values[9] = reg_values[5];

    // Start with the Interrupt Flag off; guest will enable it when ready
    reg_names[10] = WHV_REGISTER_NAME::WHvX64RegisterRflags;
    reg_values[10].Reg64 = 0x002;

    reg_names[11] = WHV_REGISTER_NAME::WHvX64RegisterRip;
    reg_values[11].Reg64 = 0;

    // Create stack with stack base at high end of mapped payload
    reg_names[12] = WHV_REGISTER_NAME::WHvX64RegisterRsp;
    reg_values[12].Reg64 = (WhpVirtualMachine::VIRTUAL_2GIB_PBASE_OFFSET.as_u64() as usize
        + payload_mem.len()) as UINT64;

    vp.set_registers(&reg_names, &reg_values)
        .map_err(WhpError::SetRegisters)?;

    Ok(())
}

fn check_hypervisor() -> Result<(), WhpError> {
    let capability =
        get_capability(WHV_CAPABILITY_CODE::WHvCapabilityCodeHypervisorPresent).unwrap();

    if unsafe { capability.HypervisorPresent } == FALSE {
        Err(WhpError::NotPresent)
    } else {
        Ok(())
    }
}

struct SampleCallbacks {
    processor: Arc<Mutex<VirtualProcessor>>,
}

impl EmulatorCallbacks for SampleCallbacks {
    fn io_port(&mut self, io_access: &mut WHV_EMULATOR_IO_ACCESS_INFO) -> HRESULT {
        if io_access.Direction == 1 {
            // Our payload writes to port 42
            if io_access.Port == 42 {
                let data = unsafe {
                    std::slice::from_raw_parts(
                        &io_access.Data as *const _ as *const u8,
                        io_access.AccessSize as usize,
                    )
                };
                io::stdout().write(data).unwrap();
            } else if io_access.Port == 0xE9 {
                print!("{}", unsafe {
                    char::from_u32_unchecked(io_access.Data & 0xFFu32)
                });
            } else if io_access.Port == 0xF4 {
                error!("Guest panic.");
                exit(1);
            } else {
                error!("Unsupported IO port 0x{:04x}", io_access.Port);
            }
        } else {
            // Our payload reads from port 43. Set a value in the Data buffer
            // to simulate an IO read, that the payload will "read" later
            if io_access.Port == 43 {
                let data = unsafe {
                    std::slice::from_raw_parts_mut(
                        &mut io_access.Data as *mut _ as *mut u8,
                        io_access.AccessSize as usize,
                    )
                };
                data[0] = 99;
            }
        }
        S_OK
    }

    fn memory(&mut self, memory_access: &mut WHV_EMULATOR_MEMORY_ACCESS_INFO) -> HRESULT {
        let addr = memory_access.GpaAddress;
        match memory_access.AccessSize {
            8 => match memory_access.Direction {
                0 => {
                    let data = (&mut memory_access.Data) as *const _ as *mut u64;
                    unsafe {
                        *data = 0x1000;
                        info!("MMIO read: 0x{:016x} @0x{:x}", *data, addr);
                    }
                }
                _ => {
                    let value = unsafe { *(&memory_access.Data as *const _ as *const u64) };
                    info!("MMIO write: 0x{:016x} @0x{:x}", value, addr);
                }
            },
            4 => match memory_access.Direction {
                0 => {
                    let data = &mut memory_access.Data as *const _ as *mut u32;
                    unsafe {
                        *data = 0x1000;
                        info!("MMIO read: 0x{:08x} @0x{:x}", *data, addr);
                    }
                }
                _ => {
                    let value = unsafe { *(&memory_access.Data as *const _ as *const u32) };
                    info!("MMIO write: 0x{:08x} @0x{:x}", value, addr);
                }
            },
            2 => match memory_access.Direction {
                0 => {
                    let data = &mut memory_access.Data as *const _ as *mut u32;
                    unsafe {
                        *data = 0x22bb;
                        info!("MMIO read: 0x{:04x} @0x{:x}", *data, addr);
                    }
                }
                _ => {
                    let value = unsafe { *(&memory_access.Data as *const _ as *const u32) };
                    info!("MMIO write: 0x{:04x} @0x{:x}", value, addr);
                }
            },
            1 => match memory_access.Direction {
                0 => {
                    let data = &mut memory_access.Data as *const _ as *mut u32;
                    unsafe {
                        *data = 0x58;
                        info!("MMIO read: 0x{:02x} @0x{:x}", *data, addr);
                    }
                }
                _ => {
                    let value = unsafe { *(&memory_access.Data as *const _ as *const u32) };
                    info!("MMIO write: 0x{:02x} @0x{:x}", value, addr);
                }
            },
            _ => info!("Unsupported MMIO access size: {}", memory_access.AccessSize),
        }

        S_OK
    }

    fn get_virtual_processor_registers(
        &mut self,
        register_names: &[WHV_REGISTER_NAME],
        register_values: &mut [WHV_REGISTER_VALUE],
    ) -> HRESULT {
        self.processor
            .lock()
            .unwrap()
            .get_registers(register_names, register_values)
            .unwrap();
        S_OK
    }

    fn set_virtual_processor_registers(
        &mut self,
        register_names: &[WHV_REGISTER_NAME],
        register_values: &[WHV_REGISTER_VALUE],
    ) -> HRESULT {
        self.processor
            .lock()
            .unwrap()
            .set_registers(register_names, register_values)
            .unwrap();
        S_OK
    }

    fn translate_gva_page(
        &mut self,
        gva: WHV_GUEST_VIRTUAL_ADDRESS,
        translate_flags: WHV_TRANSLATE_GVA_FLAGS,
        translation_result: &mut WHV_TRANSLATE_GVA_RESULT_CODE,
        gpa: &mut WHV_GUEST_PHYSICAL_ADDRESS,
    ) -> HRESULT {
        debug!(
            "GVA: {:#x}, GPA: {:#x}, FLAGS: {:#?}",
            gva, gpa, translate_flags
        );

        // *gpa = gva;
        // *translation_result = WHV_TRANSLATE_GVA_RESULT_CODE::WHvTranslateGvaResultSuccess;

        *gpa = gva - WhpVirtualMachine::VIRTUAL_2GIB_PBASE_OFFSET.as_u64();
        *translation_result = WHV_TRANSLATE_GVA_RESULT_CODE::WHvTranslateGvaResultSuccess;
        return S_OK;

        let r = match self
            .processor
            .lock()
            .unwrap()
            .translate_gva(gva, WHV_TRANSLATE_GVA_FLAGS::empty())
        {
            Ok((translation_result1, gpa1)) => {
                *translation_result = translation_result1.ResultCode;
                *gpa = gpa1;
                S_OK
            }
            Err(e) => {
                error!(
                    "Failed to translate Guest Physical Address: {}",
                    e.to_string()
                );
                *translation_result =
                    WHV_TRANSLATE_GVA_RESULT_CODE::WHvTranslateGvaResultGpaUnmapped;
                e.result()
            }
        };

        debug!(
            "GVA: {:#x}, GPA: {:#x}, FLAGS: {:#?}, RESULT: {:#?} ({:x})",
            gva, gpa, translate_flags, translation_result, r as u32
        );

        r
    }
}
