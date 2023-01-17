#![no_std]
#![no_main]
#![feature(start)]
#![feature(decl_macro)]
#![feature(const_slice_from_raw_parts_mut)]
#![feature(abi_x86_interrupt)]
#![feature(inline_const)]
#![feature(const_mut_refs)]

extern crate alloc;

mod allocator;
mod fb;
mod gdt;
mod interrupts;
mod iobasic;
mod task;

use core::panic::PanicInfo;

use apic::{
    registers::{TimerDivideConfigurationValue, TimerLocalVectorTableEntry},
    Offset,
};
pub use fb::console::{print, println};

use crate::{fb::psf::get_current_font, iobasic::iobasic_println};

libvmm::entrypoint!(kmain);

const X86_64_APIC_BASE_MSR: u32 = 0x1B;
const PHYSICAL_MEMORY_OFFSET: u64 = 0;

pub static mut APIC: apic::ApicBase = unsafe { apic::ApicBase::new(core::ptr::null_mut()) };

fn kmain() {
    gdt::init();
    interrupts::init_idt();

    println!("Welcome to the other Temple OS!");

    allocator::init_heap();

    x86_64::instructions::interrupts::enable();

    println!("{:?}", get_current_font());

    let local_apic_base =
        (unsafe { x86_64::registers::model_specific::Msr::new(X86_64_APIC_BASE_MSR).read() }
            & 0xFFFFF000)
            + PHYSICAL_MEMORY_OFFSET;

    unsafe {
        APIC = apic::ApicBase::new(local_apic_base as *mut ());
    };

    iobasic_println!("Raw apic_register: {:#016x}", unsafe {
        x86_64::registers::model_specific::Msr::new(X86_64_APIC_BASE_MSR).read()
    });

    let local_apic = unsafe { &mut APIC };

    {
        // LOCAL_APIC_TIMER

        iobasic_println!(
            "LAPIC\t\t: #{}, version {}",
            local_apic.id().read().id(),
            local_apic.version().read().version()
        );

        let mut divide = local_apic.timer_divide_configuration().read();

        divide.set(TimerDivideConfigurationValue::Divide1);

        local_apic.timer_divide_configuration().write(divide);

        let apic_current_count = volatile::Volatile::new(unsafe {
            &mut *((local_apic_base + Offset::TimerCurrentCount as u64) as *mut u32)
        });

        let mut apic_task_priority = volatile::Volatile::new(unsafe {
            &mut *((local_apic_base + Offset::TaskPriority as u64) as *mut u32)
        });

        let mut apic_destination_format = volatile::Volatile::new(unsafe {
            &mut *((local_apic_base + Offset::DestinationFormat as u64) as *mut u32)
        });

        let mut apic_spurious_interrupt_vector = volatile::Volatile::new(unsafe {
            &mut *((local_apic_base + Offset::SpuriousInterruptVector as u64) as *mut u32)
        });

        let mut tlvte = volatile::Volatile::new(unsafe {
            &mut *((local_apic_base + Offset::TimerLocalVectorTableEntry as u64) as *mut u32)
        });

        let mut siv = local_apic.spurious_interrupt_vector().read();

        siv.enable_apic_software(true);

        local_apic.spurious_interrupt_vector().write(siv);

        iobasic_println!("Raw apic_register: {:#016x}", unsafe {
            x86_64::registers::model_specific::Msr::new(X86_64_APIC_BASE_MSR).read()
        });

        iobasic_println!("LAPIC SIV\t: {}", siv.vector());

        apic_destination_format.write(0xFFFFFFFF);
        apic_task_priority.write(0);

        iobasic_println!("LAPIC TIMER CNT: {}", apic_current_count.read());

        let mut divide = local_apic.timer_divide_configuration().read();

        divide.set(TimerDivideConfigurationValue::Divide128);

        local_apic.timer_divide_configuration().write(divide);

        iobasic_println!("LAPIC TIMER CNT: {}", apic_current_count.read());

        let count = {
            let mut count = local_apic.timer_initial_count().read();

            count.set(0x80000);

            count
        };

        local_apic.timer_initial_count().write(count);

        iobasic_println!("LAPIC TIMER CNT: {}", apic_current_count.read());

        let mut timer = 0;

        timer = (timer & 0xFFFFFF00) | 0x20;
        // timer.set_mask(false);
        // timer.set_timer_mode(true);
        timer = timer | (1 << 17);

        tlvte.write(timer);

        iobasic_println!("TLVTE CMP: {:#0x}, {:#0x}", timer, tlvte.read());

        iobasic_println!("LAPIC TIMER CNT: {}", apic_current_count.read());

        loop {
            // iobasic_println!("Local APIC timer: {}", apic_current_count.read());
            libvmm::waste_time();
        }
    }

    iobasic_println!("Quitting.");

    libvmm::hlt();
}

#[panic_handler]
fn on_panic(info: &PanicInfo) -> ! {
    iobasic_println!("{}", info);

    libvmm::exit(libvmm::ExitCode::Failed)
}
