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

pub use fb::{print, println};

use crate::iobasic::iobasic_println;

libvmm::entrypoint!(kmain);

const X86_64_APIC_BASE_MSR: u32 = 0x1B;
const PHYSICAL_MEMORY_OFFSET: u64 = 0;

pub static mut APIC: apic::ApicBase = unsafe { apic::ApicBase::new(core::ptr::null_mut()) };

fn kmain() {
    gdt::init();
    interrupts::init_idt();

    // unsafe { x86_64::instructions::port::PortWrite::write_to_port(0x0, 123u8) };
    // iobasic_println!("Hello world!");
    println!("Welcome to the other Temple OS!");

    allocator::init_heap();

    let local_apic_base =
        (unsafe { x86_64::registers::model_specific::Msr::new(X86_64_APIC_BASE_MSR).read() }
            & 0xFFFFF000)
            + PHYSICAL_MEMORY_OFFSET;

    unsafe {
        APIC = apic::ApicBase::new(local_apic_base as *mut ());
    };

    let local_apic = unsafe { &mut APIC };

    {
        // LOCAL_APIC_TIMER

        println!("LAPIC BASE: {:#x}", local_apic_base);

        println!(
            "LAPIC\t\t: #{}, version {}",
            local_apic.id().read().id(),
            local_apic.version().read().version()
        );

        // let mut divide = local_apic.timer_divide_configuration().read();

        // divide.set(TimerDivideConfigurationValue::Divide1);

        // local_apic.timer_divide_configuration().write(divide);

        // let apic_current_count = volatile::Volatile::new(unsafe {
        //     &mut *((lapic_msr_addr + Offset::TimerCurrentCount as u64) as *mut u32)
        // });

        // let mut apic_task_priority = volatile::Volatile::new(unsafe {
        //     &mut *((lapic_msr_addr + Offset::TaskPriority as u64) as *mut u32)
        // });

        // let mut apic_destination_format = volatile::Volatile::new(unsafe {
        //     &mut *((lapic_msr_addr + Offset::DestinationFormat as u64) as *mut u32)
        // });

        // let mut apic_spurious_interrupt_vector = volatile::Volatile::new(unsafe {
        //     &mut *((lapic_msr_addr + Offset::SpuriousInterruptVector as u64) as *mut u32)
        // });

        // let siv = local_apic.spurious_interrupt_vector().read();

        // println!("LAPIC Enable: {}", siv.apic_software_enabled());
        // println!(
        //     "LAPIC ENABLE (raw): {:#0x}",
        //     apic_spurious_interrupt_vector.read()
        // );
        // println!("LAPIC SIV\t: {}", siv.vector());

        // local_apic.spurious_interrupt_vector().write(siv);

        // apic_destination_format.write(0xFFFFFFFF);
        // apic_task_priority.write(0);

        // println!("LAPIC TIMER CNT: {}", apic_current_count.read());

        // let mut divide = local_apic.timer_divide_configuration().read();

        // divide.set(TimerDivideConfigurationValue::Divide128);

        // local_apic.timer_divide_configuration().write(divide);

        // println!("LAPIC TIMER CNT: {}", apic_current_count.read());

        // let mut timer = local_apic.timer_local_vector_table_entry().read();

        // timer.set_vector(IRQ::Timer.as_u8()); //IRQ::Magic.as_u8());
        // timer.set_mask(false);
        // timer.set_timer_mode(true);

        // println!("LAPIC TIMER CNT: {}", apic_current_count.read());

        // local_apic.timer_local_vector_table_entry().write(timer);

        // println!("LAPIC TIMER CNT: {}", apic_current_count.read());

        // let count = {
        //     let mut count = local_apic.timer_initial_count().read();

        //     count.set(0x80000);

        //     count
        // };

        // local_apic.timer_initial_count().write(count);

        // println!("LAPIC TIMER CNT: {}", apic_current_count.read());

        // loop {
        //     println!("Local APIC timer: {}", apic_current_count.read());
        //     waste_time();
        // }
    }
}

#[panic_handler]
fn on_panic(info: &PanicInfo) -> ! {
    iobasic_println!("{}", info);

    libvmm::exit(libvmm::ExitCode::Failed)
}
