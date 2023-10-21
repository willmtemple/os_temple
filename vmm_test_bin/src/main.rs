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
mod initrd;
mod interrupts;
mod iobasic;
mod task;
mod virtio;

use core::panic::PanicInfo;

use apic::{registers::TimerDivideConfigurationValue, Offset};
pub use fb::console::{print, println};

use crate::{initrd::MOTD, interrupts::IRQ, iobasic::iobasic_println};

const X86_64_APIC_BASE_MSR: u32 = 0x1B;
pub const PHYSICAL_MEMORY_OFFSET: u64 = 0xffff_ffff_8000_0000u64;

pub static mut APIC: apic::ApicBase = unsafe { apic::ApicBase::new(core::ptr::null_mut()) };

libvmm::entrypoint!(kmain);

fn kmain() {
    gdt::init();
    interrupts::init_idt();

    println!("{}", *MOTD);

    allocator::init_heap().expect("failed to initialize kernel heap");

    x86_64::instructions::interrupts::enable();

    let local_apic_base =
        (unsafe { x86_64::registers::model_specific::Msr::new(X86_64_APIC_BASE_MSR).read() }
            & 0xFFFFF000);

    unsafe {
        APIC = apic::ApicBase::new(local_apic_base as *mut ());
    };

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

        let mut apic_task_priority = volatile::Volatile::new(unsafe {
            &mut *((local_apic_base + Offset::TaskPriority as u64) as *mut u32)
        });

        let mut apic_destination_format = volatile::Volatile::new(unsafe {
            &mut *((local_apic_base + Offset::DestinationFormat as u64) as *mut u32)
        });

        let mut siv = local_apic.spurious_interrupt_vector().read();

        siv.enable_apic_software(true);

        local_apic.spurious_interrupt_vector().write(siv);

        apic_destination_format.write(0xFFFFFFFF);
        apic_task_priority.write(0);

        let mut divide = local_apic.timer_divide_configuration().read();

        divide.set(TimerDivideConfigurationValue::Divide128);

        local_apic.timer_divide_configuration().write(divide);

        let count = {
            let mut count = local_apic.timer_initial_count().read();

            count.set(0x80000);

            count
        };

        local_apic.timer_initial_count().write(count);

        let mut timer = local_apic.timer_local_vector_table_entry().read();

        timer.set_mask(false);
        timer.set_timer_mode(true);
        timer.set_vector(IRQ::Timer.as_u8());

        local_apic.timer_local_vector_table_entry().write(timer);
    }

    // println!("{}", virtio::blk::get_blk_device());

    libvmm::hlt();
}

#[panic_handler]
fn on_panic(info: &PanicInfo) -> ! {
    iobasic_println!("{}", info);

    libvmm::exit(libvmm::ExitCode::Failed)
}
