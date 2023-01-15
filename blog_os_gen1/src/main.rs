#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![feature(alloc_error_handler)]
#![feature(abi_x86_interrupt)]
#![feature(const_mut_refs)]
#![feature(asm_const)]
#![feature(inline_const)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use acpi::{sdt::Signature, InterruptModel};
use alloc::boxed::Box;

use apic::io_apic::{values::DeliveryMode, IoApicBase};
use bootloader::{boot_info::PixelFormat, entry_point, BootInfo};
use core::panic::PanicInfo;
use pci_types::HeaderType;
use x86_64::VirtAddr;

use crate::{
    interrupts::IRQ,
    memory::BootInfoFrameAllocator,
    pci::{ExtendedConfiguration, IoConfiguration},
    task::{executor::Executor, keyboard::handle_keypresses, Task},
};

mod acpi_aml;
mod allocator;
mod command;
mod fb;
mod gdt;
mod interrupts;
mod memory;
mod pci;
mod serial;
mod task;
mod virtio;

const X86_64_APIC_BASE_MSR: u32 = 0x1B;

pub static mut APIC: apic::ApicBase = unsafe { apic::ApicBase::new(core::ptr::null_mut()) };

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    let framebuffer = boot_info.framebuffer.as_mut().unwrap();

    let info = framebuffer.info();

    fb::init(boot_info.framebuffer.as_mut().unwrap(), info);

    gdt::init();

    let px_format = info.pixel_format;

    if px_format == PixelFormat::BGR && info.bytes_per_pixel == 4 {
        fb::CONSOLE.lock().clear();
    } else {
        panic!("Unexpected pixel format: {:?}", px_format);
    }

    println!("Welcome to os_temple!");

    interrupts::init_idt();

    // provoke a page fault
    // println!("{:#0}", unsafe { *(0xdeadbeef as *const u8) });

    println!(
        "bootloader\t: {}.{}.{}",
        boot_info.version_major, boot_info.version_minor, boot_info.version_patch
    );

    println!(
        "framebuffer\t: {}x{} ({:?})",
        info.horizontal_resolution, info.vertical_resolution, info.pixel_format
    );

    println!(
        "physical\t: {:#0x}",
        boot_info.physical_memory_offset.as_ref().unwrap()
    );

    let physical_memory_offset = *boot_info.physical_memory_offset.as_ref().unwrap();
    let physical_offset = VirtAddr::new(physical_memory_offset);

    let mut mapper = unsafe { memory::init(physical_offset) };
    let mut frame_allocator = unsafe { BootInfoFrameAllocator::init(&boot_info.memory_regions) };

    allocator::init_heap(&mut mapper, &mut frame_allocator).unwrap();

    let handler = acpi_aml::Handler::new(physical_memory_offset as usize);

    let acpi_table = unsafe {
        acpi::AcpiTables::from_rsdp(
            handler,
            *boot_info
                .rsdp_addr
                .as_ref()
                .expect("No rsdp address provided") as usize,
        )
    }
    .unwrap();

    println!("ACPI\t\t: {}", acpi_table.revision);

    let platform = acpi_table.platform_info().unwrap();

    println!(
        "Processor\t: {:#?}",
        platform.processor_info.unwrap().boot_processor
    );

    let apic_info = if let InterruptModel::Apic(apic_info) = platform.interrupt_model {
        println!(
            "Has APIC\t: yes (legacy PICs = {})",
            apic_info.also_has_legacy_pics
        );
        apic_info
    } else {
        panic!("No APIC detected");
    };

    let dsdt = acpi_table.dsdt.as_ref().unwrap();

    let aml_handler = Box::new(handler);

    let mut aml_context = aml::AmlContext::new(aml_handler, aml::DebugVerbosity::None);

    let dsdt_data = unsafe {
        core::slice::from_raw_parts(
            (dsdt.address as u64 + physical_memory_offset) as *const u8,
            dsdt.length as usize,
        )
    };

    println!("Parsing DSDT...");

    aml_context
        .parse_table(dsdt_data)
        .expect("Failed to parse DSDT.");

    // println!("Parsing MCFG...");

    println!("Available SDTs:");

    for (k, _) in &acpi_table.sdts {
        println!("- {}", k);
    }

    // let mcfg = unsafe { acpi_table.get_sdt::<acpi::mcfg::Mcfg>(Signature::MCFG) }
    //     .unwrap()
    //     .unwrap();

    // let mcfg_data = unsafe {
    //     core::slice::from_raw_parts(
    //         mcfg.virtual_start().as_ptr() as *const u8,
    //         mcfg.region_length(),
    //     )
    // };

    // aml_context.parse_table(mcfg_data);

    println!("Parsing SSDTs...");

    for (idx, ssdt) in acpi_table.ssdts.iter().enumerate() {
        let ssdt_data = unsafe {
            core::slice::from_raw_parts(
                (ssdt.address as u64 + physical_memory_offset) as *const u8,
                ssdt.length as usize,
            )
        };

        aml_context
            .parse_table(ssdt_data)
            .expect(&alloc::format!("failed to parse SSDT #{idx}"));
    }

    println!(
        "Interrupts: {}",
        x86_64::instructions::interrupts::are_enabled()
    );

    // disable PIC
    // TODO: remap the PIC -> 0x20
    unsafe {
        x86_64::instructions::port::PortWrite::write_to_port(0xa1, 0xffu8);
        x86_64::instructions::port::PortWrite::write_to_port(0x21, 0xffu8);
    };

    x86_64::instructions::interrupts::enable();

    println!(
        "Interrupts: {}",
        x86_64::instructions::interrupts::are_enabled()
    );

    let lapic_addr = apic_info.local_apic_address as u64 + physical_memory_offset;
    unsafe {
        APIC = apic::ApicBase::new(lapic_addr as *mut ());
    };

    let local_apic = unsafe { &mut APIC };

    let mut lapic_msr_addr = (unsafe { x86_64::registers::model_specific::Msr::new(0x1B).read() }
        & 0xFFFFF000)
        + physical_memory_offset;

    { // LOCAL_APIC_TIMER

        // println!("LAPIC CMP\t: {:#0} vs {:#0}", lapic_addr, lapic_msr_addr);

        // println!(
        //     "LAPIC\t\t: #{}, version {}",
        //     local_apic.id().read().id(),
        //     local_apic.version().read().version()
        // );

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

    // println!("AML Traversal:");

    // let mut cpus = alloc::vec![];

    // let mut kbd = None;

    // aml_context.namespace.traverse(|name, level| {
    //     println!("{}: {:?}", name.clone().normalize().unwrap(), level.typ);

    //     // match level.typ {
    //     //     _ => {
    //     //         println!("{:?}", level.values);
    //     //     }
    //     // };

    //     if level.typ == LevelType::Processor {
    //         cpus.push((
    //             name.is_absolute().then_some(name.clone()).unwrap(),
    //             level.values.clone(),
    //         ));
    //     }

    //     if level.typ == LevelType::Device && name.as_string() == "\\_SB_.PCI0.ISA_.KBD_" {
    //         kbd = Some(level.clone());
    //     }

    //     Ok(true)
    // });

    // for (name, cpu) in cpus {
    //     println!("CPU:");

    //     for (k, v) in cpu {
    //         // let value = aml_context
    //         //     .namespace
    //         //     .get(v)
    //         //     .expect("failed to get AML value");

    //         // println!("  {:?}: {:?}", k, value)

    //         if k.as_str() == "_STA" {
    //             let status = aml_context
    //                 .invoke_method(&name, Args::EMPTY)
    //                 .expect("Failed to invoke method");

    //             println!("Processor status: {:?}", status);
    //         }
    //     }
    // }

    // println!("# I/O APIC Information");

    // println!("I/O APICs:");

    // for ioapic in &apic_info.io_apics {
    //     println!(
    //         "- IOAPIC {}: {:#0x} ({})",
    //         ioapic.id, ioapic.address, ioapic.global_system_interrupt_base
    //     );
    // }

    // println!("Interrupt source overrides:");
    // for iso in &apic_info.interrupt_source_overrides {
    //     println!(
    //         "- {} ({}), {:?}/{:?}",
    //         iso.isa_source, iso.global_system_interrupt, iso.polarity, iso.trigger_mode
    //     );
    // }

    // println!("Non-maskable interrupt sources:");

    // for nmi in &apic_info.nmi_sources {
    //     println!(
    //         "- {}, {:?}/{:?}",
    //         nmi.global_system_interrupt, nmi.polarity, nmi.trigger_mode
    //     );
    // }

    // if let Some(kbd) = kbd {
    //     let values = kbd.values;
    //     println!("# ISA Keyboard");

    //     for (k, v) in values {
    //         println!("- {:?}: {:?}", k, aml_context.namespace.get(v));
    //     }
    // } else {
    //     panic!("No keyboard is available. Bailing out.")
    // }

    acpi_aml::init(aml_context);

    let mut ioapic = unsafe {
        IoApicBase::new(
            (apic_info.io_apics.first().unwrap().address as u64 + physical_memory_offset)
                as *mut u8,
        )
    };

    let pci_configuration = IoConfiguration::new();

    // I pretty much just guessed that IRQ 1 on the IOAPIC would be the keyboard since that's the IRQ on the legacy PIC.
    // Who knows what this will do if it isn't?
    let mut rte = ioapic.read_redirection_table_entry(1);

    rte.set_vector(IRQ::Keyboard.as_u8());
    rte.set_masked(false);
    rte.set_polarity_low_active(false);
    rte.set_trigger_mode_level(false);
    rte.set_delivery_mode(DeliveryMode::Fixed);
    rte.set_destination(local_apic.id().read().id());

    ioapic.write_redirection_table_entry(1, rte);

    // TODO: this breaks the tests because handle_keypresses is effectively divergent, but wrapping it in #[cfg(not(test))]
    // makes the IDE unhappy
    let mut executor = Executor::new();
    executor.spawn(Task::new(handle_keypresses()));
    executor.run();

    #[cfg(test)]
    {
        test_main();
    }

    hlt_loop();
}

pub fn waste_time() {
    let mut idx = 0;

    // TODO: this wastes more or less time depending on how fast the CPU is

    while idx < 50000000 {
        idx += 1;
    }
}

pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

pub fn test_runner(tests: &[&dyn Testable]) {
    serial_println!("Running {} tests", tests.len());
    for test in tests {
        test.run();
    }
    exit_qemu(QemuExitCode::Success);
}

pub trait Testable {
    fn run(&self);
}

impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        serial_print!("{}...\t", core::any::type_name::<T>());
        self();
        serial_println!("[ok]");
    }
}

#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    panic!("Out of memory: {:?}", layout);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use fb::CONSOLE;

    CONSOLE.lock().set_color((0x00, 0x00, 0xFF, 0xFF));
    println!("{}", info);
    hlt_loop();
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code: QemuExitCode) -> ! {
    use x86_64::instructions::port::Port;

    unsafe {
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }

    hlt_loop();
}

#[cfg(test)]
mod tests {
    #[test_case]
    fn trivial_assertion() {
        assert_eq!(1, 1);
    }
}
