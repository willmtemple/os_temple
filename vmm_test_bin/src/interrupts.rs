use crate::{fb::CONSOLE, println /*task::keyboard::add_scancode*/};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum IRQ {
    Timer = 0x20,
    Keyboard = 0x21,
    Magic = 34,
    Spurious = 255,
}

impl IRQ {
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub const fn as_usize(self) -> usize {
        self as usize
    }
}

macro_rules! set_handler {
    ($idt: expr, $i: ident) => {
        $idt.$i.set_handler_fn(paste::paste! { [<$i _handler>] });
    };
}

macro_rules! define_handler {
    ($i: ident) => {
        paste::paste! {
            extern "x86-interrupt" fn [<$i _handler>](stack_frame: InterruptStackFrame) {
                CONSOLE.lock().set_color((0x00, 0xFF, 0xFF, 0xFF));

                $crate::println!("EXCEPTION ({}): {:?}", stringify!($i), stack_frame);

                ::libvmm::hlt();
            }
        }
    };
    ($i: ident, true) => {
        paste::paste! {
            extern "x86-interrupt" fn [<$i _handler>](stack_frame: InterruptStackFrame, error_code: u64) {
                CONSOLE.lock().set_color((0x1F, 0x5F, 0xFF, 0xFF));

                $crate::println!("EXCEPTION: {}", stringify!($i).to_ascii_uppercase());
                $crate::println!("Error Code: {:?}", error_code);
                $crate::println!("{:#?}", stack_frame);

                ::libvmm::hlt();
            }
        }
    };
}

define_handler!(divide_error);
define_handler!(debug);
define_handler!(non_maskable_interrupt);
define_handler!(overflow);
define_handler!(bound_range_exceeded);
define_handler!(invalid_opcode);
define_handler!(device_not_available);
define_handler!(invalid_tss, true);
define_handler!(segment_not_present, true);
define_handler!(stack_segment_fault, true);
define_handler!(general_protection_fault, true);
define_handler!(x87_floating_point);
define_handler!(alignment_check, true);
define_handler!(machine_check);
define_handler!(simd_floating_point);
define_handler!(virtualization);
define_handler!(vmm_communication_exception, true);
define_handler!(security_exception, true);

lazy_static::lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        unsafe { idt.double_fault.set_handler_fn(double_fault).set_stack_index(crate::gdt::DOUBLE_FAULT_IST_INDEX) };
        idt.page_fault.set_handler_fn(page_fault);

        set_handler!(idt, divide_error);
        set_handler!(idt, debug);
        set_handler!(idt, non_maskable_interrupt);
        set_handler!(idt, overflow);
        set_handler!(idt, bound_range_exceeded);
        set_handler!(idt, invalid_opcode);
        set_handler!(idt, device_not_available);
        set_handler!(idt, invalid_tss);
        set_handler!(idt, segment_not_present);
        set_handler!(idt, stack_segment_fault);
        set_handler!(idt, general_protection_fault);
        set_handler!(idt, x87_floating_point);
        set_handler!(idt, alignment_check);
        set_handler!(idt, simd_floating_point);
        set_handler!(idt, virtualization);
        set_handler!(idt, vmm_communication_exception);
        set_handler!(idt, security_exception);

        idt.machine_check.set_handler_fn(machine_check);

        //for idx in 0x20..0xFF {
        //    idt[idx].set_handler_fn(spurious_handler);
        //}

        // idt[IRQ::Timer.as_usize()].set_handler_fn(irq0_handler);
        // idt[IRQ::Keyboard.as_usize()].set_handler_fn(keyboard_handler);
        idt[IRQ::Magic.as_usize()].set_handler_fn(magic_irq_handler);
        idt[IRQ::Spurious.as_usize()].set_handler_fn(spurious_handler);

        idt
    };
}

pub fn init_idt() {
    IDT.load();
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault(stack_frame: InterruptStackFrame, code: u64) -> ! {
    // crate::fb::indicate((0, 0, 0xFF, 0xFF));

    panic!("EXCEPTION: DOUBLE FAULT {}\n{:#?}", code, stack_frame);
}

extern "x86-interrupt" fn page_fault(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    CONSOLE.lock().set_color((0x1F, 0x5F, 0xFF, 0xFF));

    println!("EXCEPTION: PAGE FAULT");
    println!("Accessed Address: {:?}", Cr2::read());
    println!("Error Code: {:?}", error_code);
    println!("{:#?}", stack_frame);

    libvmm::hlt();
}

extern "x86-interrupt" fn machine_check(stack_frame: InterruptStackFrame) -> ! {
    CONSOLE.lock().set_color((0x1F, 0x5F, 0xFF, 0xFF));

    println!("EXCEPTION: MACHINE CHECK");
    println!("{:#?}", stack_frame);

    libvmm::hlt();
}

extern "x86-interrupt" fn magic_irq_handler(stack_frame: InterruptStackFrame) {
    println!("Interrupts are working :)");
    panic!();
}
extern "x86-interrupt" fn spurious_handler(stack_frame: InterruptStackFrame) {
    panic!("Spurious interrupt: {:?}", stack_frame);
}

// extern "x86-interrupt" fn irq0_handler(stack_frame: InterruptStackFrame) {
//     print!(".");

//     unsafe { &crate::APIC }.end_of_interrupt().signal();
// }

// extern "x86-interrupt" fn keyboard_handler(stack_frame: InterruptStackFrame) {
//     use x86_64::instructions::port::Port;

//     // PS/2 port
//     let mut port = Port::new(0x60);
//     let scancode: u8 = unsafe { port.read() };

//     add_scancode(scancode);

//     unsafe { &crate::APIC }.end_of_interrupt().signal();
// }
