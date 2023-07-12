// Extremely simple console print module. In the VMM we just echo all bytes written to IO 0xE9 to the VMM's output pipe,
// so we don't need to mess with any weird serial protocols. We just write bytes.

use core::fmt::Write;
// use spin::{Lazy, Mutex};

#[derive(Clone, Copy)]
struct BasicWritePort(pub u16);

lazy_static::lazy_static! {
    static ref IOBASIC: BasicWritePort = {
        BasicWritePort(0xE9)
    };
}

// Teach BasicWritePort how to print a string.
impl Write for BasicWritePort {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            unsafe { core::arch::asm!("out dx, al", in("dx") self.0, in("al") b) };
        }

        Ok(())
    }
}

#[doc(hidden)]
pub fn _print(args: ::core::fmt::Arguments) {
    use x86_64::instructions::interrupts;

    interrupts::without_interrupts(|| {
        IOBASIC
            .clone()
            .write_fmt(args)
            .expect("Printing to iobasic failed");
    });
}

/// Prints to the host through the iobasic interface.
pub macro iobasic_print {
    ($($arg:tt)*) => {
        $crate::iobasic::_print(format_args!($($arg)*));
    }
}

/// Prints to the host through the iobasic interface, appending a newline.
pub macro iobasic_println {
    () => ($crate::iobasic_print!("\n")),
    ($fmt:expr) => ($crate::iobasic::iobasic_print!(concat!($fmt, "\n"))),
    ($fmt:expr, $($arg:tt)*) => ($crate::iobasic::iobasic_print!(
        concat!($fmt, "\n"), $($arg)*)),
}
