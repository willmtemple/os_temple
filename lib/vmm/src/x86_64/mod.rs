#[repr(u32)]
pub enum ExitCode {
    Success = 0,
    Failed = 1,
}

pub fn exit(exit_code: ExitCode) -> ! {
    use x86_64::instructions::port::Port;

    unsafe {
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }

    hlt();
}

pub fn hlt() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

pub macro entrypoint($i: ident) {
    #[no_mangle]
    extern "C" fn _start(argc: isize, argv: *const *const isize) -> ! {
        // unsafe { x86_64::instructions::port::PortWrite::write_to_port(0x0, 123u8) };
        $i();

        $crate::hlt();
    }
}
