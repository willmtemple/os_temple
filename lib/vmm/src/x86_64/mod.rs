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

pub fn waste_time() {
    let mut idx = 0;

    // TODO: this wastes more or less time depending on how fast the CPU is

    while idx < 50000000 {
        idx += 1;
    }
}

pub fn hlt() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

pub macro entrypoint($i: ident) {
    #[no_mangle]
    extern "C" fn _start(argc: isize, argv: *const *const isize) -> ! {
        $i();

        $crate::hlt();
    }
}
