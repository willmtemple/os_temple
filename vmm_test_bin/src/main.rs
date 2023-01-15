#![no_std]
#![no_main]
#![feature(start)]

use core::panic::PanicInfo;

fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn on_panic(_: &PanicInfo) -> ! {
    hlt_loop()
}

#[no_mangle]
extern "C" fn _start(argc: isize, argv: *const *const isize) -> ! {
    run();

    hlt_loop();
}

fn run() {
    for b in "Hello, world!\n".as_bytes() {
        unsafe { core::arch::asm!("out 0xE9, al", in("al") *b) };
    }

    unsafe {
        *(0x400 as *mut i32) = 1337;
    }

    let x = 0xCAFEBABE_u64;

    unsafe { core::arch::asm!("nop", in("rax") x) };
}
