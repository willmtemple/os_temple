#![no_std]
#![feature(decl_macro)]

#[cfg(target_arch = "x86_64")]
#[path = "./x86_64/mod.rs"]
mod arch;

pub use arch::*;

#[repr(C)]
pub struct Aligned<Align, T: ?Sized> {
    _align: [Align; 0],
    data: T,
}

pub macro include_bytes_aligned($align:ty, $path:literal) {{
    static _ALIGNED: &'static $crate::Aligned<$align, [u8]> = &$crate::Aligned {
        _align: [],
        data: *include_bytes!($path),
    };

    &_ALIGNED.data
}}
