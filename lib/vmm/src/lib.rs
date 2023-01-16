#![no_std]
#![feature(decl_macro)]

#[cfg(target_arch = "x86_64")]
#[path = "./x86_64/mod.rs"]
mod arch;

pub use arch::*;
