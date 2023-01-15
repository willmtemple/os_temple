#[allow(unused)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod kvm_inline;

pub mod kvm {
    pub use super::kvm_inline::*;
}
