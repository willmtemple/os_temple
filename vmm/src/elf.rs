use std::ffi::c_void;

use elfloader::*;
use log::info;
use nix::libc::memcpy;

pub struct ExampleLoader {
    memory: *mut c_void,
    vbase: u64,
}

impl ExampleLoader {
    pub fn new(memory: *mut c_void, vbase: u64) -> Self {
        Self { memory, vbase }
    }
}

impl ElfLoader for ExampleLoader {
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
        for header in load_headers {
            info!(
                "allocate base = {:#x} size = {:#x} flags = {}",
                header.virtual_addr(),
                header.mem_size(),
                header.flags()
            );
        }
        Ok(())
    }

    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        use RelocationType::x86_64;

        let addr: *mut u64 = (self.vbase + entry.offset) as *mut u64;

        match entry.rtype {
            x86_64(_) => {
                // TODO: probably need to handle this LOL
                // This type requires addend to be present
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                // This is a relative relocation, add the offset (where we put our
                // binary in the vspace) to the addend and we're done.
                info!("R_RELATIVE *{:p} = {:#x}", addr, self.vbase + addend);
                Ok(())
            }
            _ => Ok((/* not implemented */)),
        }
    }

    fn load(&mut self, flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
        let start = self.vbase + base;
        let end = self.vbase + base + region.len() as u64;
        info!("load region into = {:#x} -- {:#x}", start, end);

        unsafe {
            memcpy(
                self.memory.add(start as usize),
                region.as_ptr() as *const c_void,
                region.len(),
            );
        }

        Ok(())
    }

    fn tls(
        &mut self,
        tdata_start: VAddr,
        _tdata_length: u64,
        total_size: u64,
        _align: u64,
    ) -> Result<(), ElfLoaderErr> {
        let tls_end = tdata_start + total_size;
        info!(
            "Initial TLS region is at = {:#x} -- {:#x}",
            tdata_start, tls_end
        );
        Ok(())
    }
}
