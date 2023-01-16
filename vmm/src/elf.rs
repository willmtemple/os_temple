use std::ffi::c_void;

use elfloader::*;
use log::{debug, info, warn};
use nix::libc::memcpy;

pub struct BasicLoader {
    memory: *mut c_void,
    vbase: u64,
}

impl BasicLoader {
    pub fn new(memory: *mut c_void, vbase: u64) -> Self {
        Self { memory, vbase }
    }
}

impl ElfLoader for BasicLoader {
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
        for header in load_headers {
            // TODO: actually allocate memory for these and set the appropriate paging flags. Currently the memory layout
            // is completely static.
            info!(
                "unimplemented/static allocate base = {:#x} size = {:#x} flags = {}",
                header.virtual_addr(),
                header.mem_size(),
                header.flags()
            );
        }
        Ok(())
    }

    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        use RelocationType::x86_64;

        // The base address of the relocation needs to include the virt base, as we alloc'd and loaded the ELF sections
        // using that offset already.
        let relocation_address = self.vbase + entry.offset;

        match entry.rtype {
            x86_64(_) => {
                // This type requires addend to be present
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                // We handle the relative relocation by simply setting *(MEMORY + relocation_addr)
                unsafe {
                    *(self.memory.add(relocation_address as usize) as *mut u64) =
                        self.vbase + addend
                };

                // We handle the relative relocation by simply
                debug!(
                    "R_RELATIVE *{:#x} = {:#x}",
                    relocation_address,
                    self.vbase + addend
                );

                Ok(())
            }
            _ => {
                warn!(
                    "relo unimplemented rtype {:?} idx={}, off={}, addend={:?}",
                    entry.rtype, entry.index, entry.offset, entry.addend
                );
                Ok((/* not implemented */))
            }
        }
    }

    fn load(&mut self, _flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
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
        warn!(
            "[unimplemented] initial TLS region is at = {:#x} -- {:#x}",
            tdata_start, tls_end
        );
        Ok(())
    }
}
