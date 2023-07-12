use elfloader::*;
use log::{debug, info, warn};

use crate::hal::VirtualMachine;

pub struct BasicLoader {
    memory: *mut u8,
    pbase: u64,
    vbase: u64,
}

impl BasicLoader {
    pub fn new<Vm: VirtualMachine>(memory: *mut u8) -> Self {
        Self {
            memory,
            pbase: Vm::KERN_PHYS_OFFSET.as_u64(),
            vbase: Vm::KERN_PHYS_OFFSET.as_u64() + Vm::VIRTUAL_2GIB_PBASE_OFFSET.as_u64(),
        }
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
        let relocation_address = self.pbase + entry.offset;

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
                    "relo/relative: *{:#x} = {:#x}",
                    relocation_address,
                    self.vbase + addend
                );

                Ok(())
            }
            _ => {
                warn!(
                    "unimplemented rtype {:?} idx={}, off={}, addend={:?}",
                    entry.rtype, entry.index, entry.offset, entry.addend
                );
                Ok((/* not implemented */))
            }
        }
    }

    fn load(&mut self, _flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
        let start = self.pbase + base;
        let end = self.pbase + base + region.len() as u64;
        info!("load region into = {:#x} -- {:#x}", start, end);

        unsafe {
            core::slice::from_raw_parts_mut(
                self.memory.add(start as usize) as *mut u8,
                region.len(),
            )
            .copy_from_slice(region);
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
