use core::ptr::NonNull;

use virtio_drivers::{
    device::blk::VirtIOBlk,
    transport::mmio::{MmioTransport, VirtIOHeader},
};

use crate::PHYSICAL_MEMORY_OFFSET;

use super::VmmHal;

const VIRTIO_BLK_DEVICE_VADDR: u64 = 0x1000000 + PHYSICAL_MEMORY_OFFSET;

pub fn get_blk_device() -> u64 {
    let blk = VirtIOBlk::<VmmHal, _>::new(unsafe {
        MmioTransport::new(NonNull::new(VIRTIO_BLK_DEVICE_VADDR as *mut VirtIOHeader).unwrap())
            .unwrap()
    })
    .unwrap();

    blk.capacity()
}
