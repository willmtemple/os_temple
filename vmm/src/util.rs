#[repr(usize)]
pub enum PageSize {
    Small4KiB = 4 * 1024,
    Large2MiB = 2 * 1024 * 1024,
    Huge1GiB = 1024 * 1024 * 1024,
}

pub const fn round_page(offset: usize, boundary: PageSize) -> usize {
    offset - (offset % (boundary as usize))
}
