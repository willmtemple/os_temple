use tar_no_std::TarArchiveRef;

const INITRD_BYTES: &'static [u8] = include_bytes!(concat!(env!("OUT_DIR"), "/initrd.tar"));

lazy_static::lazy_static! {
    pub static ref INITRD: TarArchiveRef<'static> = {
        TarArchiveRef::new(INITRD_BYTES)
    };

    pub static ref MOTD: &'static str = {
        core::str::from_utf8(INITRD.entries().find(|e| e.filename().eq("motd.txt")).expect("failed to load motd.txt").data()).expect("MOTD was not valid UTF-8")
    };
}
