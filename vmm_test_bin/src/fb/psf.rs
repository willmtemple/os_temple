use crate::initrd::INITRD;

static BLANK: [u8; 128] = [0; 128];

lazy_static::lazy_static! {
    static ref FONT_BYTES: &'static [u8] = {
        let fontfile = INITRD
            .entries()
            .find(|e| e.filename().eq("lat2-terminus16.psfu"))
            .expect("failed to load default console font file");

        fontfile.data()
    };
}

#[derive(Debug)]
#[repr(C)]
pub struct PsfFont {
    magic: u32,
    version: u32,
    header_size: u32,
    flags: u32,
    num_glyphs: u32,
    bytes_per_glyph: u32,
    pub height: u32,
    pub width: u32,
}

impl PsfFont {
    pub fn ascii_glyph(&self, c: char) -> &'static [u8] {
        if !c.is_ascii() {
            panic!("non-ascii characters not supported")
        }

        let clamped_c = if (0..self.num_glyphs).contains(&(c as u32)) {
            c as u32
        } else {
            0u32
        };

        let off = (self.header_size + self.bytes_per_glyph * clamped_c) as usize;

        unsafe {
            core::slice::from_raw_parts(FONT_BYTES.as_ptr().add(off), self.bytes_per_glyph as usize)
        }
    }

    pub fn blank(&self) -> &'static [u8] {
        &BLANK[..self.bytes_per_glyph as usize]
    }
}

pub fn get_current_font() -> &'static PsfFont {
    unsafe { &*(FONT_BYTES.as_ptr() as *const PsfFont) }
}
