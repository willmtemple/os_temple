use spin::Mutex;

use crate::{fb::psf::get_current_font, PHYSICAL_MEMORY_OFFSET};

use super::psf::PsfFont;

pub struct FrameBufferInfo {
    // pixel_format: B8G8R8A8 (unorm)
    byte_len: usize,
    horizontal_resolution: u32,
    vertical_resolution: u32,
    bytes_per_pixel: u32,
    stride: usize,
}

// const FRAMEBUFFER: &'static mut [u8] =
//     unsafe { core::slice::from_raw_parts_mut((0x3 << 20) as *mut u8, 1920 * 1080 * 4) };

const FRAMEBUFFERINFO: FrameBufferInfo = FrameBufferInfo {
    byte_len: 1920 * 1080 * 4,
    horizontal_resolution: 1920,
    vertical_resolution: 1080,
    bytes_per_pixel: 4,
    stride: 1080 * 4,
};
// static mut INITIALIZED: bool = false;

const SCALE: u32 = 1;

// pub fn indicate(buffer: &mut [u8], color: (u8, u8, u8, u8)) {
//     buffer[0] = color.0;
//     buffer[1] = color.1;
//     buffer[2] = color.2;
//     buffer[3] = color.3;
// }

fn clear(buffer: &mut [u8]) {
    buffer.fill(0);
}

unsafe fn write_glyph(
    buffer: &mut [u8],
    font: &PsfFont,
    glyph: &[u8],
    pos: (u32, u32),
    color: (u8, u8, u8, u8),
    scale: u32,
) {
    let info = FRAMEBUFFERINFO;

    let x_offset = pos.0 * font.width * scale;

    let mut y_offset = pos.1 * font.height * scale;
    for line_idx in 0..font.height {
        let line = glyph[(line_idx * (font.width / 8)) as usize];
        for lc in 0..scale {
            for bit in 0..font.width {
                let pixel_offset =
                    (y_offset + lc) * info.horizontal_resolution * info.bytes_per_pixel;
                let pixel_offset =
                    pixel_offset + ((x_offset + (bit * scale)) * info.bytes_per_pixel);

                if (line & (0b10000000 >> bit)) != 0 {
                    for cc in 0..scale {
                        let pixel_offset = (pixel_offset + cc * info.bytes_per_pixel) as usize;
                        buffer[pixel_offset] = color.0;
                        buffer[pixel_offset + 1] = color.1;
                        buffer[pixel_offset + 2] = color.2;
                        buffer[pixel_offset + 3] = color.3;
                    }
                } else {
                    for cc in 0..scale {
                        let pixel_offset = (pixel_offset + cc * info.bytes_per_pixel) as usize;
                        buffer[pixel_offset] = 0;
                        buffer[pixel_offset + 1] = 0;
                        buffer[pixel_offset + 2] = 0;
                        buffer[pixel_offset + 3] = 0;
                    }
                }
            }
        }
        y_offset += scale;
    }
}

#[rustfmt::skip]
const MISSING_GLYPH: [u8; 8] = [
    0b01010101,
    0b10000000,
    0b00000001,
    0b10000000,
    0b00000001,
    0b10000000,
    0b00000001,
    0b10101010,
];

pub struct FbConsole {
    font: &'static PsfFont,
    column_position: u32,
    line_position: u32,
    color: (u8, u8, u8, u8),
    scale: u32,
    tab_stop: u32,
}

impl FbConsole {
    pub fn write_char(&mut self, c: char) {
        // debug_assert!(unsafe { INITIALIZED });

        match c {
            '\n' => self.new_line(),
            '\r' => {
                self.column_position = 0;
            }
            '\t' => {
                self.column_position =
                    ((self.column_position + self.tab_stop) / self.tab_stop) * self.tab_stop;

                let max_x = unsafe { FRAMEBUFFERINFO }.horizontal_resolution
                    - (self.font.width * self.scale);

                if (self.column_position * self.font.width * self.scale) > max_x {
                    self.new_line();
                    self.column_position = self.tab_stop;
                }
            }
            _ => {
                unsafe {
                    write_glyph(
                        self.buffer(),
                        self.font,
                        self.font.ascii_glyph(c),
                        (self.column_position, self.line_position),
                        self.color,
                        self.scale,
                    )
                }

                self.column_position += 1;

                let max_x = unsafe { FRAMEBUFFERINFO }.horizontal_resolution
                    - (self.font.width * self.scale);

                if (self.column_position as u32 * self.font.width * self.scale) > max_x {
                    self.new_line()
                }
            }
        }
    }

    pub fn write_string(&mut self, message: &str) {
        for c in message.chars() {
            self.write_char(c);
        }
    }

    pub fn write_line(&mut self, message: &str) {
        self.write_string(message);
        self.new_line();
    }

    pub fn new_line(&mut self) {
        self.line_position += 1;
        self.column_position = 0;

        let max_y =
            unsafe { FRAMEBUFFERINFO }.vertical_resolution - (self.font.height * self.scale);

        if (self.line_position as u32 * self.font.height * self.scale) > max_y {
            self.scroll();
            self.line_position -= 1;
        }
    }

    pub fn clear(&mut self) {
        clear(self.buffer());
        self.column_position = 0;
        self.line_position = 0;
    }

    pub fn clear_line(&mut self) {
        self.column_position = 0;
        let line_length = FRAMEBUFFERINFO.horizontal_resolution / (self.font.width * self.scale);
        for idx in 0..line_length {
            unsafe {
                write_glyph(
                    self.buffer(),
                    self.font,
                    self.font.blank(),
                    (idx, self.line_position),
                    self.color,
                    self.scale,
                );
            }
        }
    }

    fn scroll(&mut self) {
        unsafe {
            let buffer = self.buffer();

            let single_line_length = (self.scale
                * self.font.height
                * FRAMEBUFFERINFO.horizontal_resolution
                * FRAMEBUFFERINFO.bytes_per_pixel) as usize;

            let source = &buffer[single_line_length..];
            let len = source.len();
            core::ptr::copy(source.as_ptr(), buffer.as_mut_ptr(), len);

            let len = buffer.len();
            buffer[len - single_line_length..].fill(0x00);
        }
    }

    pub fn set_color(&mut self, color: (u8, u8, u8, u8)) {
        self.color = color;
    }

    pub fn delete_backwards(&mut self) {
        if self.column_position > 0 {
            self.column_position -= 1;
            unsafe {
                write_glyph(
                    self.buffer(),
                    self.font,
                    self.font.blank(),
                    (self.column_position, self.line_position),
                    self.color,
                    self.scale,
                )
            };
        }
    }

    fn buffer(&self) -> &'static mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                (PHYSICAL_MEMORY_OFFSET + (0x3 << 20)) as *mut u8,
                1920 * 1080 * 4,
            )
        }
    }
}

impl core::fmt::Write for FbConsole {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

lazy_static::lazy_static! {
    pub static ref CONSOLE: Mutex<FbConsole> = {
        let console = FbConsole {
            font: get_current_font(),
            column_position: 0,
            line_position: 0,
            color: (0xFF, 0xFF, 0xFF, 0xFF),
            scale:  SCALE,
            tab_stop: 4
        };

        clear(console.buffer());

        Mutex::new(console)
    };
}

pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    use x86_64::instructions::interrupts;

    interrupts::without_interrupts(|| {
        CONSOLE.lock().write_fmt(args).unwrap();
    });
}

#[macro_export]
pub macro print {
    ($($arg:tt)*) => {
        ($crate::fb::console::_print(format_args!($($arg)*)))
    },
}

pub macro println {
    () => ($crate::print!("\n")),
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*))),
}
