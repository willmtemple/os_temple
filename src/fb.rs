use bootloader::boot_info::{FrameBuffer, FrameBufferInfo, PixelFormat};

use font8x8::UnicodeFonts;

use spin::Mutex;

static mut FRAMEBUFFER: *mut FrameBuffer = core::ptr::null_mut();
static mut FRAMEBUFFERINFO: FrameBufferInfo = FrameBufferInfo {
    pixel_format: PixelFormat::BGR,
    byte_len: 0,
    horizontal_resolution: 0,
    vertical_resolution: 0,
    bytes_per_pixel: 0,
    stride: 0,
};
static mut INITIALIZED: bool = false;

const SCALE: usize = 2;

pub fn indicate(color: (u8, u8, u8, u8)) {
    let buffer = unsafe { (*FRAMEBUFFER).buffer_mut() };

    buffer[0] = color.0;
    buffer[1] = color.1;
    buffer[2] = color.2;
    buffer[3] = color.3;
}

fn clear() {
    unsafe {
        (*FRAMEBUFFER).buffer_mut().fill(0);
    }
}

unsafe fn write_glyph(glyph: &[u8; 8], pos: (usize, usize), color: (u8, u8, u8, u8), scale: usize) {
    let buffer = (*FRAMEBUFFER).buffer_mut();
    let info = FRAMEBUFFERINFO;

    let x_offset = pos.0 * 8 * scale;

    let mut y_offset = pos.1 * 8 * scale;
    for line in glyph {
        for lc in 0..scale {
            for bit in 0..8 {
                if (*line & (1 << bit)) != 0 {
                    let pixel_offset =
                        (y_offset + lc) * info.horizontal_resolution * info.bytes_per_pixel;
                    let pixel_offset =
                        pixel_offset + ((x_offset + (bit * scale)) * info.bytes_per_pixel);

                    for cc in 0..scale {
                        let pixel_offset = pixel_offset + cc * info.bytes_per_pixel;
                        buffer[pixel_offset] = color.0;
                        buffer[pixel_offset + 1] = color.1;
                        buffer[pixel_offset + 2] = color.2;
                        buffer[pixel_offset + 3] = color.3;
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

pub fn init(fb: &mut FrameBuffer, fbi: FrameBufferInfo) {
    unsafe {
        if !INITIALIZED {
            FRAMEBUFFER = fb;
            FRAMEBUFFERINFO = fbi;
            INITIALIZED = true;

            clear();
        } else {
            panic!("Attempted to initialize framebuffer console twice.")
        }
    }
}

pub struct FbConsole {
    column_position: usize,
    line_position: usize,
    color: (u8, u8, u8, u8),
    scale: usize,
    tab_stop: usize,
}

impl FbConsole {
    pub fn write_char(&mut self, c: char) {
        debug_assert!(unsafe { INITIALIZED });

        match c {
            '\n' => self.new_line(),
            '\r' => {
                self.column_position = 0;
            }
            '\t' => {
                self.column_position =
                    ((self.column_position + self.tab_stop) / self.tab_stop) * self.tab_stop;

                let max_x = unsafe { FRAMEBUFFERINFO }.horizontal_resolution - (8 * self.scale);

                if (self.column_position * 8 * self.scale) > max_x {
                    self.new_line();
                    self.column_position = self.tab_stop;
                }
            }
            _ => {
                if let Some(ref glyph) = font8x8::BASIC_FONTS.get(c) {
                    unsafe {
                        write_glyph(
                            glyph,
                            (self.column_position, self.line_position),
                            self.color,
                            self.scale,
                        )
                    };
                } else {
                    unsafe {
                        write_glyph(
                            &MISSING_GLYPH,
                            (self.column_position, self.line_position),
                            self.color,
                            self.scale,
                        )
                    };
                };

                self.column_position += 1;

                let max_x = unsafe { FRAMEBUFFERINFO }.horizontal_resolution - (8 * self.scale);

                if (self.column_position * 8 * self.scale) > max_x {
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

        let max_y = unsafe { FRAMEBUFFERINFO }.vertical_resolution - (8 * self.scale);

        if (self.line_position * 8 * self.scale) > max_y {
            self.scroll();
            self.line_position -= 1;
        }
    }

    pub fn clear(&mut self) {
        clear();
        self.column_position = 0;
        self.line_position = 0;
    }

    fn scroll(&mut self) {
        unsafe {
            let buffer = (*FRAMEBUFFER).buffer_mut();

            let single_line_length = self.scale
                * 8
                * FRAMEBUFFERINFO.horizontal_resolution
                * FRAMEBUFFERINFO.bytes_per_pixel;

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
}

impl core::fmt::Write for FbConsole {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

lazy_static::lazy_static! {
    pub static ref CONSOLE: Mutex<FbConsole> = Mutex::new(FbConsole {
        column_position: 0,
        line_position: 0,
        color: (0xFF, 0xFF, 0xFF, 0xFF),
        scale:  SCALE,
        tab_stop: 4
    });
}

pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    use x86_64::instructions::interrupts;

    interrupts::without_interrupts(|| {
        CONSOLE.lock().write_fmt(args).unwrap();
    });
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        ($crate::fb::_print(format_args!($($arg)*)));
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
