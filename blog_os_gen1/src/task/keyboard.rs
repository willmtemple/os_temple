use core::task::Poll;

use alloc::string::String;
use conquer_once::spin::OnceCell;
use crossbeam_queue::ArrayQueue;
use futures_util::{task::AtomicWaker, Stream, StreamExt};
use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};

use crate::{fb::CONSOLE, print};

static SCANCODE_QUEUE: OnceCell<ArrayQueue<u8>> = OnceCell::uninit();
static WAKER: AtomicWaker = AtomicWaker::new();

const QUEUE_SIZE: usize = 100;

pub(crate) fn add_scancode(scancode: u8) {
    let q = SCANCODE_QUEUE
        .get()
        .expect("PS/2 scancode queue used before initialization");

    if let Err(_) = q.push(scancode) {
        crate::println!("WARNING: dropped keyboard input; scancode queue full");
    } else {
        WAKER.wake();
    }
}

#[non_exhaustive]
pub struct ScancodeStream;

impl ScancodeStream {
    pub fn new() -> Self {
        SCANCODE_QUEUE
            .try_init_once(|| ArrayQueue::new(QUEUE_SIZE))
            .expect("Attempted to initialize scancode queue twice");

        Self
    }
}

impl Stream for ScancodeStream {
    type Item = u8;

    fn poll_next(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Self::Item>> {
        let q = SCANCODE_QUEUE
            .get()
            .expect("PS/2 scancode queue used before initialization");

        if let Ok(sc) = q.pop() {
            return Poll::Ready(Some(sc));
        }

        WAKER.register(&cx.waker());
        match q.pop() {
            Ok(scancode) => {
                WAKER.take();
                Poll::Ready(Some(scancode))
            }
            Err(_) => Poll::Pending,
        }
    }
}

pub struct History<T, const SIZE: usize> {
    front: usize,
    back: usize,
    data: [Option<T>; SIZE],
}

impl<T, const SIZE: usize> History<T, SIZE> {
    pub fn new() -> Self {
        Self {
            front: 0,
            back: 0,
            data: [const { None }; SIZE],
        }
    }

    pub fn push(&mut self, s: T) {
        self.data[self.back] = Some(s);
        self.back = (self.back + 1) % SIZE;

        if self.back == self.front {
            self.front = (self.front + 1) % SIZE;
        }
    }

    pub fn nth(&self, n: usize) -> Option<&T> {
        self.data[(self.front + (SIZE + 1 - n)) % SIZE].as_ref()
    }
}

pub async fn handle_keypresses() {
    let mut scancodes = ScancodeStream::new();
    let mut keyboard = Keyboard::new(layouts::Us104Key, ScancodeSet1, HandleControl::Ignore);

    let mut command_buffer = String::new();

    let mut command_history = History::<String, 64>::new();
    let mut history_cursor = 0;

    let mut stored_entry = None;

    print!("> ");

    while let Some(scancode) = scancodes.next().await {
        match scancode {
            // Backspace
            0xe => {
                if command_buffer.len() > 0 {
                    crate::fb::CONSOLE.lock().delete_backwards();
                    command_buffer.pop();
                }
            }
            // Enter
            0x1c => {
                crate::fb::CONSOLE.lock().new_line();
                let command = command_buffer;
                command_buffer = String::new();

                crate::command::run_command(&command).await;

                command_history.push(command);
                history_cursor = 0;

                print!("> ");
            }
            // arrow up
            0x48 => {
                if let Some(restored) = command_history.nth(history_cursor) {
                    CONSOLE.lock().clear_line();

                    print!("> {}", restored);

                    command_buffer = String::from(restored);

                    history_cursor += 1;
                }
            }
            // arrow down
            0x50 => {
                if history_cursor > 0 {
                    history_cursor -= 1;

                    if history_cursor == 0 && let Some(v) = stored_entry {

                        CONSOLE.lock().clear_line();

                        print!("> {}", v);

                        command_buffer = v;
                        stored_entry = None;
                    } else {
                        let restored = command_history.nth(history_cursor).unwrap();

                        CONSOLE.lock().clear_line();

                        print!("> {}", restored);

                        command_buffer = String::from(restored);
                    }
                }
            }
            _ => {
                if let Ok(Some(kev)) = keyboard.add_byte(scancode) {
                    if let Some(key) = keyboard.process_keyevent(kev) {
                        match key {
                            DecodedKey::Unicode(c) => {
                                crate::print!("{}", c);
                                command_buffer.push(c);
                            }
                            DecodedKey::RawKey(k) => {
                                let s = alloc::format!("{:?}", k);
                                if s.len() == 1 {
                                    let c = s.chars().nth(0).unwrap();
                                    crate::print!("{}", c);
                                    command_buffer.push(c)
                                }
                            }
                        };
                    }
                }
            }
        }
    }
}
