use std::{io, ops};
use tracing_subscriber::fmt::MakeWriter;

// This type may be moved out of `kanidmd` later
#[derive(Default)]
pub struct LogBuffer {
    buf: Vec<u8>,
}

// An "owned" type pointing to a buffer in a
// `LogBuffer`. This type exists to satisfy the
// `MakeWriter` trait restriction on `make_writer`,
// which must return an owned `io::Write` object.
// The benefit of using a raw ptr is that creating this
// object of very cheap and fast, and unless `Subscriber`s
// are opening a new thread of each log (I don't think they are),
// this will never cross a thread boundry.
pub struct LogBufferWriter(*mut Vec<u8>);

impl ops::Drop for LogBuffer {
    fn drop(&mut self) {
        // logs are written to stderr when dropped
        use io::Write;
        #[allow(clippy::expect_used)]
        io::stderr()
            .write_all(&self.buf)
            .expect("Failed to write logs")
    }
}

impl MakeWriter for LogBuffer {
    type Writer = LogBufferWriter;

    fn make_writer(&self) -> Self::Writer {
        LogBufferWriter(&self.buf as *const _ as *mut _)
    }
}

impl LogBufferWriter {
    fn get_buffer(&mut self) -> &mut Vec<u8> {
        // SAFETY:
        //
        // `LogBufferWriter`s are logical references to a
        // `LogBuffer`, which is held for the entire duration
        // of a `Subscriber`. A `LogBufferWriter` is only held
        // for the duration of a `write` call, which is shorter
        // than the lifetime of the `Subscriber` that created it.
        // Therefore, the data behind the ptr will always be safe.
        //
        // I think this is concurrency safe, because I'm pretty sure
        // `Subscriber`s aren't sending each log to a new thread.
        unsafe { &mut *self.0 }
    }
}

impl io::Write for LogBufferWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.get_buffer().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.get_buffer().flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.get_buffer().write_all(buf)
    }
}
