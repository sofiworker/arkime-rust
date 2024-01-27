pub trait Log {
    fn debug(fmt: String);
    fn info(fmt: String);
    fn warn(fmt: String);
    fn error(fmt: String);
    fn panic(fmt: String);
}

pub struct LogInstance {}
