use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static LOGGER: StdoutLogger = StdoutLogger::new();
static LOGGER_INSTALLED: AtomicBool = AtomicBool::new(false);

pub fn init_logger(level: LevelFilter) -> Result<(), SetLoggerError> {
    LOGGER.set_level(level);

    if LOGGER_INSTALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        if let Err(error) = log::set_logger(&LOGGER) {
            LOGGER_INSTALLED.store(false, Ordering::SeqCst);
            return Err(error);
        }
        log::set_max_level(LevelFilter::Trace);
    }

    Ok(())
}

struct StdoutLogger {
    level: AtomicU8,
}

impl StdoutLogger {
    const fn new() -> Self {
        StdoutLogger {
            level: AtomicU8::new(LevelFilter::Info as u8),
        }
    }

    fn set_level(&self, level: LevelFilter) {
        self.level.store(level as u8, Ordering::Relaxed);
    }

    fn current_level(&self) -> LevelFilter {
        match self.level.load(Ordering::Relaxed) {
            0 => LevelFilter::Off,
            1 => LevelFilter::Error,
            2 => LevelFilter::Warn,
            3 => LevelFilter::Info,
            4 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        }
    }
}

impl log::Log for StdoutLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.current_level()
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let prefix = match record.level() {
            Level::Error => "[ERROR]",
            Level::Warn => "[WARN]",
            Level::Info => "[INFO]",
            Level::Debug => "[DEBUG]",
            Level::Trace => "[TRACE]",
        };

        match record.level() {
            Level::Error | Level::Warn => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "{} {}", prefix, record.args());
            }
            Level::Info | Level::Debug | Level::Trace => {
                let mut stdout = io::stdout().lock();
                let _ = writeln!(stdout, "{} {}", prefix, record.args());
            }
        }
    }

    fn flush(&self) {}
}
