use log::{info, warn, error, LevelFilter};
use simplelog::{Config, SimpleLogger};

pub fn init_logger() {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .unwrap();
}

pub fn log_example() {
    info!("This is an info message");
    warn!("This is a warning message");
    error!("This is an error message");
}