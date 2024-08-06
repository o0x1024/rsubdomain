// use colored::*;
// use log::{Level, LevelFilter, Metadata, Record};
// use std::sync::Mutex;
// use std::fmt;

// pub struct Logger {
//     use_colors: bool,
//     max_level: Level,
//     labels: std::collections::HashMap<Level, &'static str>,
//     mutex: Mutex<()>,
// }

// impl Logger {
//     pub fn new() -> Self {
//         let mut labels = std::collections::HashMap::new();
//         labels.insert(Level::Error, "Error");
//         labels.insert(Level::Warn, "Warning");
//         labels.insert(Level::Info, "INFO");
//         labels.insert(Level::Debug, "DEBUG");
//         labels.insert(Level::Trace, "TRACE");

//         Logger {
//             use_colors: true,
//             max_level: Level::Info,
//             labels,
//             mutex: Mutex::new(()),
//         }
//     }

//     fn wrap(&self, label: &str, level: Level) -> String {
//         if !self.use_colors {
//             return label.to_string();
//         }

//         match level {
//             Level::Error => label.red().to_string(),
//             Level::Warn => label.yellow().to_string(),
//             Level::Info => label.blue().to_string(),
//             Level::Debug => label.magenta().to_string(),
//             Level::Trace => label.normal().to_string(),
//         }
//     }

//     fn get_label(&self, level: Level, sb: &mut fmt::Formatter) -> fmt::Result {
//         if level > self.max_level {
//             return Ok(());
//         }

//         if let Some(label) = self.labels.get(&level) {
//             write!(sb, "[{}] ", self.wrap(label, level))
//         } else {
//             Ok(())
//         }
//     }

//     pub fn log(&self, level: Level, format: &str, args: fmt::Arguments) {
//         if level > self.max_level {
//             return;
//         }

//         let _guard = self.mutex.lock().unwrap();
//         let mut sb = String::new();

//         let _ = self.get_label(level, &mut sb);
//         sb.push_str(&format!("{}", args));

//         println!("{}", sb);
//     }
// }

// impl log::Log for Logger {
//     fn enabled(&self, metadata: &Metadata) -> bool {
//         metadata.level() <= self.max_level
//     }

//     fn log(&self, record: &Record) {
//         self.log(record.level(), record.args().as_str(), record.args())
//     }

//     fn flush(&self) {}
// }

// pub fn init_logger() {
//     let logger = Logger::new();
//     log::set_boxed_logger(Box::new(logger)).unwrap();
//     log::set_max_level(LevelFilter::Trace);
// }

// pub fn infof(format: &str, args: fmt::Arguments) {
//     log::info!("{}", format, args);
// }

// pub fn warningf(format: &str, args: fmt::Arguments) {
//     log::warn!("{}", format, args);
// }

// pub fn errorf(format: &str, args: fmt::Arguments) {
//     log::error!("{}", format, args);
// }

// pub fn debugf(format: &str, args: fmt::Arguments) {
//     log::debug!("{}", format, args);
// }

// pub fn verbosef(format: &str, args: fmt::Arguments) {
//     log::trace!("{}", format, args);
// }

// pub fn fatalf(format: &str, args: fmt::Arguments) {
//     log::error!("{}", format, args);
//     std::process::exit(1);
// }

// pub fn printf(format: &str, args: fmt::Arguments) {
//     print!("{}", format, args);
// }

// pub fn labelf(format: &str, args: fmt::Arguments) {
//     print!("{}", format, args);
// }
