#[macro_use]
extern crate cfg_if;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

mod elf;
mod loader;
mod parser;
mod prog;
#[cfg(target_os = "linux")]
mod syscall;

pub use loader::{load, Loader};
pub use parser::{parse, Parser};
