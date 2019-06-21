#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

mod elf;
mod loader;
mod parser;
mod prog;

pub use loader::{load, Loader};
pub use parser::{parse, Parser};
