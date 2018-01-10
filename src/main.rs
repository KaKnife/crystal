#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unreachable_code)]
#![allow(unused_imports)]
pub mod pacman;
pub mod common;
pub mod alpm;
pub use self::common::*;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate libc;
extern crate getopts;
extern crate glob;
const PACKAGE_VERSION:&str = "0.0.1";
fn main() {
    std::env::set_var("RUST_LOG","debug");
    env_logger::init().unwrap();
    pacman::main();
}
