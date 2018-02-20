#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unreachable_code)]
pub mod pacman;
pub mod common;
pub mod alpm;
pub use self::common::*;
extern crate env_logger;
extern crate getopts;
extern crate glob;
extern crate libc;
extern crate time;
#[macro_use]
extern crate log;
const PACKAGE_VERSION: &str = "0.0.1";
fn main() {
    // std::env::set_var("RUST_LOG", "debug");
    // std::env::set_var("RUST_LOG", "error");
    env_logger::init().unwrap();
    pacman::main();
}
