#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]
#![allow(unreachable_code)]
#![allow(unreachable_patterns)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_must_use)]
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
