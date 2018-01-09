#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unreachable_code)]
#![allow(unused_mut)]
#![allow(unused_imports)]
pub mod pacman;
pub mod common;
pub mod alpm;
pub use self::common::*;
extern crate libc;
extern crate getopts;
extern crate glob;
const PACKAGE_VERSION:&str = "0.0.1";
fn main() {
    pacman::main();
}
