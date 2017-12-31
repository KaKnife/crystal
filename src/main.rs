#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unreachable_code)]
#![allow(unused_mut)]
#![allow(unused_imports)]
mod pacman;
extern crate libc;
extern crate getopts;
fn main() {
    pacman::main();
}
