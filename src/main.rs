// #![allow(non_camel_case_types)]
// #![allow(non_snake_case)]
#![allow(dead_code)]
// #![allow(unreachable_code)]
// #![allow(unreachable_patterns)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_must_use)]
pub mod pacman;
pub mod alpm;
extern crate curl;
extern crate env_logger;
extern crate getopts;
extern crate glob;
extern crate libc;
extern crate libarchive;
extern crate humantime;
// extern crate time;
#[macro_use]
extern crate log;
use env_logger::{Builder, Color};
use log::{Level, LevelFilter};
use std::io::Write;
const PACKAGE_VERSION: &str = "0.0.1";
const DEBUG: bool = true;
pub fn main() {
    let mut builder = Builder::new();
    builder.format(|buf, record| {
        let ts = buf.timestamp();
        let level = record.level();
        let mut level_style = buf.style();

        match level {
            Level::Trace => level_style.set_color(Color::Green),
            Level::Debug => level_style.set_color(Color::Blue),
            Level::Info => level_style.set_color(Color::White),
            Level::Warn => level_style.set_color(Color::Yellow),
            Level::Error => level_style.set_color(Color::Red).set_bold(true),
        };

        if DEBUG {
            writeln!(
                buf,
                "{:>5} {}: {}",
                level_style.value(level),
                record.module_path().unwrap_or(""),
                record.args()
            )
        } else {
            writeln!(buf, "{}", level_style.value(record.args()))
        }
    });

    if DEBUG {
        builder.filter(None, LevelFilter::Trace);
    } else {
        builder.filter(None, LevelFilter::Info);
    }
    builder.init();
    pacman::main();
}
