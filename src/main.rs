// #![allow(non_camel_case_types)]
// #![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unreachable_code)]
#![allow(unreachable_patterns)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_must_use)]
pub mod pacman;
pub mod alpm;
pub mod consts;
mod package;
mod error;
mod util;
mod db;
mod package_reason;
mod handle;
mod question;
mod trans;
mod signature;
mod dependency;
mod parse;
mod config;
mod conflict;

extern crate curl;
extern crate env_logger;
extern crate getopts;
extern crate glob;
extern crate humantime;
extern crate libarchive;
extern crate libc;
#[macro_use]
extern crate log;
// extern crate time;

use env_logger::{Builder, Color};
use log::{Level, LevelFilter};
use std::io::Write;
use std::result::Result as StdResult;
use consts::DEBUG;
use dependency::{dep_from_string, dep_vercmp, find_dep_satisfier, find_dep_satisfier_ref,
                 find_satisfier};

pub use config::ConfigRepo;
pub use config::Operations;
pub use config::Config;
pub use parse::IniParserFn;
pub type Result<T> = StdResult<T, Error>;
pub use handle::Handle;
pub use db::Database;
pub use db::DbOpsType;
pub use dependency::DepMissing;
pub use dependency::Depmod;
pub use dependency::Dependency;
pub use signature::{SigLevel, SigValidity, SignatureList, SignatureStatus};
pub use trans::{TransState, Transaction, TransactionFlag};
pub use package_reason::PackageReason;
pub use error::Error;
pub use package::{Package, PackageFrom, PackageValidation};
pub use conflict::Conflict;

fn main() {
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
