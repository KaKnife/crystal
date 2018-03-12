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
mod package;
mod error;
mod util;
mod db;
mod package_reason;
mod handle;

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

pub use handle::Handle;
pub use package_reason::PackageReason;
pub use db::Database;
pub use db::DbOpsType;
pub use error::Error;
pub use package::Package;
pub type Result<T> = StdResult<T, Error>;

const PACKAGE_VERSION: &str = "0.0.1";
const DEBUG: bool = true;
const CONFFILE: &str = "/etc/pacman.conf";
const ROOTDIR: &str = "/";
const DBPATH: &str = "/var/lib/pacman/";
const LOGFILE: &str = "/var/log/crystal.log";
const CACHEDIR: &str = "/var/cache/pacman/pkg/";
const GPGDIR: &str = "/etc/pacman.d/gnupg/";
const HOOKDIR: &str = "/etc/pacman.d/hooks/";
const SYSHOOKDIR: &str = "/usr/local/share/libalpm/hooks/";
const ALPM_LOCAL_DB_VERSION: usize = 9;
/// Database entries
const INFRQ_BASE: i32 = (1 << 0);
const INFRQ_DESC: i32 = (1 << 1);
const INFRQ_FILES: i32 = (1 << 2);
const INFRQ_SCRIPTLET: i32 = (1 << 3);
const INFRQ_DSIZE: i32 = (1 << 4);
/// ALL should be info stored in the package or database
const INFRQ_ALL: i32 = INFRQ_BASE | INFRQ_DESC | INFRQ_FILES | INFRQ_SCRIPTLET | INFRQ_DSIZE;
const INFRQ_ERROR: i32 = (1 << 30);

#[cfg(target_arch = "x86_64")]
const OS_ARCH: &str = "x86_64";

#[cfg(target_arch = "x86")]
const OS_ARCH: &str = "x86";

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
