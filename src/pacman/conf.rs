// use pacman::alpm::*;
// use pacman::cleanup;
// use getopts;
use super::*;
#[cfg(target_os = "linux")]
const CONFFILE: &str = "/etc/pacman.conf";
const ROOTDIR: &str = "/";
const DBPATH: &str = "/var/lib/pacman/";
const LOGFILE: &str = "/var/log/crystal.log";
const CACHEDIR: &str = "/var/cache/pacman/pkg/";
const GPGDIR: &str = "/etc/pacman.d/gnupg/";
const HOOKDIR: &str = "/etc/pacman.d/hooks/";

#[cfg(target_arch = "x86_64")]
const OS_ARCH: &str = "x86_64";

#[cfg(target_arch = "x86")]
const OS_ARCH: &str = "x86";
/*
 *  conf.h
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  conf.c
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// #ifndef PM_CONF_H
// #define PM_CONF_H
//
// #include <alpm.h>
// #include <errno.h>
// #include <limits.h>
// #include <locale.h> /* setlocale */
// #include <fcntl.h> /* open */
// #include <glob.h>
// #include <stdlib.h>
// #include <stdio.h>
// #include <string.h> /* strdup */
// #include <sys/stat.h>
// #include <sys/types.h>
// #include <sys/utsname.h> /* uname */
// #include <unistd.h>
//
// /* pacman */
// #include "conf.h"
// #include "ini.h"
// #include "util.h"
// #include "pacman.h"
// #include "callback.h"

#[derive(Default, Debug)]
pub struct ColStr {
    pub colon: String,
    pub title: String,
    pub repo: String,
    pub version: String,
    pub groups: String,
    pub meta: String,
    pub warn: String,
    pub err: String,
    pub nocolor: String,
}

#[derive(Default, Debug, Clone)]
pub struct ConfigRepo {
    name: String,
    servers: Vec<String>,
    usage: DatabaseUsage,
    siglevel: SigLevel,
    siglevel_mask: SigLevel,
}

#[derive(Default, Debug)]
pub struct Config {
    pub op: Option<Operations>,
    pub quiet: bool,
    pub verbose: u8,
    pub version: bool,
    pub help: bool,
    pub noconfirm: bool,
    pub noprogressbar: u8,
    pub logmask: alpm::LogLevel,
    pub print: bool,
    pub checkspace: u8,
    pub usesyslog: u8,
    pub color: u8,
    pub disable_dl_timeout: u8,
    pub deltaratio: f64,
    pub arch: String,
    pub print_format: String,
    /* unfortunately, we have to keep track of paths both here and in the library
     * because they can come from both the command line or config file, and we
     * need to ensure we get the order of preference right. */
    pub configfile: String,
    pub rootdir: String,
    pub dbpath: String,
    pub logfile: String,
    pub gpgdir: String,
    pub sysroot: String,
    pub hookdirs: Vec<String>,
    pub cachedirs: Vec<String>,

    pub op_q_isfile: u8,
    pub op_q_info: u8,
    pub op_q_list: u8,
    pub op_q_unrequired: u8,
    pub op_q_deps: u8,
    pub op_q_explicit: u8,
    pub op_q_owns: u8,
    pub op_q_search: u8,
    pub op_q_changelog: u8,
    pub op_q_upgrade: u8,
    pub op_q_check: u8,
    pub op_q_locality: u8,

    pub op_s_clean: u8,
    pub op_s_downloadonly: u8,
    pub op_s_info: u8,
    pub op_s_sync: u8,
    pub op_s_search: u8,
    pub op_s_upgrade: u8,

    pub op_f_regex: u8,
    pub op_f_machinereadable: u8,

    pub group: u8,
    pub noask: bool,
    pub ask: u64,
    pub flags: alpm::TransactionFlag,
    pub siglevel: SigLevel,
    pub localfilesiglevel: SigLevel,
    pub remotefilesiglevel: SigLevel,

    pub siglevel_mask: SigLevel,
    pub localfilesiglevel_mask: SigLevel,
    pub remotefilesiglevel_mask: SigLevel,

    /* conf file options */
    /* I Love Candy! */
    pub chomp: u8,
    pub verbosepkglists: u8,
    /* When downloading, display the amount downloaded, rate, ETA, and percent
     * downloaded of the total download list */
    pub totaldownload: u8,
    pub cleanmethod: CleanMethod,
    pub holdpkg: Vec<String>,
    pub ignorepkg: Vec<String>,
    pub ignoregrp: Vec<String>,
    pub assumeinstalled: Vec<String>,
    pub noupgrade: Vec<String>,
    pub noextract: Vec<String>,
    pub overwrite_files: Vec<String>, //Not sure this should be a string
    pub xfercommand: String,

    /* our connection to libalpm */
    // pub handle: Handle,
    pub explicit_adds: Vec<Package>,
    pub explicit_removes: Vec<Package>,

    /* Color strings for output */
    pub colstr: ColStr,
    pub repos: Vec<ConfigRepo>,
}

/* Operations */
#[derive(Debug)]
pub enum Operations {
    MAIN = 1,
    REMOVE,
    UPGRADE,
    QUERY,
    SYNC,
    DEPTEST,
    Database,
    FILES,
}

/// clean method
#[derive(Debug, Default)]
pub struct CleanMethod {
    keepinst: bool,
    keepcur: bool,
}

/** package locality */

pub static PKG_LOCALITY_UNSET: u8 = 0;
pub static PKG_LOCALITY_NATIVE: u8 = (1 << 0);
pub static PKG_LOCALITY_FOREIGN: u8 = (1 << 1);

// enum {
// 	PM_COLOR_UNSET = 0,
// 	PM_COLOR_OFF,
// 	PM_COLOR_ON
// };

fn invalid_opt(used: bool, opt1: &str, opt2: &str) {
    if used {
        eprintln!(
            "invalid option: '{}' and '{}' may not be used together",
            opt1, opt2
        );
        cleanup(1);
    }
}

// #define NOCOLOR       "\033[0m"
// #define BOLD          "\033[0;1m"
// #define BLACK         "\033[0;30m"
// #define RED           "\033[0;31m"
// #define GREEN         "\033[0;32m"
// #define YELLOW        "\033[0;33m"
// #define BLUE          "\033[0;34m"
// #define MAGENTA       "\033[0;35m"
// #define CYAN          "\033[0;36m"
// #define WHITE         "\033[0;37m"
// #define BOLDBLACK     "\033[1;30m"
// #define BOLDRED       "\033[1;31m"
// #define BOLDGREEN     "\033[1;32m"
// #define BOLDYELLOW    "\033[1;33m"
// #define BOLDBLUE      "\033[1;34m"
// #define BOLDMAGENTA   "\033[1;35m"
// #define BOLDCYAN      "\033[1;36m"
// #define BOLDWHITE     "\033[1;37m"

// void enable_colors(int colors)
// {
// 	colstr_t *colstr = &config.colstr;
//
// 	if(colors == PM_COLOR_ON) {
// 		colstr.colon   = BOLDBLUE "::" BOLD " ";
// 		colstr.title   = BOLD;
// 		colstr.repo    = BOLDMAGENTA;
// 		colstr.version = BOLDGREEN;
// 		colstr.groups  = BOLDBLUE;
// 		colstr.meta    = BOLDCYAN;
// 		colstr.warn    = BOLDYELLOW;
// 		colstr.err     = BOLDRED;
// 		colstr.nocolor = NOCOLOR;
// 	} else {
// 		colstr.colon   = ":: ";
// 		colstr.title   = "";
// 		colstr.repo    = "";
// 		colstr.version = "";
// 		colstr.groups  = "";
// 		colstr.meta    = "";
// 		colstr.warn    = "";
// 		colstr.err     = "";
// 		colstr.nocolor = "";
// 	}
// }

impl Config {
    pub fn new() -> Config {
        let mut newconfig = Config::default();

        /* defaults which may get overridden later */
        newconfig.op = Some(Operations::MAIN);
        newconfig.logmask.error = true;
        newconfig.logmask.warning = true;
        newconfig.configfile = String::from(CONFFILE); //TODO: implement this
        newconfig.deltaratio = 0.0;
        //TODO: implement this
        // if(alpm_capabilities() & ALPM_CAPABILITY_SIGNATURES) {
        // 	newconfig.SigLevel = package | package_optional |
        // 		database | database_optional;
        // 	newconfig.localfileSigLevel = USE_DEFAULT;
        // 	newconfig.remotefileSigLevel = USE_DEFAULT;
        // }

        newconfig.colstr.colon = String::from(":: ");
        newconfig.colstr.title = String::new();
        newconfig.colstr.repo = String::new();
        newconfig.colstr.version = String::new();
        newconfig.colstr.groups = String::new();
        newconfig.colstr.meta = String::new();
        newconfig.colstr.warn = String::new();
        newconfig.colstr.err = String::new();
        newconfig.colstr.nocolor = String::new();

        return newconfig;
    }

    pub fn needs_root(&self) -> bool {
        if self.sysroot != "" {
            return true;
        }
        use pacman::conf::Operations::*;
        match self.op {
            Some(Database) => return self.op_q_check == 0,
            Some(UPGRADE) | Some(REMOVE) => return self.print,
            Some(SYNC) => {
                return self.op_s_clean != 0 || self.op_s_sync != 0
                    || (self.group == 0 && self.op_s_info == 0 && self.op_q_list == 0
                        && self.op_s_search == 0 && self.print)
            }

            Some(FILES) => return self.op_s_sync != 0,
            _ => return false,
        }
    }

    /// Parse command-line arguments for each operation.
    pub fn parseargs(&mut self, argv: Vec<String>) -> std::result::Result<Vec<String>, ()> {
        let mut opts = getopts::Options::new();
        {
            opts.optflag("D", "--database", "");
            opts.optflag("F", "--files", "");
            opts.optflag("Q", "--query", "");
            opts.optflag("R", "--remove", "");
            opts.optflag("S", "--sync", "");
            opts.optflag("T", "--deptest", ""); /* used by makepkg */
            opts.optflag("U", "--upgrade", "");
            opts.optflag("V", "--version", "");
            opts.optflag("h", "--help", "");

            opts.optopt("b", "dbpath", "", "");
            opts.optflag("c", "cascade", "");
            opts.optflag("c", "changelog", "");
            opts.optflag("c", "clean", "");
            opts.optflag("d", "nodeps", "");
            opts.optflag("d", "deps", "");
            opts.optflag("e", "explicit", "");
            opts.optflag("g", "groups", "");
            opts.optflag("i", "info", "");
            opts.optflag("k", "check", "");
            opts.optflag("l", "list", "");
            opts.optflag("m", "foreign", "");
            opts.optflag("n", "native", "");
            opts.optflag("n", "nosave", "");
            opts.optflag("o", "owns", "");
            opts.optflag("p", "file", "");
            opts.optflag("p", "print", "");
            opts.optflag("q", "quiet", "");
            opts.optopt("r", "root", "", "");
            opts.optopt("", "sysroot", "", "");
            opts.optflag("s", "recursive", "");
            opts.optflag("s", "search", "");
            opts.optflag("x", "regex", "");
            opts.optflag("", "machinereadable", "");
            opts.optflag("t", "unrequired", "");
            opts.optflag("u", "upgrades", "");
            opts.optflag("u", "sysupgrade", "");
            opts.optflag("u", "unneeded", "");
            opts.optflag("v", "verbose", "");
            opts.optflag("w", "downloadonly", "");
            opts.optflag("y", "refresh", "");
            opts.optflag("", "noconfirm", "");
            opts.optflag("", "confirm", "");
            opts.optopt("", "config", "", "");
            opts.optopt("", "ignore", "", "");
            opts.optopt("", "assume-installed", "", "");
            opts.optflagopt("", "debug", "", "");
            opts.optflag("", "force", "");
            opts.optopt("", "overwrite", "", "");
            opts.optflag("", "noprogressbar", "");
            opts.optflag("", "noscriptlet", "");
            opts.optopt("", "ask", "", "");
            opts.optopt("", "cachedir", "", "");
            opts.optopt("", "hookdir", "", "");
            opts.optflag("", "asdeps", "");
            opts.optopt("", "logfile", "", "");
            opts.optopt("", "ignoregroup", "", "");
            opts.optflag("", "needed", "");
            opts.optflag("", "asexplicit", "");
            opts.optopt("", "arch", "", "");
            opts.optopt("", "print-format", "", "");
            opts.optopt("", "gpgdir", "", "");
            opts.optopt("", "dbonly", "", "");
            opts.optopt("", "color", "", "");
            opts.optflag("", "disable-download-timeout", "");
        }

        /* parse operation */
        let matches = match opts.parse(&argv[1..]) {
            Ok(m) => m,
            Err(f) => {
                println!("{:?}", f);
                return Err(());
            }
        };
        // println!("{:?}", matches.free);
        // let pm_targets = &matches.free;
        self.parsearg_op(&matches);
        self.parsearg_global(&matches);
        // println!("{:?}", self);

        if self.op.is_none() {
            unimplemented!();
            // pm_printf(ALPM_LOG_ERROR, _("only one operation may be used at a time\n"));
            return Err(());
        }
        if self.help {
            unimplemented!();
            // usage(self.op, mbasename(argv[0]));
            cleanup(0);
        }
        if self.version {
            unimplemented!();
            // version();
            cleanup(0);
        }

        use self::Operations::*;
        match &self.op {
            &Some(Database) => {
                self.parsearg_database(&matches);
                self.checkargs_database();
            }
            &Some(QUERY) => {
                self.parsearg_query(&matches);
                self.checkargs_query();
            }
            &Some(REMOVE) => {
                self.parsearg_remove(&matches);
                self.checkargs_remove();
            }
            &Some(SYNC) => {
                self.parsearg_sync(&matches);
                self.checkargs_sync();
            }
            &Some(UPGRADE) => {
                self.parsearg_upgrade(&matches);
                self.checkargs_upgrade();
            }
            &Some(FILES) => {
                self.parsearg_files(&matches);
                self.checkargs_files();
            }
            _ => {}
        }

        return Ok(matches.free);
    }

    // static int parsearg_util_addlist(alpm_list_t **list)
    // {
    // 	char *i, *save = NULL;
    //
    // 	for(i = strtok_r(optarg, ",", &save); i; i = strtok_r(NULL, ",", &save)) {
    // 		*list = alpm_list_add(*list, strdup(i));
    // 	}
    //
    // 	return 0;
    // }

    /** Helper function for parsing operation from command-line arguments.
     * @param opt Keycode returned by getopt_long
     * @param dryrun If nonzero, application state is NOT changed
     * @return 0 if opt was handled, 1 if it was not handled
     */
    // fn parsearg_op(int opt, int dryrun) . i64
    fn parsearg_op(&mut self, opts: &getopts::Matches) -> i64 {
        use self::Operations::*;
        /* operations */
        if opts.opt_present("D") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(MAIN) => Some(Operations::Database),
                _ => None,
            }
        } else if opts.opt_present("F") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(MAIN) => Some(FILES),
                _ => None,
            };
        } else if opts.opt_present("Q") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(MAIN) => Some(QUERY),
                _ => None,
            };
        } else if opts.opt_present("R") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(MAIN) => Some(REMOVE),
                _ => None,
            };
        } else if opts.opt_present("S") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(MAIN) => Some(SYNC),
                _ => None,
            };
        } else if opts.opt_present("T") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(MAIN) => Some(Operations::DEPTEST),
                _ => None,
            };
        } else if opts.opt_present("U") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(MAIN) => Some(Operations::UPGRADE),
                _ => None,
            };
        } else if opts.opt_present("V") {
            //if(dryrun) break;
            self.version = true;
        } else if opts.opt_present("h") {
            //if(dryrun) break;
            self.help = true;
        } else {
            return 1;
        }
        return 0;
    }

    /** Helper functions for parsing command-line arguments.
     * @param opt Keycode returned by getopt_long
     * @return 0 on success, 1 on failure
     */
    fn parsearg_global(&mut self, opts: &getopts::Matches) -> i8 {
        if opts.opt_present("arch") {
            unimplemented!();
            // self_set_arch(opts.opt_str("arch").unwrap());
        }
        if opts.opt_present("ask") {
            self.noask = true;
            self.ask = opts.opt_str("ask")
                .unwrap()
                .parse()
                .expect("--ask requires a number argument");
        }
        if opts.opt_present("cachedir") {
            unimplemented!()
            // self.cachedirs = alpm_list_add(self.cachedirs, strdup(opts.opt_str("cachedir")));
        }
        if opts.opt_present("color") {
            unimplemented!();
            let optarg = opts.opt_str("color").unwrap();
            if "never" == optarg {
                // self.color = PM_COLOR_OFF;
            } else if "auto" == optarg {
                // self.color = isatty(fileno(stdout)) ? PM_COLOR_ON : PM_COLOR_OFF;
            } else if "always" == optarg {
                // self.color = PM_COLOR_ON;
            } else {
                // pm_printf(ALPM_LOG_ERROR, _("invalid argument '{}' for {}\n"),
                // 		optarg, "--color");
                return 1;
            }
            // enable_colors(self.color);
        }
        if opts.opt_present("config") {
            self.configfile = opts.opt_str("config").unwrap();
        }
        if opts.opt_present("debug") {
            /* debug levels are made more 'human readable' than using a raw logmask
             * here, error and warning are set in self_new, though perhaps a
             * --quiet option will remove these later */
            match opts.opt_str("debug") {
                Some(d) => {
                    let debug = d.parse().unwrap();
                    match debug {
                        2 => {
                            self.logmask.function = true; /* fall through */
                            self.logmask.debug = true;
                        }
                        1 => self.logmask.debug = true,
                        _ => {
                            unimplemented!();
                            error!("'{}' is not a valid debug level", d);
                            return 1;
                        }
                    }
                }
                None => {
                    self.logmask.debug = true;
                }
            }
            /* progress bars get wonky with debug on, shut them off */
            self.noprogressbar = 1;
        }
        if opts.opt_present("gpgdir") {
            self.gpgdir = opts.opt_str("gpgdir").unwrap();
        }
        if opts.opt_present("hookdir") {
            unimplemented!();
            // 		self.hookdirs = alpm_list_add(self.hookdirs, strdup(optarg));
        }
        if opts.opt_present("logfile") {
            self.logfile = opts.opt_str("logfile").unwrap();
        }
        if opts.opt_present("noconfirm") {
            self.noconfirm = true;
        }
        if opts.opt_present("confirm") {
            self.noconfirm = false;
        }
        if opts.opt_present("dbpath") {
            self.dbpath = opts.opt_str("dbpath").unwrap();
        }
        if opts.opt_present("root") {
            self.rootdir = opts.opt_str("rootdir").unwrap();
        }
        if opts.opt_present("sysroot") {
            self.sysroot = opts.opt_str("sysroot").unwrap();
        }
        if opts.opt_present("disable-download-timeout") {
            self.disable_dl_timeout = 1;
        }
        if opts.opt_present("verbose") {
            self.verbose = opts.opt_count("verbose") as u8;
        }
        return 0;
    }

    fn parsearg_database(&mut self, opts: &getopts::Matches) {
        if opts.opt_present("asdeps") {
            self.flags.all_deps = true;
        }
        if opts.opt_present("asexplicit") {
            self.flags.all_explicit = true;
        }
        if opts.opt_present("check") {
            self.op_q_check = opts.opt_count("check") as u8;
        }
        if opts.opt_present("check") {
            self.quiet = true;
        }
    }

    fn checkargs_database(&mut self) {
        invalid_opt(
            self.flags.all_deps && self.flags.all_explicit,
            "--asdeps",
            "--asexplicit",
        );

        if self.op_q_check != 0 {
            invalid_opt(self.flags.all_deps, "--asdeps", "--check");
            invalid_opt(self.flags.all_explicit, "--asexplicit", "--check");
        }
    }

    fn parsearg_query(&mut self, opts: &getopts::Matches) {
        if opts.opt_present("changelog") {
            self.op_q_changelog = 1;
        }
        if opts.opt_present("deps") {
            self.op_q_deps = 1;
        }
        if opts.opt_present("explicit") {
            self.op_q_explicit = 1;
        }
        if opts.opt_present("groups") {
            self.group = opts.opt_count("groups") as u8;
        }
        if opts.opt_present("info") {
            self.op_q_info = opts.opt_count("info") as u8;
        }
        if opts.opt_present("check") {
            self.op_q_check = opts.opt_count("check") as u8;
        }
        if opts.opt_present("list") {
            self.op_q_list = 1;
        }
        if opts.opt_present("foreign") {
            self.op_q_locality |= PKG_LOCALITY_FOREIGN;
        }
        if opts.opt_present("native") {
            self.op_q_locality |= PKG_LOCALITY_NATIVE;
        }
        if opts.opt_present("owns") {
            self.op_q_owns = 1;
        }
        if opts.opt_present("file") {
            self.op_q_isfile = 1;
        }
        if opts.opt_present("quiet") {
            self.quiet = true;
        }
        if opts.opt_present("search") {
            self.op_q_search = 1;
        }
        if opts.opt_present("unrequired") {
            self.op_q_unrequired = opts.opt_count("unrequired") as u8;
        }
        if opts.opt_present("upgrades") {
            self.op_q_upgrade = 1;
        }
    }

    fn checkargs_query_display_opts(&mut self, opname: &str) {
        invalid_opt(self.op_q_changelog != 0, opname, "--changelog");
        invalid_opt(self.op_q_check != 0, opname, "--check");
        invalid_opt(self.op_q_info != 0, opname, "--info");
        invalid_opt(self.op_q_list != 0, opname, "--list");
    }

    fn checkargs_query_filter_opts(&mut self, opname: &str) {
        invalid_opt(self.op_q_deps != 0, opname, "--deps");
        invalid_opt(self.op_q_explicit != 0, opname, "--explicit");
        invalid_opt(self.op_q_upgrade != 0, opname, "--upgrade");
        invalid_opt(self.op_q_unrequired != 0, opname, "--unrequired");
        invalid_opt(
            self.op_q_locality & PKG_LOCALITY_NATIVE != 0,
            opname,
            "--native",
        );
        invalid_opt(
            self.op_q_locality & PKG_LOCALITY_FOREIGN != 0,
            opname,
            "--foreign",
        );
    }

    fn checkargs_query(&mut self) {
        if self.op_q_isfile != 0 {
            invalid_opt(self.group != 0, "--file", "--groups");
            invalid_opt(self.op_q_search != 0, "--file", "--search");
            invalid_opt(self.op_q_owns != 0, "--file", "--owns");
        } else if self.op_q_search != 0 {
            invalid_opt(self.group != 0, "--search", "--groups");
            invalid_opt(self.op_q_owns != 0, "--search", "--owns");
            self.checkargs_query_display_opts("--search");
            self.checkargs_query_filter_opts("--search");
        } else if self.op_q_owns != 0 {
            invalid_opt(self.group != 0, "--owns", "--groups");
            self.checkargs_query_display_opts("--owns");
            self.checkargs_query_filter_opts("--owns");
        } else if self.group != 0 {
            self.checkargs_query_display_opts("--groups");
        }

        invalid_opt(
            self.op_q_deps != 0 && self.op_q_explicit != 0,
            "--deps",
            "--explicit",
        );
        invalid_opt(
            (self.op_q_locality & PKG_LOCALITY_NATIVE != 0)
                && (self.op_q_locality & PKG_LOCALITY_FOREIGN != 0),
            "--native",
            "--foreign",
        );
    }

    /* options common to -S -R -U */
    fn parsearg_trans(&mut self, opts: &getopts::Matches) {
        if opts.opt_present("nodeps") {
            if self.flags.no_depversion {
                self.flags.no_deps = true;
            } else {
                self.flags.no_depversion = true;
            }
        }
        if opts.opt_present("dbonly") {
            self.flags.db_only = true;
            self.flags.no_scriptlet = true;
        }
        if opts.opt_present("noprogressbar") {
            self.noprogressbar = 1;
        }
        if opts.opt_present("noscriptlet") {
            self.flags.no_scriptlet = true;
        }
        if opts.opt_present("print") {
            self.print = true;
        }
        if opts.opt_present("print-format") {
            self.print = true;
            self.print_format = opts.opt_str("print-format").unwrap();
        }
        if opts.opt_present("assume-installed") {
            unimplemented!();
            // parsearg_util_addlist(&(self.assumeinstalled));
        }
    }

    fn checkargs_trans(&mut self) {
        if self.print {
            invalid_opt(self.flags.db_only, "--print", "--dbonly");
            invalid_opt(self.flags.no_scriptlet, "--print", "--noscriptlet");
        }
    }

    fn parsearg_remove(&mut self, opts: &getopts::Matches) {
        self.parsearg_trans(opts);

        if opts.opt_present("cascade") {
            self.flags.cascade = true;
        }
        if opts.opt_present("nosave") {
            self.flags.no_save = true;
        }
        if opts.opt_present("recursive") {
            if self.flags.recurse {
                self.flags.recurse_all = true;
            } else {
                self.flags.recurse = true;
            }
        }
        if opts.opt_present("unneeded") {
            self.flags.unneeded = true;
        }
    }

    fn checkargs_remove(&mut self) {
        self.checkargs_trans();
        if self.flags.no_save {
            invalid_opt(self.print, "--nosave", "--print");
            invalid_opt(self.flags.db_only, "--nosave", "--dbonly");
        }
    }

    /* options common to -S -U */
    fn parsearg_upgrade(&mut self, opts: &getopts::Matches) {
        self.parsearg_trans(opts);

        if opts.opt_present("force") {
            self.flags.force = true;
        }
        if opts.opt_present("overwrite") {
            unimplemented!();
            // parsearg_util_addlist(&(self.overwrite_files));
        }
        if opts.opt_present("asdeps") {
            self.flags.all_deps = true;
        }
        if opts.opt_present("asexplicit") {
            self.flags.all_explicit = true;
        }
        if opts.opt_present("needed") {
            self.flags.needed = true;
        }
    }

    fn checkargs_upgrade(&mut self) {
        self.checkargs_trans();
        invalid_opt(
            self.flags.all_deps && self.flags.all_explicit,
            "--asdeps",
            "--asexplicit",
        );
    }

    fn parsearg_files(&mut self, opts: &getopts::Matches) {
        self.parsearg_trans(opts);

        if opts.opt_present("owns") {
            self.op_q_owns = 1;
        }
        if opts.opt_present("list") {
            self.op_q_list = 1;
        }
        if opts.opt_present("search") {
            self.op_s_search = 1;
        }
        if opts.opt_present("refresh") {
            self.op_s_sync = opts.opt_count("refresh") as u8;
        }
        if opts.opt_present("machinereadable") {
            self.op_f_machinereadable = 1;
        }
        if opts.opt_present("quiet") {
            self.quiet = true;
        }
    }

    fn checkargs_files(&mut self) {
        if self.op_q_owns != 0 {
            invalid_opt(self.op_q_list != 0, "--owns", "--list");
            invalid_opt(self.op_q_search != 0, "--owns", "--search");
            invalid_opt(self.op_f_regex != 0, "--owns", "--regex");
        } else if self.op_q_list != 0 {
            invalid_opt(self.op_q_search != 0, "--list", "--search");
            invalid_opt(self.op_f_regex != 0, "--list", "--regex");
        }
    }

    fn parsearg_sync(&mut self, opts: &getopts::Matches) {
        self.parsearg_upgrade(opts);

        if opts.opt_present("clean") {
            self.op_s_clean = opts.opt_count("clean") as u8;
        }
        if opts.opt_present("groups") {
            self.group = opts.opt_count("groups") as u8;
        }
        if opts.opt_present("info") {
            self.op_s_info = opts.opt_count("info") as u8;
        }
        if opts.opt_present("list") {
            self.op_q_list = 1;
        }
        if opts.opt_present("quiet") {
            self.quiet = true;
        }
        if opts.opt_present("search") {
            self.op_s_search = 1;
        }
        if opts.opt_present("u") | opts.opt_present("sysupgrade") {
            self.op_s_upgrade = (opts.opt_count("sysupgrade") + opts.opt_count("u")) as u8;
        }
        if opts.opt_present("downloadonly") {
            self.op_s_downloadonly = 1;
            self.flags.download_only = true;
            self.flags.no_conflicts = true;
        }
        if opts.opt_present("refresh") {
            self.op_s_sync = opts.opt_count("refresh") as u8;
        }
    }

    fn checkargs_sync(&mut self) {
        self.checkargs_upgrade();
        if self.op_s_clean != 0 {
            invalid_opt(self.group != 0, "--clean", "--groups");
            invalid_opt(self.op_s_info != 0, "--clean", "--info");
            invalid_opt(self.op_q_list != 0, "--clean", "--list");
            invalid_opt(self.op_s_sync != 0, "--clean", "--refresh");
            invalid_opt(self.op_s_search != 0, "--clean", "--search");
            invalid_opt(self.op_s_upgrade != 0, "--clean", "--sysupgrade");
            invalid_opt(self.op_s_downloadonly != 0, "--clean", "--downloadonly");
        } else if self.op_s_info != 0 {
            invalid_opt(self.group != 0, "--info", "--groups");
            invalid_opt(self.op_q_list != 0, "--info", "--list");
            invalid_opt(self.op_s_search != 0, "--info", "--search");
            invalid_opt(self.op_s_upgrade != 0, "--info", "--sysupgrade");
            invalid_opt(self.op_s_downloadonly != 0, "--info", "--downloadonly");
        } else if self.op_s_search != 0 {
            invalid_opt(self.group != 0, "--search", "--groups");
            invalid_opt(self.op_q_list != 0, "--search", "--list");
            invalid_opt(self.op_s_upgrade != 0, "--search", "--sysupgrade");
            invalid_opt(self.op_s_downloadonly != 0, "--search", "--downloadonly");
        } else if self.op_q_list != 0 {
            invalid_opt(self.group != 0, "--list", "--groups");
            invalid_opt(self.op_s_upgrade != 0, "--list", "--sysupgrade");
            invalid_opt(self.op_s_downloadonly != 0, "--list", "--downloadonly");
        } else if self.group != 0 {
            invalid_opt(self.op_s_upgrade != 0, "--groups", "--sysupgrade");
            invalid_opt(self.op_s_downloadonly != 0, "--groups", "--downloadonly");
        }
    }
}

///Helper function for download_with_xfercommand()
fn get_filename(url: &String) -> String {
    unimplemented!();
    // 	char *filename = strrchr(url, '/');
    // 	if(filename != NULL) {
    // 		filename++;
    // 	}
    // 	return filename;
}

// /** Helper function for download_with_xfercommand() */
// static char *get_destfile(const char *path, const char *filename)
// {
// 	char *destfile;
// 	/* len = localpath len + filename len + null */
// 	size_t len = strlen(path) + strlen(filename) + 1;
// 	destfile = calloc(len, sizeof(char));
// 	snprintf(destfile, len, "{}{}", path, filename);
//
// 	return destfile;
// }

// /** Helper function for download_with_xfercommand() */
// static char *get_tempfile(const char *path, const char *filename)
// {
// 	char *tempfile;
// 	/* len = localpath len + filename len + '.part' len + null */
// 	size_t len = strlen(path) + strlen(filename) + 6;
// 	tempfile = calloc(len, sizeof(char));
// 	snprintf(tempfile, len, "{}{}.part", path, filename);
//
// 	return tempfile;
// }

// /** External fetch callback */
// static int download_with_xfercommand(const char *url, const char *localpath,
// 		int force)
// {
// 	int ret = 0, retval;
// 	int usepart = 0;
// 	int cwdfd;
// 	struct stat st;
// 	char *parsedcmd, *tempcmd;
// 	char *destfile, *tempfile, *filename;
//
// 	if(!config.xfercommand) {
// 		return -1;
// 	}
//
// 	filename = get_filename(url);
// 	if(!filename) {
// 		return -1;
// 	}
// 	destfile = get_destfile(localpath, filename);
// 	tempfile = get_tempfile(localpath, filename);
//
// 	if(force && stat(tempfile, &st) == 0) {
// 		unlink(tempfile);
// 	}
// 	if(force && stat(destfile, &st) == 0) {
// 		unlink(destfile);
// 	}
//
// 	tempcmd = strdup(config.xfercommand);
// 	/* replace all occurrences of %o with fn.part */
// 	if(strstr(tempcmd, "%o")) {
// 		usepart = 1;
// 		parsedcmd = strreplace(tempcmd, "%o", tempfile);
// 		free(tempcmd);
// 		tempcmd = parsedcmd;
// 	}
// 	/* replace all occurrences of %u with the download URL */
// 	parsedcmd = strreplace(tempcmd, "%u", url);
// 	free(tempcmd);
//
// 	/* save the cwd so we can restore it later */
// 	do {
// 		cwdfd = open(".", O_RDONLY);
// 	} while(cwdfd == -1 && errno == EINTR);
// 	if(cwdfd < 0) {
// 		pm_printf(ALPM_LOG_ERROR, _("could not get current working directory\n"));
// 	}
//
// 	/* cwd to the download directory */
// 	if(chdir(localpath)) {
// 		pm_printf(ALPM_LOG_WARNING, _("could not chdir to download directory {}\n"), localpath);
// 		ret = -1;
// 		goto cleanup;
// 	}
// 	/* execute the parsed command via /bin/sh -c */
// 	debug!( "running command: {}\n", parsedcmd);
// 	retval = system(parsedcmd);
//
// 	if(retval == -1) {
// 		pm_printf(ALPM_LOG_WARNING, _("running XferCommand: fork failed!\n"));
// 		ret = -1;
// 	} else if(retval != 0) {
// 		/* download failed */
// 		debug!( "XferCommand command returned non-zero status "
// 				"code ({})\n", retval);
// 		ret = -1;
// 	} else {
// 		/* download was successful */
// 		ret = 0;
// 		if(usepart) {
// 			if(rename(tempfile, destfile)) {
// 				pm_printf(ALPM_LOG_ERROR, _("could not rename {} to {} ({})\n"),
// 						tempfile, destfile, strerror(errno));
// 				ret = -1;
// 			}
// 		}
// 	}
//
// cleanup:
// 	/* restore the old cwd if we have it */
// 	if(cwdfd >= 0) {
// 		if(fchdir(cwdfd) != 0) {
// 			pm_printf(ALPM_LOG_ERROR, _("could not restore working directory ({})\n"),
// 					strerror(errno));
// 		}
// 		close(cwdfd);
// 	}
//
// 	if(ret == -1) {
// 		/* hack to let an user the time to cancel a download */
// 		sleep(2);
// 	}
// 	free(destfile);
// 	free(tempfile);
// 	free(parsedcmd);
//
// 	return ret;
// }

impl Config {
    pub fn config_set_arch(&mut self, arch: &String) -> i32 {
        if arch == "auto" {
            // struct utsname un;
            // uname(&un);
            self.arch = String::from(OS_ARCH);
        } else {
            self.arch = arch.clone();
        }
        debug!("config: arch: {}", self.arch);
        return 0;
    }
}

/// Parse a signature verification level line.
/// @param values the list of parsed option values
/// @param storage location to store the derived signature level; any existing
/// value here is used as a starting point
/// @param file path to the config file
/// @param linenum current line number in file
/// @return 0 on success, 1 on any parsing error
fn process_siglevel(
    values: Vec<String>,
    storage: &mut SigLevel,
    storage_mask: &mut SigLevel,
    file: &String,
    linenum: i32,
) -> i32 {
    let mut level = storage.clone();
    let mut mask = storage_mask.clone();
    let mut ret = 0;

    /* Collapse the option names into a single bitmasked value */
    for original in values {
        let value;
        // 		const char *original = i.data, *value;
        // 		int package = 0, database = 0;
        let mut package = false;
        let mut db = false;

        if original.starts_with("Package") {
            /* only packages are affected, don't flip flags for databases */
            value = String::from(original.trim_left_matches("Package"));
            package = true;
        } else if original.starts_with("Database") {
            /* only databases are affected, don't flip flags for packages */
            value = String::from(original.trim_left_matches("Database"));
            db = true;
        } else {
            /* no prefix, so anything found will affect both packages and dbs */
            value = original.clone();
            package = true;
            db = true;
        }

        /* now parse out and store actual flag if it is valid */
        if value == "Never" {
            if package {
                level.package = false;
                mask.package = false;
            }
            if db {
                level.database = false;
                mask.database = false;
            }
        } else if value == "Optional" {
            if package {
                level.database = true;
                mask.database = true;

                level.package_optional = true;
                mask.package_optional = true;
            }
            if db {
                level.database = true;
                mask.database = true;

                level.database_optional = true;
                mask.database_optional = true;
            }
        } else if value == "Required" {
            if package {
                level.package = true;
                mask.package = true;

                level.package_optional = false;
                mask.package_optional = false;
            }
            if db {
                level.database = true;
                mask.database = true;

                level.database_optional = false;
                mask.database_optional = false;
            }
        } else if value == "TrustedOnly" {
            if package {
                level.package_marginal_ok = false;
                mask.package_marginal_ok = false;

                level.package_unknown_ok = false;
                mask.package_unknown_ok = false;
            }
            if db {
                level.database_marginal_ok = false;
                mask.database_marginal_ok = false;

                level.database_unknown_ok = false;
                mask.database_unknown_ok = false;
            }
        } else if value == "TrustAll" {
            if package {
                level.package_marginal_ok = true;
                mask.package_marginal_ok = true;

                level.package_unknown_ok = true;
                mask.package_unknown_ok = true;
            }
            if db {
                level.database_marginal_ok = true;
                mask.database_marginal_ok = true;

                level.database_unknown_ok = true;
                mask.database_unknown_ok = true;
            }
        } else {
            eprintln!(
                "config file {}, line {}: invalid value for '{}' : '{}'",
                file, linenum, "SigLevel", original
            );
            ret = 1;
        }
        level.use_default = false;
    }

    /* ensure we have sig checking ability and are actually turning it on */
    if !(alpm::capabilities().signatures && level.package
        || level.database)
    {
        eprintln!(
            "config file {}, line {}: '{}' option invalid, no signature support",
            file, linenum, "SigLevel"
        );
        ret = 1;
    }

    if ret == 0 {
        *storage = level;
        *storage_mask = mask;
    }
    return ret;
}

/// Merge the package entries of two signature verification levels.
/// @param base initial SigLevel
/// @param over overriding SigLevel
/// @return merged SigLevel
pub fn merge_siglevel(base: SigLevel, over: SigLevel, mask: SigLevel) -> SigLevel {
    return if mask.not_zero() {
        (over & mask) | (base & !mask)
    } else {
        over
    };
}

pub fn process_cleanmethods(
    values: Vec<String>,
    file: &String,
    linenum: i32,
    config: &mut Config,
) -> i32 {
    for value in values {
        if value == "KeepInstalled" {
            config.cleanmethod.keepinst = true;
        } else if value == "KeepCurrent" {
            config.cleanmethod.keepcur = true;
        } else {
            error!(
                "config file {}, line {}: invalid value for '{}' : '{}'",
                file, linenum, "CleanMethod", value
            );
            return 1;
        }
    }
    return 0;
}

/// Add repeating options such as NoExtract, NoUpgrade, etc to libalpm
/// settings. Refactored out of the parseconfig code since all of them did
/// the exact same thing and duplicated code.
///
/// - `ptr` - a pointer to the start of the multiple options
/// - `option` - the string (friendly) name of the option, used for messages
/// - `list` - the list to add the option to
fn setrepeatingoption(ptr: &String, _option: &str, list: &mut Vec<String>) {
    // char *val, *saveptr = NULL;

    let vals = ptr.split_whitespace();
    for val in vals {
        list.push(String::from(val));
        // debug!( "config: {}: {}", option, val);
        // val = strtok_r(NULL, " ", &saveptr);
    }
}

fn _parse_options(
    key: &Option<String>,
    value: &Option<String>,
    file: &String,
    linenum: i32,
    config: &mut Config,
) -> i32 {
    let key = match key {
        &Some(ref k) => k,
        &None => unimplemented!(),
    };
    match value {
        &None => {
            /* options without settings */
            if key == "UseSyslog" {
                config.usesyslog = 1;
                debug!("config: usesyslog");
            } else if key == "ILoveCandy" {
                config.chomp = 1;
                debug!("config: chomp");
            } else if key == "VerbosePkgLists" {
                config.verbosepkglists = 1;
                debug!("config: verbosepkglists");
            } else if key == "UseDelta" {
                config.deltaratio = 0.7;
                debug!("config: usedelta (default 0.7)");
            } else if key == "TotalDownload" {
                config.totaldownload = 1;
                debug!("config: totaldownload");
            } else if key == "CheckSpace" {
                config.checkspace = 1;
            } else if key == "Color" {
                unimplemented!();
            // if config.color == PM_COLOR_UNSET {
            // config.color = isatty(fileno(stdout)) ? PM_COLOR_ON : PM_COLOR_OFF;
            // enable_colors(config.color);
            // }
            } else if key == "DisableDownloadTimeout" {
                config.disable_dl_timeout = 1;
            } else {
                warn!(
                    "config file {}, line {}: directive '{}' in section '{}' not recognized.",
                    file, linenum, key, "options"
                );
            }
        }
        &Some(ref value) => {
            // 		/* options with settings */
            if key == "NoUpgrade" {
                setrepeatingoption(value, "NoUpgrade", &mut config.noupgrade);
            } else if key == "NoExtract" {
                setrepeatingoption(value, "NoExtract", &mut config.noextract);
            } else if key == "IgnorePkg" {
                setrepeatingoption(value, "IgnorePkg", &mut config.ignorepkg);
            } else if key == "IgnoreGroup" {
                setrepeatingoption(value, "IgnoreGroup", &mut config.ignoregrp);
            } else if key == "HoldPkg" {
                setrepeatingoption(value, "HoldPkg", &mut config.holdpkg);
            } else if key == "CacheDir" {
                setrepeatingoption(value, "CacheDir", &mut config.cachedirs);
            } else if key == "HookDir" {
                setrepeatingoption(value, "HookDir", &mut config.hookdirs);
            } else if key == "Architecture" {
                if config.arch == "" {
                    config.config_set_arch(value);
                }
            } else if key == "UseDelta" {
                unimplemented!();
            // double ratio;
            // char *endptr;
            // const char *oldlocale;
            // /* set the locale to 'C' for consistent decimal parsing (0.7 and never
            //  * 0,7) from config files, then restore old setting when we are done */
            // oldlocale = setlocale(LC_NUMERIC, NULL);
            // setlocale(LC_NUMERIC, "C");
            // ratio = strtod(value, &endptr);
            // setlocale(LC_NUMERIC, oldlocale);
            //
            // if (*endptr != '\0' || ratio < 0.0 || ratio > 2.0) {
            //     error!(
            //         "config file {}, line {}: invalid value for '{}' : '{}'",
            //         file, linenum, "UseDelta", value
            //     );
            //     return 1;
            // }
            // config.deltaratio = ratio;
            // debug!("config: usedelta = {}\n", ratio);
            } else if key == "DBPath" {
                /* don't overwrite a path specified on the command line */
                if config.dbpath == "" {
                    config.dbpath = value.clone();
                    debug!("config: dbpath: {}", value);
                }
            } else if key == "RootDir" {
                /* don't overwrite a path specified on the command line */
                if config.rootdir == "" {
                    config.rootdir = value.clone();
                    debug!("config: rootdir: {}", value);
                }
            } else if key == "GPGDir" {
                if config.gpgdir == "" {
                    config.gpgdir = value.clone();
                    debug!("config: gpgdir: {}", value);
                }
            } else if key == "LogFile" {
                if config.logfile == "" {
                    config.logfile = value.clone();
                    debug!("config: logfile: {}", value);
                }
            } else if key == "XferCommand" {
                config.xfercommand = value.clone();
                debug!("config: xfercommand: {}", value);
            } else if key == "CleanMethod" {
                unimplemented!();
                let mut methods = Vec::new();
                setrepeatingoption(value, "CleanMethod", &mut methods);
                if process_cleanmethods(methods, file, linenum, config) != 0 {
                    return 1;
                }
            } else if key == "SigLevel" {
                let mut values = Vec::new();
                setrepeatingoption(value, "SigLevel", &mut values);
                if process_siglevel(
                    values,
                    &mut config.siglevel,
                    &mut config.siglevel_mask,
                    file,
                    linenum,
                ) != 0
                {
                    return 1;
                }
            } else if key == "LocalFileSigLevel" {
                let mut values = Vec::new();
                setrepeatingoption(value, "LocalFileSigLevel", &mut values);
                if process_siglevel(
                    values,
                    &mut config.localfilesiglevel,
                    &mut config.localfilesiglevel_mask,
                    file,
                    linenum,
                ) != 0
                {
                    return 1;
                }
            } else if key == "RemoteFileSigLevel" {
                let mut values = Vec::new();
                setrepeatingoption(value, "RemoteFileSigLevel", &mut values);
                if process_siglevel(
                    values,
                    &mut config.remotefilesiglevel,
                    &mut config.remotefilesiglevel_mask,
                    file,
                    linenum,
                ) != 0
                {
                    return 1;
                }
            } else {
                warn!(
                    "config file {}, line {}: directive '{}' in section '{}' not recognized.",
                    file, linenum, key, "options"
                );
            }
        }
    }
    return 0;
}

fn _add_mirror(db: &mut Database, value: &String, arch: &String) -> Result<()> {
    let dbname = db.alpm_db_get_name().clone();
    /* let's attempt a replacement for the current repo */
    let temp = value.replace("$repo", &dbname);
    /* let's attempt a replacement for the arch */
    let server;
    if arch != "" {
        server = temp.replace("$arch", arch);
    } else {
        if temp.contains("$arch") {
            error!(
                "mirror '{}' contains the '{}' variable, but no '{}' is defined.",
                value, "$arch", "Architecture"
            );
            // return 1;
            unimplemented!();
        }
        server = temp;
    }

    match db.alpm_db_add_server(&server) {
        Err(e) => {
            error!(
                "could not add server URL to database '{}': {} ({})",
                dbname, server, e
            );
            return Err(e);
        }
        Ok(()) => {}
    }
    Ok(())
}

fn register_repo(
    repo: &mut ConfigRepo,
    config_handle: &mut Handle,
    config_siglevel: SigLevel,
    arch: &String,
) -> i32 {
    repo.siglevel = merge_siglevel(config_siglevel, repo.siglevel, repo.siglevel_mask);

    let mut db = match config_handle.alpm_register_syncdb(&repo.name, repo.siglevel) {
        Err(e) => {
            eprintln!(
                "could not register '{}' database ({})",
                repo.name,
                e.alpm_strerror()
            );
            return 1;
        }
        Ok(db) => db,
    };

    // debug!(
    //     "setting usage of {} for {} repository\n",
    //     if repo.usage.is_zero() {
    //         DatabaseUsage {
    //             ALPM_DB_USAGE_ALL: true,
    //             ..Default::default()
    //         }
    //     } else {
    //         repo.usage
    //     },
    //     repo.name
    // );
    if repo.usage.is_zero() {
        repo.usage.all = true;
    }
    db.alpm_db_set_usage(repo.usage);

    for value in &repo.servers {
        // char *value = i.data;
        match _add_mirror(&mut db, &value, arch) {
            Err(e) => {
                error!(
                    "could not add mirror '{}' to database '{}' ({})",
                    value,
                    repo.name,
                    e.alpm_strerror()
                );
                return 1;
            }
            Ok(_) => {}
        }
    }

    // if config_handle.dbs_sync.len() == 0 {
    //     config_handle.dbs_sync = Vec::new();
    // }
    config_handle.dbs_sync.push(db);

    return 0;
}

/** Sets up libalpm global stuff in one go. Called after the command line
 * and initial config file parsing. Once this is complete, we can see if any
 * paths were defined. If a rootdir was defined and nothing else, we want all
 * of our paths to live under the rootdir that was specified. Safe to call
 * multiple times (will only do anything the first time).
 */
fn setup_libalpm(config: &mut Config) -> Result<Handle> {
    let mut handle;

    debug!("setup_libalpm called");

    /* Configure root path first. If it is set and dbpath/logfile were not
     * set, then set those as well to reside under the root. */
    if config.rootdir != "" {
        // 		char path[PATH_MAX];
        if config.dbpath == "" {
            let path = format!("{}{}", config.rootdir, DBPATH);
            config.dbpath = path.clone();
        }
        if config.logfile == "" {
            let path = format!("{}{}", config.rootdir, LOGFILE);
            config.logfile = path.clone();
        }
    } else {
        config.rootdir = String::from(ROOTDIR);
        if config.dbpath == "" {
            config.dbpath = String::from(DBPATH);
        }
    }

    /* initialize library */
    handle = match alpm::initialize(&config.rootdir, &config.dbpath) {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "failed to initialize alpm library({}: {})",
                e.alpm_strerror(),
                config.dbpath
            );
            match e {
                Error::ALPM_ERR_DB_VERSION => {
                    eprintln!("try running pacman-db-upgrade");
                }
                _ => {}
            }
            return Err(e);
        }
    };

    // config.handle = handle;

    // alpm_option_set_logcb(handle, cb_log);
    // alpm_option_set_dlcb(handle, cb_dl_progress);
    // alpm_option_set_eventcb(handle, cb_event);
    // alpm_option_set_questioncb(handle, cb_question);
    // alpm_option_set_progresscb(handle, cb_progress);

    match config.op {
        Some(Operations::FILES) => {
            handle.alpm_option_set_dbext(&String::from(".files"));
        }
        _ => {}
    }

    if config.logfile == "" {
        config.logfile = String::from(LOGFILE)
    };
    match handle.alpm_option_set_logfile(&config.logfile) {
        Err(e) => {
            eprintln!(
                "problem setting logfile '{}' ({})",
                config.logfile,
                e.alpm_strerror()
            );
            return Err(e);
        }
        _ => {}
    };

    /* Set GnuPG's home directory. This is not relative to rootdir, even if
     * rootdir is defined. Reasoning: gpgdir contains configuration data. */
    if config.gpgdir == "" {
        config.gpgdir = String::from(GPGDIR);
    }
    match handle.alpm_option_set_gpgdir(&config.gpgdir) {
        Err(ret) => {
            eprintln!(
                "problem setting gpgdir '{}' ({})",
                config.gpgdir,
                ret.alpm_strerror()
            );
            return Err(ret);
        }
        _ => {}
    }

    /* Set user hook directory. This is not relative to rootdir, even if
     * rootdir is defined. Reasoning: hookdir contains configuration data. */
    if config.hookdirs.is_empty() {
        match handle.alpm_option_add_hookdir(&String::from(HOOKDIR)) {
            Err(e) => {
                eprintln!(
                    "problem adding hookdir '{}' ({})",
                    HOOKDIR,
                    e.alpm_strerror()
                );
                return Err(e);
            }
            Ok(_) => {}
        }
    } else {
        /* add hook directories 1-by-1 to avoid overwriting the system directory */
        for data in &config.hookdirs {
            match handle.alpm_option_add_hookdir(data) {
                Err(e) => {
                    eprintln!("problem adding hookdir '{}' ({})", data, e.alpm_strerror());
                    return Err(e);
                }
                Ok(_) => {}
            }
        }
    }

    // 	/* add a default cachedir if one wasn't specified */
    if config.cachedirs.is_empty() {
        handle.alpm_option_add_cachedir(&String::from(CACHEDIR))?;
    } else {
        handle.alpm_option_set_cachedirs(&config.cachedirs)?;
    }

    handle.alpm_option_set_overwrite_files(&config.overwrite_files);

    handle.alpm_option_set_default_siglevel(&config.siglevel);

    config.localfilesiglevel = merge_siglevel(
        config.siglevel,
        config.localfilesiglevel,
        config.localfilesiglevel_mask,
    );
    config.remotefilesiglevel = merge_siglevel(
        config.siglevel,
        config.remotefilesiglevel,
        config.remotefilesiglevel_mask,
    );

    handle.alpm_option_set_local_file_siglevel(config.localfilesiglevel)?;

    handle.alpm_option_set_remote_file_siglevel(config.remotefilesiglevel);

    for mut data in &mut config.repos {
        register_repo(&mut data, &mut handle, config.siglevel, &config.arch);
    }

    // if config.xfercommand!="" {
    //     alpm_option_set_fetchcb(handle, download_with_xfercommand);
    // } else if !(alpm_capabilities().ALPM_CAPABILITY_DOWNLOADER) {
    //     // pm_printf(ALPM_LOG_WARNING, _("no '{}' configured\n"), "XferCommand");
    // }

    // if config.totaldownload {
    //     alpm_option_set_totaldlcb(handle, cb_dl_total);
    // }

    handle.alpm_option_set_arch(&config.arch);

    handle.alpm_option_set_checkspace(config.checkspace as i32);

    handle.alpm_option_set_usesyslog(config.usesyslog as i32);
    handle.alpm_option_set_deltaratio(config.deltaratio)?;
    handle.alpm_option_set_ignorepkgs(&config.ignorepkg);

    handle.alpm_option_set_ignoregroups(&config.ignoregrp);
    handle.alpm_option_set_noupgrades(&config.noupgrade);
    handle.alpm_option_set_noextracts(&config.noextract);

    handle.alpm_option_set_disable_dl_timeout(config.disable_dl_timeout as u16);

    for entry in &config.assumeinstalled {
        let dep = alpm_dep_from_string(&entry);
        debug!("parsed assume installed: {} {}", dep.name, dep.version,);
        handle.alpm_option_add_assumeinstalled(&dep);
    }

    Ok(handle)
}

/// Allows parsing in advance of an entire config section before we start
/// calling library methods.
#[derive(Default, Debug)]
pub struct Section {
    name: String,
    repo: Option<ConfigRepo>,
    depth: i32,
}

fn process_usage(
    values: &Vec<String>,
    usage: &mut DatabaseUsage,
    file: &String,
    linenum: i32,
) -> std::result::Result<(), ()> {
    let mut level = *usage;
    let mut ret = Ok(());

    for key in values {
        if key == "Sync" {
            level.sync = true;
        } else if key == "Search" {
            level.search = true;
        } else if key == "Install" {
            level.install = true;
        } else if key == "Upgrade" {
            level.upgrade = true;
        } else if key == "All" {
            level.all = true;
        } else {
            error!(
                "config file {}, line {}: '{}' option '{}' not recognized",
                file, linenum, "Usage", key
            );
            ret = Err(());
        }
    }
    if ret.is_ok() {
        *usage = level;
    }
    ret
}

fn _parse_repo(
    key: &Option<String>,
    value: &Option<String>,
    file: &String,
    line: i32,
    section: &mut Section,
) -> i32 {
    let mut ret = 0;
    // 	ConfigRepo *repo = section.repo;
    match (&mut section.repo, key) {
        (&mut Some(ref mut repo), &Some(ref key)) => {
            if key == "Server" {
                match value {
                    &None => {
                        eprintln!(
                            "config file {}, line {}: directive '{}' needs a value",
                            file, line, key
                        );
                        ret = 1;
                    }
                    &Some(ref value) => {
                        repo.servers.push(value.clone());
                    }
                }
            } else if key == "SigLevel" {
                match value {
                    &None => {
                        eprintln!(
                            "config file {}, line {}: directive '{}' needs a value",
                            file, line, key,
                        );
                    }
                    &Some(ref value) => {
                        // alpm_list_t *values = NULL;
                        let mut values = Vec::new();
                        setrepeatingoption(value, "SigLevel", &mut values);
                        if !values.is_empty() {
                            ret = process_siglevel(
                                values,
                                &mut repo.siglevel,
                                &mut repo.siglevel_mask,
                                file,
                                line,
                            );
                            // FREELIST(values);
                        }
                    }
                }
            } else if key == "Usage" {
                // alpm_list_t *values = NULL;
                match value {
                    &Some(ref value) => {
                        let mut values = Vec::new();
                        setrepeatingoption(&value, "Usage", &mut values);
                        if !values.is_empty() {
                            if process_usage(&values, &mut repo.usage, file, line).is_ok() {
                                // FREELIST(values);
                                return 1;
                            }
                            // FREELIST(values);
                        }
                    }
                    &None => panic!(),
                }
            } else {
                warn!(
                    "config file {}, line {}: directive '{}' in section '{}' not recognized.",
                    file, line, key, repo.name,
                );
            }
        }
        (_, _) => panic!("Should not get here"),
    }
    return ret;
}

fn process_include(
    value: &Option<String>,
    section: &mut Section,
    file: &String,
    linenum: i32,
    config: &mut Config,
) -> i32 {
    let globret;
    let mut ret = 0;
    let config_max_recursion = 10;

    match value {
        &None => {
            eprintln!(
                "config file {}, line {}: directive '{}' needs a value",
                file, linenum, "Include"
            );
            return 1;
        }
        &Some(ref value) => {
            if section.depth >= config_max_recursion {
                eprintln!(
                    "config parsing exceeded max recursion depth of {}.",
                    config_max_recursion
                );
                return 1;
            }

            section.depth += 1;

            /* Ignore include failures... assume non-critical */
            globret = glob::glob(&value);
            // match globret {
            //     GLOB_NOSPACE => eprintln!(
            //         "config file {}, line {}: include globbing out of space",
            //         file, linenum,
            //     ),
            //     GLOB_ABORTED => eprintln!(
            //         "config file {}, line {}: include globbing read error for {}",
            //         file, linenum, value
            //     ),
            //     GLOB_NOMATCH => eprintln!(
            //         "config file {}, line {}: no include found for {}",
            //         file, linenum, value
            //     ),
            //     _ => {
            //         // for(gindex = 0; gindex < globbuf.gl_pathc; gindex++) {
            //         // 	debug!( "config file {}, line {}: including {}\n",
            //         // 			file, linenum, globbuf.gl_pathv[gindex]);
            //         // 	ret = parse_ini(globbuf.gl_pathv[gindex], _parse_directive, data);
            //         // 	if(ret) {
            //         // 		goto cleanup;
            //         // 	}
            //         // }
            //     }
            // }
            match globret {
                Ok(items) => {
                    for item in items {
                        let item = item.unwrap().into_os_string().into_string().unwrap();
                        debug!(
                            "config file {}, line {}: including {}",
                            file, linenum, &item
                        );
                        // println!("{:?}", item);
                        ret = parse_ini(&item, &_parse_directive, section, config);
                        if ret != 0 {
                            section.depth -= 1;
                            return ret;
                        }
                    }
                }
                Err(_) => unimplemented!(),
            }
        }
    }

    // cleanup:
    section.depth -= 1;
    return ret;
}

fn _parse_directive(
    file: &String,
    linenum: i32,
    name: &String,
    key: &Option<String>,
    value: &Option<String>,
    section: &mut Section,
    config: &mut Config,
) -> i32 {
    match (key, value) {
        (&None, &None) => {
            section.name = name.clone();
            debug!("config: new section '{}'", name);
            if name == "options" {
                section.repo = None;
            } else {
                let mut repo = ConfigRepo::default();
                repo.name = name.clone();
                repo.siglevel.use_default = true;
                section.repo = Some(repo.clone());
                config.repos.push(repo);
            }
            return 0;
        }
        _ => {}
    }

    match key {
        &Some(ref k) => if k == "Include" {
            return process_include(value, section, &file, linenum, config);
        },
        &None => {}
    }

    if section.name == "" {
        eprintln!(
            "config file {}, line {}: All directives must belong to a section.",
            file, linenum
        );
        return 1;
    }

    if section.repo.is_none() {
        /* we are either in options ... */
        return _parse_options(key, value, file, linenum, config);
    } else {
        return _parse_repo(key, value, file, linenum, section);
    }
    // return 1;
}

/// Parse a configuration file.
///
/// - `file` - path to the config file
/// - `returns` - 0 on success, non-zero on error
pub fn parseconfig(file: &String, config: &mut Config) -> Result<Handle> {
    let ret;
    let handle;
    let mut section = Section::default();
    debug!("config: attempting to read file {}", file);
    ret = parse_ini(file, &_parse_directive, &mut section, config);
    if ret != 0 {
        unimplemented!();
        //should be error
        // return Ok(ret);
    }
    debug!("config: finished parsing {}", file);
    handle = setup_libalpm(config)?;
    return Ok(handle);
}
