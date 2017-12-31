use pacman::alpm::*;
use pacman::cleanup;
use getopts;
// /*
//  *  conf.h
//  *
//  *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
//  *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
//  *
//  *  This program is free software; you can redistribute it and/or modify
//  *  it under the terms of the GNU General Public License as published by
//  *  the Free Software Foundation; either version 2 of the License, or
//  *  (at your option) any later version.
//  *
//  *  This program is distributed in the hope that it will be useful,
//  *  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  *  GNU General Public License for more details.
//  *
//  *  You should have received a copy of the GNU General Public License
//  *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//  */
// #ifndef PM_CONF_H
// #define PM_CONF_H
//
// #include <alpm.h>
//
#[derive(Default, Debug)]
pub struct colstr_t {
    colon: String,
    title: String,
    repo: String,
    version: String,
    groups: String,
    meta: String,
    warn: String,
    err: String,
    nocolor: String,
}
//
// typedef struct __config_repo_t {
// 	char *name;
// 	alpm_list_t *servers;
// 	int usage;
// 	int siglevel;
// 	int siglevel_mask;
// } config_repo_t;
//
use super::alpm;
#[derive(Default, Debug)]
pub struct config_t {
    pub op: Option<operations>,
    pub quiet: bool,
    pub verbose: u8,
    pub version: bool,
    pub help: bool,
    pub noconfirm: bool,
    pub noprogressbar: u8,
    pub logmask: alpm::loglevel,
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
    pub hookdirs: alpm_list_t,
    pub cachedirs: alpm_list_t,

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
    pub flags: alpm::alpm_transflag_t,
    pub siglevel: i64,
    pub localfilesiglevel: i64,
    pub remotefilesiglevel: i64,

    pub siglevel_mask: i64,
    pub localfilesiglevel_mask: i64,
    pub remotefilesiglevel_mask: i64,

    /* conf file options */
    /* I Love Candy! */
    pub chomp: u8,
    pub verbosepkglists: u8,
    /* When downloading, display the amount downloaded, rate, ETA, and percent
     * downloaded of the total download list */
    pub totaldownload: u8,
    pub cleanmethod: u8,
    pub holdpkg: alpm_list_t,
    pub ignorepkg: alpm_list_t,
    pub ignoregrp: alpm_list_t,
    pub assumeinstalled: alpm_list_t,
    pub noupgrade: alpm_list_t,
    pub noextract: alpm_list_t,
    pub overwrite_files: alpm_list_t,
    pub xfercommand: String,

    /* our connection to libalpm */
    pub handle: alpm_handle_t,

    pub explicit_adds: alpm_list_t,
    pub explicit_removes: alpm_list_t,

    /* Color strings for output */
    pub colstr: colstr_t,

    pub repos: alpm_list_t,
}


//
// /* Operations */
#[derive(Debug)]
pub enum operations {
    PM_OP_MAIN = 1,
    PM_OP_REMOVE,
    PM_OP_UPGRADE,
    PM_OP_QUERY,
    PM_OP_SYNC,
    PM_OP_DEPTEST,
    PM_OP_DATABASE,
    PM_OP_FILES,
}
// /* clean method */
// enum {
// 	PM_CLEAN_KEEPINST = 1,
// 	PM_CLEAN_KEEPCUR = (1 << 1)
// };
//
/** package locality */

pub static PKG_LOCALITY_UNSET: u8 = 0;
pub static PKG_LOCALITY_NATIVE: u8 = (1 << 0);
pub static PKG_LOCALITY_FOREIGN: u8 = (1 << 1);

//
// enum {
// 	PM_COLOR_UNSET = 0,
// 	PM_COLOR_OFF,
// 	PM_COLOR_ON
// };
//
// /* global config variable */
// extern config_t *config;
//
// void enable_colors(int colors);
// config_t *config_new(void);
// int config_free(config_t *oldconfig);
//
// void config_repo_free(config_repo_t *repo);
//
// int config_set_arch(const char *arch);
// int parseconfig(const char *file);
// #endif /* PM_CONF_H */
//
// /* vim: set noet: */

/*
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

fn invalid_opt(used: bool, _opt1: &str, _opt2: &str) {
    if used {
        unimplemented!();
        // pm_printf(ALPM_LOG_ERROR,
        // 		_("invalid option: '%s' and '%s' may not be used together\n"),
        // 		opt1, opt2);
        cleanup(1);
    }
}

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
//
// /* global config variable */
// config_t *config = NULL;
//
// #define NOCOLOR       "\033[0m"
//
// #define BOLD          "\033[0;1m"
//
// #define BLACK         "\033[0;30m"
// #define RED           "\033[0;31m"
// #define GREEN         "\033[0;32m"
// #define YELLOW        "\033[0;33m"
// #define BLUE          "\033[0;34m"
// #define MAGENTA       "\033[0;35m"
// #define CYAN          "\033[0;36m"
// #define WHITE         "\033[0;37m"
//
// #define BOLDBLACK     "\033[1;30m"
// #define BOLDRED       "\033[1;31m"
// #define BOLDGREEN     "\033[1;32m"
// #define BOLDYELLOW    "\033[1;33m"
// #define BOLDBLUE      "\033[1;34m"
// #define BOLDMAGENTA   "\033[1;35m"
// #define BOLDCYAN      "\033[1;36m"
// #define BOLDWHITE     "\033[1;37m"
//
// void enable_colors(int colors)
// {
// 	colstr_t *colstr = &config->colstr;
//
// 	if(colors == PM_COLOR_ON) {
// 		colstr->colon   = BOLDBLUE "::" BOLD " ";
// 		colstr->title   = BOLD;
// 		colstr->repo    = BOLDMAGENTA;
// 		colstr->version = BOLDGREEN;
// 		colstr->groups  = BOLDBLUE;
// 		colstr->meta    = BOLDCYAN;
// 		colstr->warn    = BOLDYELLOW;
// 		colstr->err     = BOLDRED;
// 		colstr->nocolor = NOCOLOR;
// 	} else {
// 		colstr->colon   = ":: ";
// 		colstr->title   = "";
// 		colstr->repo    = "";
// 		colstr->version = "";
// 		colstr->groups  = "";
// 		colstr->meta    = "";
// 		colstr->warn    = "";
// 		colstr->err     = "";
// 		colstr->nocolor = "";
// 	}
// }
//
impl config_t {
    pub fn new() -> config_t {
        let mut newconfig = config_t::default();

        /* defaults which may get overridden later */
        newconfig.op = Some(operations::PM_OP_MAIN);
        newconfig.logmask.ALPM_LOG_ERROR = true;
        newconfig.logmask.ALPM_LOG_WARNING = true;
        // newconfig.configfile = strdup(CONFFILE);//TODO: implement this
        newconfig.deltaratio = 0.0;
        //TODO: implement this
        // if(alpm_capabilities() & ALPM_CAPABILITY_SIGNATURES) {
        // 	newconfig.siglevel = ALPM_SIG_PACKAGE | ALPM_SIG_PACKAGE_OPTIONAL |
        // 		ALPM_SIG_DATABASE | ALPM_SIG_DATABASE_OPTIONAL;
        // 	newconfig.localfilesiglevel = ALPM_SIG_USE_DEFAULT;
        // 	newconfig.remotefilesiglevel = ALPM_SIG_USE_DEFAULT;
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
        use pacman::conf::operations::*;
        match self.op {
            Some(PM_OP_DATABASE) => return self.op_q_check == 0,
            Some(PM_OP_UPGRADE) | Some(PM_OP_REMOVE) => return self.print,
            Some(PM_OP_SYNC) => {
                return self.op_s_clean != 0 || self.op_s_sync != 0
                    || (self.group == 0 && self.op_s_info == 0 && self.op_q_list == 0
                        && self.op_s_search == 0 && self.print)
            }

            Some(PM_OP_FILES) => return self.op_s_sync != 0,
            _ => return false,
        }
    }


    /** Parse command-line arguments for each operation.
     * @param argc argc
     * @param argv argv
     * @return 0 on success, 1 on error
     */
    pub fn parseargs(&mut self, argv: Vec<String>) -> Result<Vec<String>, ()> {
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
            opts.optflag("H", "--help", "");

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

        use self::operations::*;
        match &self.op {
            &Some(PM_OP_DATABASE) => {
                self.parsearg_database(&matches);
                self.checkargs_database();
            }
            &Some(PM_OP_QUERY) => {
                self.parsearg_query(&matches);
                self.checkargs_query();
            }
            &Some(PM_OP_REMOVE) => {
                self.parsearg_remove(&matches);
                self.checkargs_remove();
            }
            &Some(PM_OP_SYNC) => {
                self.parsearg_sync(&matches);
                self.checkargs_sync();
            }
            &Some(PM_OP_UPGRADE) => {
                self.parsearg_upgrade(&matches);
                self.checkargs_upgrade();
            }
            &Some(PM_OP_FILES) => {
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
    // fn parsearg_op(int opt, int dryrun) -> i64
    fn parsearg_op(&mut self, opts: &getopts::Matches) -> i64 {
        use self::operations::*;
        /* operations */
        if opts.opt_present("D") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(PM_OP_MAIN) => Some(PM_OP_DATABASE),
                _ => None,
            }
        } else if opts.opt_present("F") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(PM_OP_MAIN) => Some(PM_OP_FILES),
                _ => None,
            };
        } else if opts.opt_present("Q") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(PM_OP_MAIN) => Some(PM_OP_QUERY),
                _ => None,
            };
        } else if opts.opt_present("R") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(PM_OP_MAIN) => Some(PM_OP_REMOVE),
                _ => None,
            };
        } else if opts.opt_present("S") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(PM_OP_MAIN) => Some(PM_OP_SYNC),
                _ => None,
            };
        } else if opts.opt_present("T") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(PM_OP_MAIN) => Some(PM_OP_DEPTEST),
                _ => None,
            };
        } else if opts.opt_present("U") {
            //if(dryrun) break;
            self.op = match self.op {
                Some(PM_OP_MAIN) => Some(operations::PM_OP_UPGRADE),
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
                // pm_printf(ALPM_LOG_ERROR, _("invalid argument '%s' for %s\n"),
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
                            self.logmask.ALPM_LOG_FUNCTION = true; /* fall through */
                            self.logmask.ALPM_LOG_DEBUG = true;
                        }
                        1 => self.logmask.ALPM_LOG_DEBUG = true,
                        _ => {
                            unimplemented!();
                            // pm_printf(ALPM_LOG_ERROR, _("'%s' is not a valid debug level\n"),
                            // optarg);
                            return 1;
                        }
                    }
                }
                None => {
                    self.logmask.ALPM_LOG_DEBUG = true;
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
            self.flags.ALLDEPS = true;
        }
        if opts.opt_present("asexplicit") {
            self.flags.ALLEXPLICIT = true;
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
            self.flags.ALLDEPS && self.flags.ALLEXPLICIT,
            "--asdeps",
            "--asexplicit",
        );

        if self.op_q_check != 0 {
            invalid_opt(self.flags.ALLDEPS, "--asdeps", "--check");
            invalid_opt(self.flags.ALLEXPLICIT, "--asexplicit", "--check");
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
            if self.flags.NODEPVERSION {
                self.flags.NODEPS = true;
            } else {
                self.flags.NODEPVERSION = true;
            }
        }
        if opts.opt_present("dbonly") {
            self.flags.DBONLY = true;
            self.flags.NOSCRIPTLET = true;
        }
        if opts.opt_present("noprogressbar") {
            self.noprogressbar = 1;
        }
        if opts.opt_present("noscriptlet") {
            self.flags.NOSCRIPTLET = true;
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
            invalid_opt(self.flags.DBONLY, "--print", "--dbonly");
            invalid_opt(self.flags.NOSCRIPTLET, "--print", "--noscriptlet");
        }
    }

    fn parsearg_remove(&mut self, opts: &getopts::Matches) {
        self.parsearg_trans(opts);

        if opts.opt_present("cascade") {
            self.flags.CASCADE = true;
        }
        if opts.opt_present("nosave") {
            self.flags.NOSAVE = true;
        }
        if opts.opt_present("recursive") {
            if self.flags.RECURSE {
                self.flags.RECURSEALL = true;
            } else {
                self.flags.RECURSE = true;
            }
        }
        if opts.opt_present("unneeded") {
            self.flags.UNNEEDED = true;
        }
    }

    fn checkargs_remove(&mut self) {
        self.checkargs_trans();
        if self.flags.NOSAVE {
            invalid_opt(self.print, "--nosave", "--print");
            invalid_opt(self.flags.DBONLY, "--nosave", "--dbonly");
        }
    }

    /* options common to -S -U */
    fn parsearg_upgrade(&mut self, opts: &getopts::Matches) {
        self.parsearg_trans(opts);


        if opts.opt_present("force") {
            self.flags.FORCE = true;
        }
        if opts.opt_present("overwrite") {
            unimplemented!();
            // parsearg_util_addlist(&(self.overwrite_files));
        }
        if opts.opt_present("asdeps") {
            self.flags.ALLDEPS = true;
        }
        if opts.opt_present("asexplicit") {
            self.flags.ALLEXPLICIT = true;
        }
        if opts.opt_present("needed") {
            self.flags.NEEDED = true;
        }
    }

    fn checkargs_upgrade(&mut self) {
        self.checkargs_trans();
        invalid_opt(
            self.flags.ALLDEPS && self.flags.ALLEXPLICIT,
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
        if opts.opt_present("sysupgrade") {
            self.op_s_upgrade = opts.opt_count("sysupgrade") as u8;
        }
        if opts.opt_present("downloadonly") {
            self.op_s_downloadonly = 1;
            self.flags.DOWNLOADONLY = true;
            self.flags.NOCONFLICTS = true;
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

// int config_free(config_t *oldconfig)
// {
// 	if(oldconfig == NULL) {
// 		return -1;
// 	}
//
// 	alpm_list_free(oldconfig->explicit_adds);
// 	alpm_list_free(oldconfig->explicit_removes);
//
// 	alpm_list_free_inner(config->repos, (alpm_list_fn_free) config_repo_free);
// 	alpm_list_free(config->repos);
//
// 	FREELIST(oldconfig->holdpkg);
// 	FREELIST(oldconfig->ignorepkg);
// 	FREELIST(oldconfig->ignoregrp);
// 	FREELIST(oldconfig->assumeinstalled);
// 	FREELIST(oldconfig->noupgrade);
// 	FREELIST(oldconfig->noextract);
// 	FREELIST(oldconfig->overwrite_files);
// 	free(oldconfig->configfile);
// 	free(oldconfig->rootdir);
// 	free(oldconfig->dbpath);
// 	free(oldconfig->logfile);
// 	free(oldconfig->gpgdir);
// 	FREELIST(oldconfig->hookdirs);
// 	FREELIST(oldconfig->cachedirs);
// 	free(oldconfig->xfercommand);
// 	free(oldconfig->print_format);
// 	free(oldconfig->arch);
// 	free(oldconfig);
//
// 	return 0;
// }
//
// void config_repo_free(config_repo_t *repo)
// {
// 	if(repo == NULL) {
// 		return;
// 	}
// 	free(repo->name);
// 	FREELIST(repo->servers);
// 	free(repo);
// }
//
// /** Helper function for download_with_xfercommand() */
// static char *get_filename(const char *url)
// {
// 	char *filename = strrchr(url, '/');
// 	if(filename != NULL) {
// 		filename++;
// 	}
// 	return filename;
// }
//
// /** Helper function for download_with_xfercommand() */
// static char *get_destfile(const char *path, const char *filename)
// {
// 	char *destfile;
// 	/* len = localpath len + filename len + null */
// 	size_t len = strlen(path) + strlen(filename) + 1;
// 	destfile = calloc(len, sizeof(char));
// 	snprintf(destfile, len, "%s%s", path, filename);
//
// 	return destfile;
// }
//
// /** Helper function for download_with_xfercommand() */
// static char *get_tempfile(const char *path, const char *filename)
// {
// 	char *tempfile;
// 	/* len = localpath len + filename len + '.part' len + null */
// 	size_t len = strlen(path) + strlen(filename) + 6;
// 	tempfile = calloc(len, sizeof(char));
// 	snprintf(tempfile, len, "%s%s.part", path, filename);
//
// 	return tempfile;
// }
//
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
// 	if(!config->xfercommand) {
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
// 	tempcmd = strdup(config->xfercommand);
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
// 		pm_printf(ALPM_LOG_WARNING, _("could not chdir to download directory %s\n"), localpath);
// 		ret = -1;
// 		goto cleanup;
// 	}
// 	/* execute the parsed command via /bin/sh -c */
// 	pm_printf(ALPM_LOG_DEBUG, "running command: %s\n", parsedcmd);
// 	retval = system(parsedcmd);
//
// 	if(retval == -1) {
// 		pm_printf(ALPM_LOG_WARNING, _("running XferCommand: fork failed!\n"));
// 		ret = -1;
// 	} else if(retval != 0) {
// 		/* download failed */
// 		pm_printf(ALPM_LOG_DEBUG, "XferCommand command returned non-zero status "
// 				"code (%d)\n", retval);
// 		ret = -1;
// 	} else {
// 		/* download was successful */
// 		ret = 0;
// 		if(usepart) {
// 			if(rename(tempfile, destfile)) {
// 				pm_printf(ALPM_LOG_ERROR, _("could not rename %s to %s (%s)\n"),
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
// 			pm_printf(ALPM_LOG_ERROR, _("could not restore working directory (%s)\n"),
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
//
//
// int config_set_arch(const char *arch)
// {
// 	if(strcmp(arch, "auto") == 0) {
// 		struct utsname un;
// 		uname(&un);
// 		config->arch = strdup(un.machine);
// 	} else {
// 		config->arch = strdup(arch);
// 	}
// 	pm_printf(ALPM_LOG_DEBUG, "config: arch: %s\n", config->arch);
// 	return 0;
// }
//
// /**
//  * Parse a signature verification level line.
//  * @param values the list of parsed option values
//  * @param storage location to store the derived signature level; any existing
//  * value here is used as a starting point
//  * @param file path to the config file
//  * @param linenum current line number in file
//  * @return 0 on success, 1 on any parsing error
//  */
// static int process_siglevel(alpm_list_t *values, int *storage,
// 		int *storage_mask, const char *file, int linenum)
// {
// 	int level = *storage, mask = *storage_mask;
// 	alpm_list_t *i;
// 	int ret = 0;
//
// #define SLSET(sl) do { level |= (sl); mask |= (sl); } while(0)
// #define SLUNSET(sl) do { level &= ~(sl); mask |= (sl); } while(0)
//
// 	/* Collapse the option names into a single bitmasked value */
// 	for(i = values; i; i = alpm_list_next(i)) {
// 		const char *original = i->data, *value;
// 		int package = 0, database = 0;
//
// 		if(strncmp(original, "Package", strlen("Package")) == 0) {
// 			/* only packages are affected, don't flip flags for databases */
// 			value = original + strlen("Package");
// 			package = 1;
// 		} else if(strncmp(original, "Database", strlen("Database")) == 0) {
// 			/* only databases are affected, don't flip flags for packages */
// 			value = original + strlen("Database");
// 			database = 1;
// 		} else {
// 			/* no prefix, so anything found will affect both packages and dbs */
// 			value = original;
// 			package = database = 1;
// 		}
//
// 		/* now parse out and store actual flag if it is valid */
// 		if(strcmp(value, "Never") == 0) {
// 			if(package) {
// 				SLUNSET(ALPM_SIG_PACKAGE);
// 			}
// 			if(database) {
// 				SLUNSET(ALPM_SIG_DATABASE);
// 			}
// 		} else if(strcmp(value, "Optional") == 0) {
// 			if(package) {
// 				SLSET(ALPM_SIG_PACKAGE | ALPM_SIG_PACKAGE_OPTIONAL);
// 			}
// 			if(database) {
// 				SLSET(ALPM_SIG_DATABASE | ALPM_SIG_DATABASE_OPTIONAL);
// 			}
// 		} else if(strcmp(value, "Required") == 0) {
// 			if(package) {
// 				SLSET(ALPM_SIG_PACKAGE);
// 				SLUNSET(ALPM_SIG_PACKAGE_OPTIONAL);
// 			}
// 			if(database) {
// 				SLSET(ALPM_SIG_DATABASE);
// 				SLUNSET(ALPM_SIG_DATABASE_OPTIONAL);
// 			}
// 		} else if(strcmp(value, "TrustedOnly") == 0) {
// 			if(package) {
// 				SLUNSET(ALPM_SIG_PACKAGE_MARGINAL_OK | ALPM_SIG_PACKAGE_UNKNOWN_OK);
// 			}
// 			if(database) {
// 				SLUNSET(ALPM_SIG_DATABASE_MARGINAL_OK | ALPM_SIG_DATABASE_UNKNOWN_OK);
// 			}
// 		} else if(strcmp(value, "TrustAll") == 0) {
// 			if(package) {
// 				SLSET(ALPM_SIG_PACKAGE_MARGINAL_OK | ALPM_SIG_PACKAGE_UNKNOWN_OK);
// 			}
// 			if(database) {
// 				SLSET(ALPM_SIG_DATABASE_MARGINAL_OK | ALPM_SIG_DATABASE_UNKNOWN_OK);
// 			}
// 		} else {
// 			pm_printf(ALPM_LOG_ERROR,
// 					_("config file %s, line %d: invalid value for '%s' : '%s'\n"),
// 					file, linenum, "SigLevel", original);
// 			ret = 1;
// 		}
// 		level &= ~ALPM_SIG_USE_DEFAULT;
// 	}
//
// #undef SLSET
// #undef SLUNSET
//
// 	/* ensure we have sig checking ability and are actually turning it on */
// 	if(!(alpm_capabilities() & ALPM_CAPABILITY_SIGNATURES) &&
// 			level & (ALPM_SIG_PACKAGE | ALPM_SIG_DATABASE)) {
// 		pm_printf(ALPM_LOG_ERROR,
// 				_("config file %s, line %d: '%s' option invalid, no signature support\n"),
// 				file, linenum, "SigLevel");
// 		ret = 1;
// 	}
//
// 	if(!ret) {
// 		*storage = level;
// 		*storage_mask = mask;
// 	}
// 	return ret;
// }
//
// /**
//  * Merge the package entries of two signature verification levels.
//  * @param base initial siglevel
//  * @param over overriding siglevel
//  * @return merged siglevel
//  */
// static int merge_siglevel(int base, int over, int mask)
// {
// 	return mask ? (over & mask) | (base & ~mask) : over;
// }
//
// static int process_cleanmethods(alpm_list_t *values,
// 		const char *file, int linenum)
// {
// 	alpm_list_t *i;
// 	for(i = values; i; i = alpm_list_next(i)) {
// 		const char *value = i->data;
// 		if(strcmp(value, "KeepInstalled") == 0) {
// 			config->cleanmethod |= PM_CLEAN_KEEPINST;
// 		} else if(strcmp(value, "KeepCurrent") == 0) {
// 			config->cleanmethod |= PM_CLEAN_KEEPCUR;
// 		} else {
// 			pm_printf(ALPM_LOG_ERROR,
// 					_("config file %s, line %d: invalid value for '%s' : '%s'\n"),
// 					file, linenum, "CleanMethod", value);
// 			return 1;
// 		}
// 	}
// 	return 0;
// }
//
// /** Add repeating options such as NoExtract, NoUpgrade, etc to libalpm
//  * settings. Refactored out of the parseconfig code since all of them did
//  * the exact same thing and duplicated code.
//  * @param ptr a pointer to the start of the multiple options
//  * @param option the string (friendly) name of the option, used for messages
//  * @param list the list to add the option to
//  */
// static void setrepeatingoption(char *ptr, const char *option,
// 		alpm_list_t **list)
// {
// 	char *val, *saveptr = NULL;
//
// 	val = strtok_r(ptr, " ", &saveptr);
// 	while(val) {
// 		*list = alpm_list_add(*list, strdup(val));
// 		pm_printf(ALPM_LOG_DEBUG, "config: %s: %s\n", option, val);
// 		val = strtok_r(NULL, " ", &saveptr);
// 	}
// }
//
// static int _parse_options(const char *key, char *value,
// 		const char *file, int linenum)
// {
// 	if(value == NULL) {
// 		/* options without settings */
// 		if(strcmp(key, "UseSyslog") == 0) {
// 			config->usesyslog = 1;
// 			pm_printf(ALPM_LOG_DEBUG, "config: usesyslog\n");
// 		} else if(strcmp(key, "ILoveCandy") == 0) {
// 			config->chomp = 1;
// 			pm_printf(ALPM_LOG_DEBUG, "config: chomp\n");
// 		} else if(strcmp(key, "VerbosePkgLists") == 0) {
// 			config->verbosepkglists = 1;
// 			pm_printf(ALPM_LOG_DEBUG, "config: verbosepkglists\n");
// 		} else if(strcmp(key, "UseDelta") == 0) {
// 			config->deltaratio = 0.7;
// 			pm_printf(ALPM_LOG_DEBUG, "config: usedelta (default 0.7)\n");
// 		} else if(strcmp(key, "TotalDownload") == 0) {
// 			config->totaldownload = 1;
// 			pm_printf(ALPM_LOG_DEBUG, "config: totaldownload\n");
// 		} else if(strcmp(key, "CheckSpace") == 0) {
// 			config->checkspace = 1;
// 		} else if(strcmp(key, "Color") == 0) {
// 			if(config->color == PM_COLOR_UNSET) {
// 				config->color = isatty(fileno(stdout)) ? PM_COLOR_ON : PM_COLOR_OFF;
// 				enable_colors(config->color);
// 			}
// 		} else if(strcmp(key, "DisableDownloadTimeout") == 0) {
// 			config->disable_dl_timeout = 1;
// 		} else {
// 			pm_printf(ALPM_LOG_WARNING,
// 					_("config file %s, line %d: directive '%s' in section '%s' not recognized.\n"),
// 					file, linenum, key, "options");
// 		}
// 	} else {
// 		/* options with settings */
// 		if(strcmp(key, "NoUpgrade") == 0) {
// 			setrepeatingoption(value, "NoUpgrade", &(config->noupgrade));
// 		} else if(strcmp(key, "NoExtract") == 0) {
// 			setrepeatingoption(value, "NoExtract", &(config->noextract));
// 		} else if(strcmp(key, "IgnorePkg") == 0) {
// 			setrepeatingoption(value, "IgnorePkg", &(config->ignorepkg));
// 		} else if(strcmp(key, "IgnoreGroup") == 0) {
// 			setrepeatingoption(value, "IgnoreGroup", &(config->ignoregrp));
// 		} else if(strcmp(key, "HoldPkg") == 0) {
// 			setrepeatingoption(value, "HoldPkg", &(config->holdpkg));
// 		} else if(strcmp(key, "CacheDir") == 0) {
// 			setrepeatingoption(value, "CacheDir", &(config->cachedirs));
// 		} else if(strcmp(key, "HookDir") == 0) {
// 			setrepeatingoption(value, "HookDir", &(config->hookdirs));
// 		} else if(strcmp(key, "Architecture") == 0) {
// 			if(!config->arch) {
// 				config_set_arch(value);
// 			}
// 		} else if(strcmp(key, "UseDelta") == 0) {
// 			double ratio;
// 			char *endptr;
// 			const char *oldlocale;
//
// 			/* set the locale to 'C' for consistent decimal parsing (0.7 and never
// 			 * 0,7) from config files, then restore old setting when we are done */
// 			oldlocale = setlocale(LC_NUMERIC, NULL);
// 			setlocale(LC_NUMERIC, "C");
// 			ratio = strtod(value, &endptr);
// 			setlocale(LC_NUMERIC, oldlocale);
//
// 			if(*endptr != '\0' || ratio < 0.0 || ratio > 2.0) {
// 				pm_printf(ALPM_LOG_ERROR,
// 						_("config file %s, line %d: invalid value for '%s' : '%s'\n"),
// 						file, linenum, "UseDelta", value);
// 				return 1;
// 			}
// 			config->deltaratio = ratio;
// 			pm_printf(ALPM_LOG_DEBUG, "config: usedelta = %f\n", ratio);
// 		} else if(strcmp(key, "DBPath") == 0) {
// 			/* don't overwrite a path specified on the command line */
// 			if(!config->dbpath) {
// 				config->dbpath = strdup(value);
// 				pm_printf(ALPM_LOG_DEBUG, "config: dbpath: %s\n", value);
// 			}
// 		} else if(strcmp(key, "RootDir") == 0) {
// 			/* don't overwrite a path specified on the command line */
// 			if(!config->rootdir) {
// 				config->rootdir = strdup(value);
// 				pm_printf(ALPM_LOG_DEBUG, "config: rootdir: %s\n", value);
// 			}
// 		} else if(strcmp(key, "GPGDir") == 0) {
// 			if(!config->gpgdir) {
// 				config->gpgdir = strdup(value);
// 				pm_printf(ALPM_LOG_DEBUG, "config: gpgdir: %s\n", value);
// 			}
// 		} else if(strcmp(key, "LogFile") == 0) {
// 			if(!config->logfile) {
// 				config->logfile = strdup(value);
// 				pm_printf(ALPM_LOG_DEBUG, "config: logfile: %s\n", value);
// 			}
// 		} else if(strcmp(key, "XferCommand") == 0) {
// 			config->xfercommand = strdup(value);
// 			pm_printf(ALPM_LOG_DEBUG, "config: xfercommand: %s\n", value);
// 		} else if(strcmp(key, "CleanMethod") == 0) {
// 			alpm_list_t *methods = NULL;
// 			setrepeatingoption(value, "CleanMethod", &methods);
// 			if(process_cleanmethods(methods, file, linenum)) {
// 				FREELIST(methods);
// 				return 1;
// 			}
// 			FREELIST(methods);
// 		} else if(strcmp(key, "SigLevel") == 0) {
// 			alpm_list_t *values = NULL;
// 			setrepeatingoption(value, "SigLevel", &values);
// 			if(process_siglevel(values, &config->siglevel,
// 						&config->siglevel_mask, file, linenum)) {
// 				FREELIST(values);
// 				return 1;
// 			}
// 			FREELIST(values);
// 		} else if(strcmp(key, "LocalFileSigLevel") == 0) {
// 			alpm_list_t *values = NULL;
// 			setrepeatingoption(value, "LocalFileSigLevel", &values);
// 			if(process_siglevel(values, &config->localfilesiglevel,
// 						&config->localfilesiglevel_mask, file, linenum)) {
// 				FREELIST(values);
// 				return 1;
// 			}
// 			FREELIST(values);
// 		} else if(strcmp(key, "RemoteFileSigLevel") == 0) {
// 			alpm_list_t *values = NULL;
// 			setrepeatingoption(value, "RemoteFileSigLevel", &values);
// 			if(process_siglevel(values, &config->remotefilesiglevel,
// 						&config->remotefilesiglevel_mask, file, linenum)) {
// 				FREELIST(values);
// 				return 1;
// 			}
// 			FREELIST(values);
// 		} else {
// 			pm_printf(ALPM_LOG_WARNING,
// 					_("config file %s, line %d: directive '%s' in section '%s' not recognized.\n"),
// 					file, linenum, key, "options");
// 		}
//
// 	}
// 	return 0;
// }
//
// static int _add_mirror(alpm_db_t *db, char *value)
// {
// 	const char *dbname = alpm_db_get_name(db);
// 	/* let's attempt a replacement for the current repo */
// 	char *temp = strreplace(value, "$repo", dbname);
// 	/* let's attempt a replacement for the arch */
// 	const char *arch = config->arch;
// 	char *server;
// 	if(arch) {
// 		server = strreplace(temp, "$arch", arch);
// 		free(temp);
// 	} else {
// 		if(strstr(temp, "$arch")) {
// 			free(temp);
// 			pm_printf(ALPM_LOG_ERROR,
// 					_("mirror '%s' contains the '%s' variable, but no '%s' is defined.\n"),
// 					value, "$arch", "Architecture");
// 			return 1;
// 		}
// 		server = temp;
// 	}
//
// 	if(alpm_db_add_server(db, server) != 0) {
// 		/* pm_errno is set by alpm_db_setserver */
// 		pm_printf(ALPM_LOG_ERROR, _("could not add server URL to database '%s': %s (%s)\n"),
// 				dbname, server, alpm_strerror(alpm_errno(config->handle)));
// 		free(server);
// 		return 1;
// 	}
//
// 	free(server);
// 	return 0;
// }
//
// static int register_repo(config_repo_t *repo)
// {
// 	alpm_list_t *i;
// 	alpm_db_t *db;
//
// 	repo->siglevel = merge_siglevel(config->siglevel,
// 			repo->siglevel, repo->siglevel_mask);
//
// 	db = alpm_register_syncdb(config->handle, repo->name, repo->siglevel);
// 	if(db == NULL) {
// 		pm_printf(ALPM_LOG_ERROR, _("could not register '%s' database (%s)\n"),
// 				repo->name, alpm_strerror(alpm_errno(config->handle)));
// 		return 1;
// 	}
//
// 	pm_printf(ALPM_LOG_DEBUG,
// 			"setting usage of %d for %s repository\n",
// 			repo->usage == 0 ? ALPM_DB_USAGE_ALL : repo->usage,
// 			repo->name);
// 	alpm_db_set_usage(db, repo->usage == 0 ? ALPM_DB_USAGE_ALL : repo->usage);
//
// 	for(i = repo->servers; i; i = alpm_list_next(i)) {
// 		char *value = i->data;
// 		if(_add_mirror(db, value) != 0) {
// 			pm_printf(ALPM_LOG_ERROR,
// 					_("could not add mirror '%s' to database '%s' (%s)\n"),
// 					value, repo->name, alpm_strerror(alpm_errno(config->handle)));
// 			return 1;
// 		}
// 	}
//
// 	return 0;
// }
//
// /** Sets up libalpm global stuff in one go. Called after the command line
//  * and initial config file parsing. Once this is complete, we can see if any
//  * paths were defined. If a rootdir was defined and nothing else, we want all
//  * of our paths to live under the rootdir that was specified. Safe to call
//  * multiple times (will only do anything the first time).
//  */
// static int setup_libalpm(void)
// {
// 	int ret = 0;
// 	alpm_errno_t err;
// 	alpm_handle_t *handle;
// 	alpm_list_t *i;
//
// 	pm_printf(ALPM_LOG_DEBUG, "setup_libalpm called\n");
//
// 	/* Configure root path first. If it is set and dbpath/logfile were not
// 	 * set, then set those as well to reside under the root. */
// 	if(config->rootdir) {
// 		char path[PATH_MAX];
// 		if(!config->dbpath) {
// 			snprintf(path, PATH_MAX, "%s/%s", config->rootdir, DBPATH + 1);
// 			config->dbpath = strdup(path);
// 		}
// 		if(!config->logfile) {
// 			snprintf(path, PATH_MAX, "%s/%s", config->rootdir, LOGFILE + 1);
// 			config->logfile = strdup(path);
// 		}
// 	} else {
// 		config->rootdir = strdup(ROOTDIR);
// 		if(!config->dbpath) {
// 			config->dbpath = strdup(DBPATH);
// 		}
// 	}
//
// 	/* initialize library */
// 	handle = alpm_initialize(config->rootdir, config->dbpath, &err);
// 	if(!handle) {
// 		pm_printf(ALPM_LOG_ERROR, _("failed to initialize alpm library\n(%s: %s)\n"),
// 		        alpm_strerror(err), config->dbpath);
// 		if(err == ALPM_ERR_DB_VERSION) {
// 			fprintf(stderr, _("try running pacman-db-upgrade\n"));
// 		}
// 		return -1;
// 	}
// 	config->handle = handle;
//
// 	alpm_option_set_logcb(handle, cb_log);
// 	alpm_option_set_dlcb(handle, cb_dl_progress);
// 	alpm_option_set_eventcb(handle, cb_event);
// 	alpm_option_set_questioncb(handle, cb_question);
// 	alpm_option_set_progresscb(handle, cb_progress);
//
// 	if(config->op == PM_OP_FILES) {
// 		alpm_option_set_dbext(handle, ".files");
// 	}
//
// 	config->logfile = config->logfile ? config->logfile : strdup(LOGFILE);
// 	ret = alpm_option_set_logfile(handle, config->logfile);
// 	if(ret != 0) {
// 		pm_printf(ALPM_LOG_ERROR, _("problem setting logfile '%s' (%s)\n"),
// 				config->logfile, alpm_strerror(alpm_errno(handle)));
// 		return ret;
// 	}
//
// 	/* Set GnuPG's home directory. This is not relative to rootdir, even if
// 	 * rootdir is defined. Reasoning: gpgdir contains configuration data. */
// 	config->gpgdir = config->gpgdir ? config->gpgdir : strdup(GPGDIR);
// 	ret = alpm_option_set_gpgdir(handle, config->gpgdir);
// 	if(ret != 0) {
// 		pm_printf(ALPM_LOG_ERROR, _("problem setting gpgdir '%s' (%s)\n"),
// 				config->gpgdir, alpm_strerror(alpm_errno(handle)));
// 		return ret;
// 	}
//
// 	/* Set user hook directory. This is not relative to rootdir, even if
// 	 * rootdir is defined. Reasoning: hookdir contains configuration data. */
// 	if(config->hookdirs == NULL) {
// 		if((ret = alpm_option_add_hookdir(handle, HOOKDIR)) != 0) {
// 			pm_printf(ALPM_LOG_ERROR, _("problem adding hookdir '%s' (%s)\n"),
// 					HOOKDIR, alpm_strerror(alpm_errno(handle)));
// 			return ret;
// 		}
// 	} else {
// 		/* add hook directories 1-by-1 to avoid overwriting the system directory */
// 		for(i = config->hookdirs; i; i = alpm_list_next(i)) {
// 			if((ret = alpm_option_add_hookdir(handle, i->data)) != 0) {
// 				pm_printf(ALPM_LOG_ERROR, _("problem adding hookdir '%s' (%s)\n"),
// 						(char *) i->data, alpm_strerror(alpm_errno(handle)));
// 				return ret;
// 			}
// 		}
// 	}
//
// 	/* add a default cachedir if one wasn't specified */
// 	if(config->cachedirs == NULL) {
// 		alpm_option_add_cachedir(handle, CACHEDIR);
// 	} else {
// 		alpm_option_set_cachedirs(handle, config->cachedirs);
// 	}
//
// 	alpm_option_set_overwrite_files(handle, config->overwrite_files);
//
// 	alpm_option_set_default_siglevel(handle, config->siglevel);
//
// 	config->localfilesiglevel = merge_siglevel(config->siglevel,
// 			config->localfilesiglevel, config->localfilesiglevel_mask);
// 	config->remotefilesiglevel = merge_siglevel(config->siglevel,
// 			config->remotefilesiglevel, config->remotefilesiglevel_mask);
//
// 	alpm_option_set_local_file_siglevel(handle, config->localfilesiglevel);
// 	alpm_option_set_remote_file_siglevel(handle, config->remotefilesiglevel);
//
// 	for(i = config->repos; i; i = alpm_list_next(i)) {
// 		register_repo(i->data);
// 	}
//
// 	if(config->xfercommand) {
// 		alpm_option_set_fetchcb(handle, download_with_xfercommand);
// 	} else if(!(alpm_capabilities() & ALPM_CAPABILITY_DOWNLOADER)) {
// 		pm_printf(ALPM_LOG_WARNING, _("no '%s' configured\n"), "XferCommand");
// 	}
//
// 	if(config->totaldownload) {
// 		alpm_option_set_totaldlcb(handle, cb_dl_total);
// 	}
//
// 	alpm_option_set_arch(handle, config->arch);
// 	alpm_option_set_checkspace(handle, config->checkspace);
// 	alpm_option_set_usesyslog(handle, config->usesyslog);
// 	alpm_option_set_deltaratio(handle, config->deltaratio);
//
// 	alpm_option_set_ignorepkgs(handle, config->ignorepkg);
// 	alpm_option_set_ignoregroups(handle, config->ignoregrp);
// 	alpm_option_set_noupgrades(handle, config->noupgrade);
// 	alpm_option_set_noextracts(handle, config->noextract);
//
// 	alpm_option_set_disable_dl_timeout(handle, config->disable_dl_timeout);
//
// 	for(i = config->assumeinstalled; i; i = i->next) {
// 		char *entry = i->data;
// 		alpm_depend_t *dep = alpm_dep_from_string(entry);
// 		if(!dep) {
// 			return 1;
// 		}
// 		pm_printf(ALPM_LOG_DEBUG, "parsed assume installed: %s %s\n", dep->name, dep->version);
//
// 		ret = alpm_option_add_assumeinstalled(handle, dep);
// 		alpm_dep_free(dep);
// 		if(ret) {
// 			pm_printf(ALPM_LOG_ERROR, _("Failed to pass %s entry to libalpm"), "assume-installed");
// 			return ret;
// 		}
// 	 }
//
// 	return 0;
// }
//
// /**
//  * Allows parsing in advance of an entire config section before we start
//  * calling library methods.
//  */
// struct section_t {
// 	const char *name;
// 	config_repo_t *repo;
// 	int depth;
// };
//
// static int process_usage(alpm_list_t *values, int *usage,
// 		const char *file, int linenum)
// {
// 	alpm_list_t *i;
// 	int level = *usage;
// 	int ret = 0;
//
// 	for(i = values; i; i = i->next) {
// 		char *key = i->data;
//
// 		if(strcmp(key, "Sync") == 0) {
// 			level |= ALPM_DB_USAGE_SYNC;
// 		} else if(strcmp(key, "Search") == 0) {
// 			level |= ALPM_DB_USAGE_SEARCH;
// 		} else if(strcmp(key, "Install") == 0) {
// 			level |= ALPM_DB_USAGE_INSTALL;
// 		} else if(strcmp(key, "Upgrade") == 0) {
// 			level |= ALPM_DB_USAGE_UPGRADE;
// 		} else if(strcmp(key, "All") == 0) {
// 			level |= ALPM_DB_USAGE_ALL;
// 		} else {
// 			pm_printf(ALPM_LOG_ERROR,
// 					_("config file %s, line %d: '%s' option '%s' not recognized\n"),
// 					file, linenum, "Usage", key);
// 			ret = 1;
// 		}
// 	}
//
// 	*usage = level;
//
// 	return ret;
// }
//
//
// static int _parse_repo(const char *key, char *value, const char *file,
// 		int line, struct section_t *section)
// {
// 	int ret = 0;
// 	config_repo_t *repo = section->repo;
//
// 	if(strcmp(key, "Server") == 0) {
// 		if(!value) {
// 			pm_printf(ALPM_LOG_ERROR, _("config file %s, line %d: directive '%s' needs a value\n"),
// 					file, line, key);
// 			ret = 1;
// 		} else {
// 			repo->servers = alpm_list_add(repo->servers, strdup(value));
// 		}
// 	} else if(strcmp(key, "SigLevel") == 0) {
// 		if(!value) {
// 			pm_printf(ALPM_LOG_ERROR, _("config file %s, line %d: directive '%s' needs a value\n"),
// 					file, line, key);
// 		} else {
// 			alpm_list_t *values = NULL;
// 			setrepeatingoption(value, "SigLevel", &values);
// 			if(values) {
// 				ret = process_siglevel(values, &repo->siglevel,
// 						&repo->siglevel_mask, file, line);
// 				FREELIST(values);
// 			}
// 		}
// 	} else if(strcmp(key, "Usage") == 0) {
// 		alpm_list_t *values = NULL;
// 		setrepeatingoption(value, "Usage", &values);
// 		if(values) {
// 			if(process_usage(values, &repo->usage, file, line)) {
// 				FREELIST(values);
// 				return 1;
// 			}
// 			FREELIST(values);
// 		}
// 	} else {
// 		pm_printf(ALPM_LOG_WARNING,
// 				_("config file %s, line %d: directive '%s' in section '%s' not recognized.\n"),
// 				file, line, key, repo->name);
// 	}
//
// 	return ret;
// }
//
// static int _parse_directive(const char *file, int linenum, const char *name,
// 		char *key, char *value, void *data);
//
// static int process_include(const char *value, void *data,
// 		const char *file, int linenum)
// {
// 	glob_t globbuf;
// 	int globret, ret = 0;
// 	size_t gindex;
// 	struct section_t *section = data;
// 	static const int config_max_recursion = 10;
//
// 	if(value == NULL) {
// 		pm_printf(ALPM_LOG_ERROR, _("config file %s, line %d: directive '%s' needs a value\n"),
// 				file, linenum, "Include");
// 		return 1;
// 	}
//
// 	if(section->depth >= config_max_recursion) {
// 		pm_printf(ALPM_LOG_ERROR,
// 				_("config parsing exceeded max recursion depth of %d.\n"),
// 				config_max_recursion);
// 		return 1;
// 	}
//
// 	section->depth++;
//
// 	/* Ignore include failures... assume non-critical */
// 	globret = glob(value, GLOB_NOCHECK, NULL, &globbuf);
// 	switch(globret) {
// 		case GLOB_NOSPACE:
// 			pm_printf(ALPM_LOG_DEBUG,
// 					"config file %s, line %d: include globbing out of space\n",
// 					file, linenum);
// 			break;
// 		case GLOB_ABORTED:
// 			pm_printf(ALPM_LOG_DEBUG,
// 					"config file %s, line %d: include globbing read error for %s\n",
// 					file, linenum, value);
// 			break;
// 		case GLOB_NOMATCH:
// 			pm_printf(ALPM_LOG_DEBUG,
// 					"config file %s, line %d: no include found for %s\n",
// 					file, linenum, value);
// 			break;
// 		default:
// 			for(gindex = 0; gindex < globbuf.gl_pathc; gindex++) {
// 				pm_printf(ALPM_LOG_DEBUG, "config file %s, line %d: including %s\n",
// 						file, linenum, globbuf.gl_pathv[gindex]);
// 				ret = parse_ini(globbuf.gl_pathv[gindex], _parse_directive, data);
// 				if(ret) {
// 					goto cleanup;
// 				}
// 			}
// 			break;
// 	}
//
// cleanup:
// 	section->depth--;
// 	globfree(&globbuf);
// 	return ret;
// }

// static int _parse_directive(const char *file, int linenum, const char *name,
// 		char *key, char *value, void *data)
// {
// 	struct section_t *section = data;
// 	if(!name && !key && !value) {
// 		pm_printf(ALPM_LOG_ERROR, _("config file %s could not be read: %s\n"),
// 				file, strerror(errno));
// 		return 1;
// 	} else if(!key && !value) {
// 		section->name = name;
// 		pm_printf(ALPM_LOG_DEBUG, "config: new section '%s'\n", name);
// 		if(strcmp(name, "options") == 0) {
// 			section->repo = NULL;
// 		} else {
// 			section->repo = calloc(sizeof(config_repo_t), 1);
// 			section->repo->name = strdup(name);
// 			section->repo->siglevel = ALPM_SIG_USE_DEFAULT;
// 			section->repo->usage = 0;
// 			config->repos = alpm_list_add(config->repos, section->repo);
// 		}
// 		return 0;
// 	}
//
// 	if(strcmp(key, "Include") == 0) {
// 		return process_include(value, data, file, linenum);
// 	}
//
// 	if(section->name == NULL) {
// 		pm_printf(ALPM_LOG_ERROR,
//              _("config file %s, line %d: All directives must belong to a section.\n"),
// 				file, linenum);
// 		return 1;
// 	}
//
// 	if(!section->repo) {
// 		/* we are either in options ... */
// 		return _parse_options(key, value, file, linenum);
// 	} else {
// 		return _parse_repo(key, value, file, linenum, section);
// 	}
// }

// /** Parse a configuration file.
//  * @param file path to the config file
//  * @return 0 on success, non-zero on error
//  */
// int parseconfig(const char *file)
// {
// 	int ret;
// 	struct section_t section;
// 	memset(&section, 0, sizeof(struct section_t));
// 	pm_printf(ALPM_LOG_DEBUG, "config: attempting to read file %s\n", file);
// 	if((ret = parse_ini(file, _parse_directive, &section))) {
// 		return ret;
// 	}
// 	pm_printf(ALPM_LOG_DEBUG, "config: finished parsing %s\n", file);
// 	if((ret = setup_libalpm())) {
// 		return ret;
// 	}
// 	alpm_list_free_inner(config->repos, (alpm_list_fn_free) config_repo_free);
// 	alpm_list_free(config->repos);
// 	config->repos = NULL;
// 	return ret;
// }
// 	/* ... or in a repo section */
// 		return _parse_repo(key, value, file, linenum, section);
// 	}
// }

// /** Parse a configuration file.
//  * @param file path to the config file
//  * @return 0 on success, non-zero on error
//  */
// int parseconfig(const char *file)
// {
// 	int ret;
// 	struct section_t section;
// 	memset(&section, 0, sizeof(struct section_t));
// 	pm_printf(ALPM_LOG_DEBUG, "config: attempting to read file %s\n", file);
// 	if((ret = parse_ini(file, _parse_directive, &section))) {
// 		return ret;
// 	}
// 	pm_printf(ALPM_LOG_DEBUG, "config: finished parsing %s\n", file);
// 	if((ret = setup_libalpm())) {
// 		return ret;
// 	}
// 	alpm_list_free_inner(config->repos, (alpm_list_fn_free) config_repo_free);
// 	alpm_list_free(config->repos);
// 	config->repos = NULL;
// 	return ret;
// }
//
// /* vim: set noet: */
