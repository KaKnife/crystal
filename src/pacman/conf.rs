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
use super::parse_ini;
use super::alpm::Result;
use super::alpm::Handle;
use super::alpm::Error;
use super::alpm::DatabaseUsage;
use super::alpm::*;
use super::alpm;
use super::getopts;
use super::glob;
use super::cleanup;
use std;

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
    /* bools */
    pub quiet: bool,
    pub version: bool,
    pub help: bool,
    pub noconfirm: bool,
    pub noprogressbar: bool,
    pub print: bool,
    pub disable_dl_timeout: bool,
    pub isfile: bool,
    pub list: bool,
    pub deps: bool,
    pub explicit: bool,
    pub owns: bool,
    pub search: bool,
    pub changelog: bool,
    pub q_upgrade: bool,
    pub noask: bool,
    pub checkspace: bool,

    pub verbose: usize,
    pub usesyslog: usize,
    pub color: usize,
    pub info: usize,
    pub unrequired: usize,
    pub check: usize,
    pub locality: usize,
    pub clean: usize,
    pub downloadonly: usize,
    pub sync: usize,
    pub s_upgrade: usize,
    pub regex: usize,
    pub machinereadable: usize,
    pub group: usize,

    pub deltaratio: f64,

    pub arch: String,
    pub print_format: String,
    pub configfile: String,
    pub rootdir: String,
    dbpath: String,
    pub logfile: String,
    pub gpgdir: String,
    pub sysroot: String,
    pub hookdirs: Vec<String>,
    pub cachedirs: Vec<String>,

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
    pub chomp: usize,
    pub verbosepkglists: usize,
    /* When downloading, display the amount downloaded, rate, ETA, and percent
     * downloaded of the total download list */
    pub totaldownload: usize,
    pub cleanmethod: CleanMethod,

    pub xfercommand: String,

    pub holdpkg: Vec<String>,
    pub ignorepkg: Vec<String>,
    pub ignoregrp: Vec<String>,
    pub assumeinstalled: Vec<String>,
    pub noupgrade: Vec<String>,
    pub noextract: Vec<String>,
    pub overwrite_files: Vec<String>, //Not sure this should be a string

    pub explicit_adds: Vec<Package>,
    pub explicit_removes: Vec<Package>,
    pub repos: Vec<ConfigRepo>,
}

/// Operations
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

/// package locality
pub static PKG_LOCALITY_UNSET: usize = 0;
pub static PKG_LOCALITY_NATIVE: usize = (1 << 0);
pub static PKG_LOCALITY_FOREIGN: usize = (1 << 1);

fn invalid_opt(used: bool, opt1: &str, opt2: &str) {
    if used {
        error!(
            "invalid option: '{}' and '{}' may not be used together",
            opt1, opt2
        );
        cleanup(1);
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
    pub fn new() -> Config {
        let mut newconfig = Config::default();

        /* defaults which may get overridden later */
        newconfig.op = Some(Operations::MAIN);
        newconfig.configfile = String::from(CONFFILE); //TODO: implement this
        newconfig.deltaratio = 0.0;
        //TODO: implement this
        // if(alpm_capabilities() & ALPM_CAPABILITY_SIGNATURES) {
        // 	newconfig.SigLevel = package | package_optional |
        // 		database | database_optional;
        // 	newconfig.localfileSigLevel = USE_DEFAULT;
        // 	newconfig.remotefileSigLevel = USE_DEFAULT;
        // }

        return newconfig;
    }

    /// Check if the operation needs root
    pub fn needs_root(&self) -> bool {
        if self.sysroot != "" {
            return true;
        }
        use pacman::conf::Operations::*;
        match self.op {
            Some(Database) => self.check == 0,
            Some(UPGRADE) | Some(REMOVE) => self.print,
            Some(SYNC) => {
                self.clean > 0 || self.sync > 0
                    || (self.group == 0 && self.info == 0 && !self.list && !self.search
                        && !self.print)
            }

            Some(FILES) => self.sync != 0,
            _ => false,
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
                print!("{}\n", f);
                return Err(());
            }
        };
        // let pm_targets = &matches.free;
        self.parsearg_op(&matches);
        match self.parsearg_global(&matches) {
            Err(e) => error!("{}", e),
            Ok(()) => {}
        }

        if self.op.is_none() {
            unimplemented!();
            error!("only one operation may be used at a time");
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
        let opts = matches;
        {
            self.changelog = opts.opt_present("changelog");
            self.check = opts.opt_count("check");
            self.clean = opts.opt_count("clean");
            self.deps = opts.opt_present("deps");
            self.explicit = opts.opt_present("explicit");
            self.flags.all_deps = opts.opt_present("asdeps");
            self.flags.all_explicit = opts.opt_present("asexplicit");
            self.flags.cascade = opts.opt_present("cascade");
            self.flags.force = opts.opt_present("force");
            self.flags.no_save = opts.opt_present("nosave");
            self.flags.no_scriptlet = opts.opt_present("noscriptlet");
            self.flags.needed = opts.opt_present("needed");
            self.flags.unneeded = opts.opt_present("unneeded");
            self.group = opts.opt_count("groups");
            self.info = opts.opt_count("info");
            self.isfile = opts.opt_present("file");
            self.list = opts.opt_present("list");
            self.noprogressbar = opts.opt_present("noprogressbar");
            self.owns = opts.opt_present("owns");
            self.print = opts.opt_present("print");
            self.quiet = opts.opt_present("quiet");
            self.q_upgrade = opts.opt_present("upgrades");
            self.search = opts.opt_present("search");
            self.sync = opts.opt_count("refresh");
            self.s_upgrade = opts.opt_count("sysupgrade") + opts.opt_count("u");
            self.unrequired = opts.opt_count("unrequired");

            if opts.opt_present("assume-installed") {
                unimplemented!();
                // parsearg_util_addlist(&(self.assumeinstalled));
            }
            if opts.opt_present("foreign") {
                self.locality |= PKG_LOCALITY_FOREIGN;
            }
            if opts.opt_present("native") {
                self.locality |= PKG_LOCALITY_NATIVE;
            }
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
            if let Some(format) = opts.opt_str("print-format") {
                self.print = true;
                self.print_format = format;
            }
            if opts.opt_present("assume-installed") {
                unimplemented!();
                // parsearg_util_addlist(&(self.assumeinstalled));
            }
            if opts.opt_present("recursive") {
                if self.flags.recurse {
                    self.flags.recurse_all = true;
                } else {
                    self.flags.recurse = true;
                }
            }
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
            if let Some(format) = opts.opt_str("print-format") {
                self.print = true;
                self.print_format = format;
            }
            if opts.opt_present("machinereadable") {
                self.machinereadable = 1;
            }
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
            if let Some(format) = opts.opt_str("print-format") {
                self.print = true;
                self.print_format = format;
            }
            if opts.opt_present("assume-installed") {
                unimplemented!();
                // parsearg_util_addlist(&(self.assumeinstalled));
            }
            if opts.opt_present("overwrite") {
                unimplemented!();
                // parsearg_util_addlist(&(self.overwrite_files));
            }
            if opts.opt_present("downloadonly") {
                self.downloadonly = 1;
                self.flags.download_only = true;
                self.flags.no_conflicts = true;
            }
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
            if let Some(format) = opts.opt_str("print-format") {
                self.print = true;
                self.print_format = format;
            }
            if opts.opt_present("overwrite") {
                unimplemented!();
                // parsearg_util_addlist(&(self.overwrite_files));
            }
        }

        match &self.op {
            &Some(Operations::Database) => {
                invalid_opt(
                    self.flags.all_deps && self.flags.all_explicit,
                    "--asdeps",
                    "--asexplicit",
                );

                if self.check != 0 {
                    invalid_opt(self.flags.all_deps, "--asdeps", "--check");
                    invalid_opt(self.flags.all_explicit, "--asexplicit", "--check");
                }
            }
            &Some(Operations::QUERY) => {
                if self.isfile {
                    invalid_opt(self.group != 0, "--file", "--groups");
                    invalid_opt(self.search, "--file", "--search");
                    invalid_opt(self.owns, "--file", "--owns");
                } else if self.search {
                    invalid_opt(self.group != 0, "--search", "--groups");
                    invalid_opt(self.owns, "--search", "--owns");
                    self.checkargs_query_display_opts("--search");
                    self.checkargs_query_filter_opts("--search");
                } else if self.owns {
                    invalid_opt(self.group != 0, "--owns", "--groups");
                    self.checkargs_query_display_opts("--owns");
                    self.checkargs_query_filter_opts("--owns");
                } else if self.group != 0 {
                    self.checkargs_query_display_opts("--groups");
                }

                invalid_opt(self.deps && self.explicit, "--deps", "--explicit");
                invalid_opt(
                    (self.locality & PKG_LOCALITY_NATIVE != 0)
                        && (self.locality & PKG_LOCALITY_FOREIGN != 0),
                    "--native",
                    "--foreign",
                );
            }
            &Some(Operations::REMOVE) => {
                self.checkargs_remove();
            }
            &Some(Operations::SYNC) => {
                self.checkargs_sync();
            }
            &Some(Operations::UPGRADE) => {
                self.checkargs_upgrade();
            }
            &Some(Operations::FILES) => {
                self.checkargs_files();
            }
            _ => {}
        }

        return Ok(opts.free);
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

    /// Helper function for parsing operation from command-line arguments.
    fn parsearg_op(&mut self, opts: &getopts::Matches) -> i64 {
        /* operations */
        if opts.opt_present("D") {
            self.op = match self.op {
                Some(Operations::MAIN) => Some(Operations::Database),
                _ => None,
            }
        } else if opts.opt_present("F") {
            self.op = match self.op {
                Some(Operations::MAIN) => Some(Operations::FILES),
                _ => None,
            };
        } else if opts.opt_present("Q") {
            self.op = match self.op {
                Some(Operations::MAIN) => Some(Operations::QUERY),
                _ => None,
            };
        } else if opts.opt_present("R") {
            self.op = match self.op {
                Some(Operations::MAIN) => Some(Operations::REMOVE),
                _ => None,
            };
        } else if opts.opt_present("S") {
            self.op = match self.op {
                Some(Operations::MAIN) => Some(Operations::SYNC),
                _ => None,
            };
        } else if opts.opt_present("T") {
            self.op = match self.op {
                Some(Operations::MAIN) => Some(Operations::DEPTEST),
                _ => None,
            };
        } else if opts.opt_present("U") {
            self.op = match self.op {
                Some(Operations::MAIN) => Some(Operations::UPGRADE),
                _ => None,
            };
        } else if opts.opt_present("V") {
            self.version = true;
        } else if opts.opt_present("h") {
            self.help = true;
        } else {
            return 1;
        }
        return 0;
    }

    /// Helper functions for parsing command-line arguments.
    fn parsearg_global(&mut self, opts: &getopts::Matches) -> Result<()> {
        if opts.opt_present("arch") {
            unimplemented!();
            // self.set_arch(opts.opt_str("arch").unwrap());
        }
        if let Some(ask) = opts.opt_str("ask") {
            self.noask = true;
            self.ask = ask.parse().expect("--ask requires a number argument");
        }
        if opts.opt_present("cachedir") {
            unimplemented!()
            // self.cachedirs = alpm_list_add(self.cachedirs, strdup(opts.opt_str("cachedir")));
        }
        if let Some(config) = opts.opt_str("config") {
            self.configfile = config;
        }
        if opts.opt_present("debug") {
            /* debug levels are made more 'human readable' than using a raw logmask
             * here, error and warning are set in self_new, though perhaps a
             * --quiet option will remove these later */
            /* progress bars get wonky with debug on, shut them off */
            self.noprogressbar = true;
        }
        if let Some(str) = opts.opt_str("gpgdir") {
            self.gpgdir = str;
        }
        if let Some(hookdir) = opts.opt_str("hookdir") {
            self.hookdirs.push(hookdir);
        }
        if let Some(logfile) = opts.opt_str("logfile") {
            self.logfile = logfile;
        }
        self.noconfirm = opts.opt_present("noconfirm");
        self.noconfirm = !opts.opt_present("confirm");
        self.disable_dl_timeout = opts.opt_present("disable-download-timeout");
        self.verbose = opts.opt_count("verbose");
        if let Some(dbpath) = opts.opt_str("dbpath") {
            self.dbpath = dbpath;
        }
        if let Some(root) = opts.opt_str("root") {
            self.rootdir = root;
        }
        if let Some(sysroot) = opts.opt_str("sysroot") {
            self.sysroot = sysroot;
        }
        return Ok(());
    }

    fn checkargs_query_display_opts(&mut self, opname: &str) {
        invalid_opt(self.changelog, opname, "--changelog");
        invalid_opt(self.check != 0, opname, "--check");
        invalid_opt(self.info != 0, opname, "--info");
        invalid_opt(self.list, opname, "--list");
    }

    fn checkargs_query_filter_opts(&mut self, opname: &str) {
        invalid_opt(self.deps, opname, "--deps");
        invalid_opt(self.explicit, opname, "--explicit");
        invalid_opt(self.q_upgrade, opname, "--upgrade");
        invalid_opt(self.unrequired != 0, opname, "--unrequired");
        invalid_opt(self.locality & PKG_LOCALITY_NATIVE != 0, opname, "--native");
        invalid_opt(
            self.locality & PKG_LOCALITY_FOREIGN != 0,
            opname,
            "--foreign",
        );
    }

    fn checkargs_trans(&mut self) {
        if self.print {
            invalid_opt(self.flags.db_only, "--print", "--dbonly");
            invalid_opt(self.flags.no_scriptlet, "--print", "--noscriptlet");
        }
    }

    fn checkargs_remove(&mut self) {
        self.checkargs_trans();
        if self.flags.no_save {
            invalid_opt(self.print, "--nosave", "--print");
            invalid_opt(self.flags.db_only, "--nosave", "--dbonly");
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

    fn checkargs_files(&mut self) {
        if self.owns {
            invalid_opt(self.list, "--owns", "--list");
            invalid_opt(self.search, "--owns", "--search");
            invalid_opt(self.regex != 0, "--owns", "--regex");
        } else if self.list {
            invalid_opt(self.search, "--list", "--search");
            invalid_opt(self.regex != 0, "--list", "--regex");
        }
    }

    fn checkargs_sync(&mut self) {
        self.checkargs_upgrade();
        if self.clean != 0 {
            invalid_opt(self.group != 0, "--clean", "--groups");
            invalid_opt(self.info != 0, "--clean", "--info");
            invalid_opt(self.list, "--clean", "--list");
            invalid_opt(self.sync != 0, "--clean", "--refresh");
            invalid_opt(self.search, "--clean", "--search");
            invalid_opt(self.s_upgrade != 0, "--clean", "--sysupgrade");
            invalid_opt(self.downloadonly != 0, "--clean", "--downloadonly");
        } else if self.info != 0 {
            invalid_opt(self.group != 0, "--info", "--groups");
            invalid_opt(self.list, "--info", "--list");
            invalid_opt(self.search, "--info", "--search");
            invalid_opt(self.s_upgrade != 0, "--info", "--sysupgrade");
            invalid_opt(self.downloadonly != 0, "--info", "--downloadonly");
        } else if self.search {
            invalid_opt(self.group != 0, "--search", "--groups");
            invalid_opt(self.list, "--search", "--list");
            invalid_opt(self.s_upgrade != 0, "--search", "--sysupgrade");
            invalid_opt(self.downloadonly != 0, "--search", "--downloadonly");
        } else if self.list {
            invalid_opt(self.group != 0, "--list", "--groups");
            invalid_opt(self.s_upgrade != 0, "--list", "--sysupgrade");
            invalid_opt(self.downloadonly != 0, "--list", "--downloadonly");
        } else if self.group != 0 {
            invalid_opt(self.s_upgrade != 0, "--groups", "--sysupgrade");
            invalid_opt(self.downloadonly != 0, "--groups", "--downloadonly");
        }
    }

    pub fn config_set_arch(&mut self, arch: &String) {
        if arch == "auto" {
            // struct utsname un;
            // uname(&un);
            self.arch = String::from(OS_ARCH);
        } else {
            self.arch = arch.clone();
        }
        debug!("config: arch: {}", self.arch);
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
    linenum: usize,
) -> Result<()> {
    let mut level = storage.clone();
    let mut mask = storage_mask.clone();
    let mut ret = Ok(());

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
            error!(
                "config file {}, line {}: invalid value for '{}' : '{}'",
                file, linenum, "SigLevel", original
            );
            ret = Err(Error::WrongArgs);
        }
        level.use_default = false;
    }

    /* ensure we have sig checking ability and are actually turning it on */
    if !(alpm::capabilities().signatures && level.package || level.database) {
        error!(
            "config file {}, line {}: '{}' option invalid, no signature support",
            file, linenum, "SigLevel"
        );
        ret = Err(Error::WrongArgs);
    }

    if ret.is_ok() {
        *storage = level;
        *storage_mask = mask;
    }
    return ret;
}

/// Merge the package entries of two signature verification levels.
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
    linenum: usize,
    config: &mut Config,
) -> Result<()> {
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
            return Err(Error::WrongArgs);
        }
    }
    return Ok(());
}

/// Add repeating options such as NoExtract, NoUpgrade, etc to libalpm
/// settings. Refactored out of the parseconfig code since all of them did
/// the exact same thing and duplicated code.
fn setrepeatingoption(options: &String, option_name: &str, list: &mut Vec<String>) {
    let vals = options.split_whitespace();
    for val in vals {
        list.push(String::from(val));
        debug!("config: {}: {}", option_name, val);
    }
}

fn parse_options(
    key: &Option<String>,
    value: &Option<String>,
    file: &String,
    linenum: usize,
    config: &mut Config,
) -> Result<()> {
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
                config.checkspace = true;
            } else if key == "Color" {
            } else if key == "DisableDownloadTimeout" {
                config.disable_dl_timeout = true;
            } else {
                warn!(
                    "config file {}, line {}: directive '{}' in section '{}' not recognized.",
                    file, linenum, key, "options"
                );
            }
        }
        &Some(ref value) => {
            /* options with settings */
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
                let mut methods = Vec::new();
                setrepeatingoption(value, "CleanMethod", &mut methods);
                process_cleanmethods(methods, file, linenum, config)?;
            } else if key == "SigLevel" {
                let mut values = Vec::new();
                setrepeatingoption(value, "SigLevel", &mut values);
                process_siglevel(
                    values,
                    &mut config.siglevel,
                    &mut config.siglevel_mask,
                    file,
                    linenum,
                )?;
            } else if key == "LocalFileSigLevel" {
                let mut values = Vec::new();
                setrepeatingoption(value, "LocalFileSigLevel", &mut values);
                process_siglevel(
                    values,
                    &mut config.localfilesiglevel,
                    &mut config.localfilesiglevel_mask,
                    file,
                    linenum,
                )?;
            } else if key == "RemoteFileSigLevel" {
                let mut values = Vec::new();
                setrepeatingoption(value, "RemoteFileSigLevel", &mut values);
                process_siglevel(
                    values,
                    &mut config.remotefilesiglevel,
                    &mut config.remotefilesiglevel_mask,
                    file,
                    linenum,
                )?;
            } else {
                warn!(
                    "config file {}, line {}: directive '{}' in section '{}' not recognized.",
                    file, linenum, key, "options"
                );
            }
        }
    }
    return Ok(());
}

fn add_mirror(db: &mut Database, value: &String, arch: &String) -> Result<()> {
    let dbname = db.get_name().clone();
    /* let's attempt a replacement for the current repo */
    let temp = value.replace("$repo", &dbname);
    /* let's attempt a replacement for the arch */
    let server;
    if arch != "" {
        server = temp.replace("$arch", arch);
    } else {
        if temp.contains("$arch") {
            error!(
                "mirror '{}' contains the '$arch' variable, but no 'Architecture' is defined.",
                value
            );
            return Err(Error::Other);
        }
        server = temp;
    }

    if let Err(e) = db.add_server(&server) {
        error!(
            "could not add server URL to database '{}': {} ({})",
            dbname, server, e
        );
        return Err(e);
    }
    Ok(())
}

fn register_repo(
    repo: &ConfigRepo,
    config_handle: &mut Handle,
    config_siglevel: SigLevel,
    arch: &String,
) -> Result<()> {
    let siglevel = merge_siglevel(config_siglevel, repo.siglevel, repo.siglevel_mask);
    let name = &repo.name;
    let servers = &repo.servers;
    let mut usage = repo.usage;
    let mut db = match config_handle.register_syncdb(name, siglevel) {
        Err(e) => {
            error!("could not register '{}' database ({})", name, e);
            return Err(e);
        }
        Ok(db) => db,
    };

    debug!("setting usage for {} repository", name);
    if usage.is_zero() {
        usage.set_all();
    }
    db.set_usage(usage);

    for ref server in servers {
        if let Err(e) = add_mirror(&mut db, server, arch) {
            error!(
                "could not add mirror '{}' to database '{}' ({})",
                server, name, e
            );
            return Err(e);
        }
    }

    config_handle.dbs_sync.push(db);
    return Ok(());
}

/// Sets up libalpm global stuff in one go. Called after the command line
/// and initial config file parsing. Once this is complete, we can see if any
/// paths were defined. If a rootdir was defined and nothing else, we want all
/// of our paths to live under the rootdir that was specified. Safe to call
/// multiple times (will only do anything the first time).
pub fn setup_libalpm(config: &Config) -> Result<Handle> {
    let mut handle;
    let mut rootdir = config.rootdir.clone();
    let mut dbpath = config.dbpath.clone();
    let mut logfile = config.logfile.clone();
    let mut gpgdir = config.gpgdir.clone();

    debug!("setup_libalpm called");

    /* Configure root path first. If it is set and dbpath/logfile were not
     * set, then set those as well to reside under the root. */
    if rootdir != "" {
        if dbpath == "" {
            dbpath = format!("{}{}", rootdir, DBPATH);
        }
        if logfile == "" {
            logfile = format!("{}{}", rootdir, LOGFILE);
        }
    } else {
        rootdir = format!("{}", ROOTDIR);
        if dbpath == "" {
            dbpath = format!("{}", DBPATH);
        }
    }

    /* initialize library */
    handle = match Handle::new(&rootdir, &dbpath) {
        Ok(h) => h,
        Err(e) => {
            error!("failed to initialize alpm library({}: {})", e, dbpath);
            match e {
                Error::DatabaseVersion => error!("try running pacman-db-upgrade"),
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
            handle.set_dbext(&String::from(".files"));
        }
        _ => {}
    }

    if logfile == "" {
        logfile = format!("{}", LOGFILE);
    }
    if let Err(e) = handle.set_logfile(&logfile) {
        error!("problem setting logfile '{}' ({})", logfile, e);
        return Err(e);
    }

    /* Set GnuPG's home directory. This is not relative to rootdir, even if
     * rootdir is defined. Reasoning: gpgdir contains configuration data. */
    if gpgdir == "" {
        gpgdir = format!("{}", GPGDIR);
    }
    if let Err(e) = handle.set_gpgdir(&gpgdir) {
        error!("problem setting gpgdir '{}' ({})", gpgdir, e);
        return Err(e);
    }

    /* Set user hook directory. This is not relative to rootdir, even if
     * rootdir is defined. Reasoning: hookdir contains configuration data. */
    if config.hookdirs.is_empty() {
        if let Err(e) = handle.add_hookdir(&String::from(HOOKDIR)) {
            error!("problem adding hookdir '{}' ({})", HOOKDIR, e);
            return Err(e);
        }
    } else {
        /* add hook directories 1-by-1 to avoid overwriting the system directory */
        for data in &config.hookdirs {
            if let Err(e) = handle.add_hookdir(data) {
                error!("problem adding hookdir '{}' ({})", data, e);
                return Err(e);
            }
        }
    }

    /* add a default cachedir if one wasn't specified */
    if config.cachedirs.is_empty() {
        handle.add_cachedir(&String::from(CACHEDIR))?;
    } else {
        handle.set_cachedirs(&config.cachedirs)?;
    }

    handle.set_overwrite_files(&config.overwrite_files);

    handle.set_default_siglevel(&config.siglevel);

    // config.localfilesiglevel = merge_siglevel(
    //     config.siglevel,
    //     config.localfilesiglevel,
    //     config.localfilesiglevel_mask,
    // );
    // config.remotefilesiglevel = merge_siglevel(
    //     config.siglevel,
    //     config.remotefilesiglevel,
    //     config.remotefilesiglevel_mask,
    // );

    handle.set_local_file_siglevel(merge_siglevel(
        config.siglevel,
        config.localfilesiglevel,
        config.localfilesiglevel_mask,
    ));

    handle.set_remote_file_siglevel(merge_siglevel(
        config.siglevel,
        config.remotefilesiglevel,
        config.remotefilesiglevel_mask,
    ));

    for mut repo in &config.repos {
        register_repo(&repo, &mut handle, config.siglevel, &config.arch)?;
    }

    // if config.xfercommand!="" {
    //     alpm_option_set_fetchcb(handle, download_with_xfercommand);
    // } else if !(alpm_capabilities().ALPM_CAPABILITY_DOWNLOADER) {
    //     // pm_printf(ALPM_LOG_WARNING, _("no '{}' configured\n"), "XferCommand");
    // }

    // if config.totaldownload {
    //     alpm_option_set_totaldlcb(handle, cb_dl_total);
    // }

    handle.set_arch(&config.arch);

    handle.set_checkspace(config.checkspace as i32);

    handle.set_usesyslog(config.usesyslog as i32);
    handle.set_deltaratio(config.deltaratio)?;
    handle.set_ignorepkgs(&config.ignorepkg);

    handle.set_ignoregroups(&config.ignoregrp);
    handle.set_noupgrades(&config.noupgrade);
    handle.set_noextracts(&config.noextract);

    handle.set_disable_dl_timeout(config.disable_dl_timeout);

    for entry in &config.assumeinstalled {
        let dep = dep_from_string(&entry);
        debug!("parsed assume installed: {} {}", dep.name, dep.version,);
        handle.add_assumeinstalled(dep);
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
    linenum: usize,
) -> Result<()> {
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
            level.set_all();
        } else {
            error!(
                "config file {}, line {}: '{}' option '{}' not recognized",
                file, linenum, "Usage", key
            );
            ret = Err(Error::WrongArgs);
        }
    }
    if ret.is_ok() {
        *usage = level;
    }
    ret
}

fn parse_repo(
    key: &Option<String>,
    value: &Option<String>,
    file: &String,
    line: usize,
    section: &mut Section,
) -> Result<()> {
    let mut ret = Ok(());
    match (&mut section.repo, key) {
        (&mut Some(ref mut repo), &Some(ref key)) => {
            if key == "Server" {
                match value {
                    &None => {
                        error!(
                            "config file {}, line {}: directive '{}' needs a value",
                            file, line, key
                        );
                        ret = Err(Error::WrongArgs);
                    }
                    &Some(ref value) => {
                        repo.servers.push(value.clone());
                    }
                }
            } else if key == "SigLevel" {
                match value {
                    &None => {
                        error!(
                            "config file {}, line {}: directive '{}' needs a value",
                            file, line, key,
                        );
                    }
                    &Some(ref value) => {
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
                        }
                    }
                }
            } else if key == "Usage" {
                match value {
                    &Some(ref value) => {
                        let mut values = Vec::new();
                        setrepeatingoption(&value, "Usage", &mut values);
                        if !values.is_empty() {
                            process_usage(&values, &mut repo.usage, file, line)?;
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
    ret
}

fn process_include(
    value: &Option<String>,
    section: &mut Section,
    file: &String,
    linenum: usize,
    config: &mut Config,
) -> Result<()> {
    let globret;
    let config_max_recursion = 10;

    match value {
        &None => {
            error!(
                "config file {}, line {}: directive '{}' needs a value",
                file, linenum, "Include"
            );
            return Err(Error::WrongArgs);
        }
        &Some(ref value) => {
            if section.depth >= config_max_recursion {
                error!(
                    "config parsing exceeded max recursion depth of {}.",
                    config_max_recursion
                );
                return Err(Error::Other);
            }

            section.depth += 1;

            /* Ignore include failures... assume non-critical */
            globret = glob::glob(&value);
            if let Ok(items) = globret {
                for item in items {
                    let item = item.unwrap().into_os_string().into_string()?;
                    debug!(
                        "config file {}, line {}: including {}",
                        file, linenum, &item
                    );
                    if let Err(e) = parse_ini(&item, &parse_directive, section, config) {
                        section.depth -= 1;
                        return Err(e);
                    }
                }
            }
        }
    }

    section.depth -= 1;
    Ok(())
}

pub fn parse_directive(
    file: &String,
    linenum: usize,
    name: &String,
    key: &Option<String>,
    value: &Option<String>,
    section: &mut Section,
    config: &mut Config,
) -> Result<()> {
    if key.is_none() && value.is_none() {
        if let Some(ref repo) = section.repo {
            config.repos.push(repo.clone());
        }

        section.name = name.clone();
        debug!("config: new section '{}'", name);
        if name == "options" {
            section.repo = None;
        } else {
            let mut repo = ConfigRepo::default();
            repo.name = name.clone();
            repo.siglevel.use_default = true;
            section.repo = Some(repo);
        }
        return Ok(());
    }

    match key {
        &Some(ref k) => if k == "Include" {
            return process_include(value, section, &file, linenum, config);
        },
        &None => {}
    }

    if section.name == "" {
        error!(
            "config file {}, line {}: All directives must belong to a section.",
            file, linenum
        );
        return Err(Error::WrongArgs);
    }

    if section.repo.is_none() {
        /* we are either in options ... */
        parse_options(key, value, file, linenum, config)
    } else {
        parse_repo(key, value, file, linenum, section)
    }
}

/// Parse a configuration file.
pub fn parseconfig(file: &String, config: &mut Config) -> Result<()> {
    let mut sec = Section::default();
    debug!("config: attempting to read file {}", file);
    parse_ini(file, &parse_directive, &mut sec, config)?;
    debug!("config: finished parsing {}", file);
    Ok(())
}
