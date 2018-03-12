use alpm::DatabaseUsage;
use pacman::cleanup;
use TransactionFlag;
use SigLevel;
use Result;
use getopts;
use StdResult;
use consts::{CONFFILE, OS_ARCH, PKG_LOCALITY_FOREIGN, PKG_LOCALITY_NATIVE};

#[derive(Default, Debug, Clone)]
pub struct ConfigRepo {
    pub name: String,
    pub servers: Vec<String>,
    pub usage: DatabaseUsage,
    pub siglevel: SigLevel,
    pub siglevel_mask: SigLevel,
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
    pub dbpath: String,
    pub logfile: String,
    pub gpgdir: String,
    pub sysroot: String,
    pub hookdirs: Vec<String>,
    pub cachedirs: Vec<String>,

    pub ask: u64,
    pub flags: TransactionFlag,
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

    // pub explicit_adds: Vec<Package<'a>>,
    // pub explicit_removes: Vec<Package<'a>>,
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
    pub keepinst: bool,
    pub keepcur: bool,
}

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
    pub fn new() -> Self {
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
        match self.op {
            Some(Operations::Database) => self.check == 0,
            Some(Operations::UPGRADE) | Some(Operations::REMOVE) => self.print,
            Some(Operations::SYNC) => {
                self.clean > 0 || self.sync > 0
                    || (self.group == 0 && self.info == 0 && !self.list && !self.search
                        && !self.print)
            }

            Some(Operations::FILES) => self.sync != 0,
            _ => false,
        }
    }

    /// Parse command-line arguments for each operation.
    pub fn parseargs(&mut self, argv: Vec<String>) -> StdResult<Vec<String>, ()> {
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
