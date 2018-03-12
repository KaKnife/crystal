mod database;
mod remove;
mod upgrade;
mod sync;
mod query;
mod deptest;
mod check;
mod callback;

// use parse_ini;
// use self::package::{dump_pkg_changelog, dump_pkg_files, dump_pkg_search};
use libc;
use std::env;
use self::database::pacman_database;
use parse::parseconfig;
use self::deptest::pacman_deptest;
use self::query::pacman_query;
use self::sync::{pacman_sync, sync_prepare_execute};
use self::upgrade::pacman_upgrade;
use self::remove::pacman_remove;
use util::{check_syncdbs, print_packages, sync_syncdbs, trans_init, trans_release, yesno};
use std::path::Path;
use std::process::exit;
use consts::PACKAGE_VERSION;
use Handle;
use dep_from_string;
use Result;
use Error;
use parse::merge_siglevel;
use consts::CACHEDIR;
use consts::DBPATH;
use consts::GPGDIR;
use consts::{HOOKDIR, LOGFILE, ROOTDIR};
use parse::register_repo;
use Config;
use Operations;

/* special handling of package version for GIT */
// #if defined(GIT_VERSION)
// #undef PACKAGE_VERSION
// #define PACKAGE_VERSION GIT_VERSION
// #endif

// /* Used to sort the options in --help */
// static int options_cmp(const void *p1, const void *p2)
// {
// 	const char *s1 = p1;
// 	const char *s2 = p2;
//
// 	if(s1 == s2) return 0;
// 	if(!s1) return -1;
// 	if(!s2) return 1;
// 	/* First skip all spaces in both strings */
// 	while(isspace((unsigned char)*s1)) {
// 		s1++;
// 	}
// 	while(isspace((unsigned char)*s2)) {
// 		s2++;
// 	}
// 	/* If we compare a long option (--abcd) and a short one (-a),
// 	 * the short one always wins */
// 	if(*s1 == '-' && *s2 == '-') {
// 		s1++;
// 		s2++;
// 		if(*s1 == '-' && *s2 == '-') {
// 			/* two long -> strcmp */
// 			s1++;
// 			s2++;
// 		} else if(*s2 == '-') {
// 			/* s1 short, s2 long */
// 			return -1;
// 		} else if(*s1 == '-') {
// 			/* s1 long, s2 short */
// 			return 1;
// 		}
// 		/* two short -> strcmp */
// 	}
//
// 	return strcmp(s1, s2);
// }

// /** Display usage/syntax for the specified operation.
//  * @param op     the operation code requested
//  * @param myname basename(argv[0])
//  */
// static void usage(int op, const char * const myname)
// {
// #define addlist(s) (list = alpm_list_add(list, s))
// 	alpm_list_t *list = NULL, *i;
// 	/* prefetch some strings for usage below, which moves a lot of calls
// 	 * out of gettext. */
// 	char const *const str_opt  = _("options");
// 	char const *const str_file = _("file(s)");
// 	char const *const str_pkg  = _("package(s)");
// 	char const *const str_usg  = _("usage");
// 	char const *const str_opr  = _("operation");
//
// 	/* please limit your strings to 80 characters in width */
// 	if(op == MAIN) {
// 		printf("%s:  %s <%s> [...]\n", str_usg, myname, str_opr);
// 		printf(_("operations:\n"));
// 		printf("    %s {-h --help}\n", myname);
// 		printf("    %s {-V --version}\n", myname);
// 		printf("    %s {-D --database} <%s> <%s>\n", myname, str_opt, str_pkg);
// 		printf("    %s {-F --files}    [%s] [%s]\n", myname, str_opt, str_pkg);
// 		printf("    %s {-Q --query}    [%s] [%s]\n", myname, str_opt, str_pkg);
// 		printf("    %s {-R --remove}   [%s] <%s>\n", myname, str_opt, str_pkg);
// 		printf("    %s {-S --sync}     [%s] [%s]\n", myname, str_opt, str_pkg);
// 		printf("    %s {-T --deptest}  [%s] [%s]\n", myname, str_opt, str_pkg);
// 		printf("    %s {-U --upgrade}  [%s] <%s>\n", myname, str_opt, str_file);
// 		printf(_("\nuse '%s {-h --help}' with an operation for available options\n"),
// 				myname);
// 	} else {
// 		if(op == REMOVE) {
// 			printf("%s:  %s {-R --remove} [%s] <%s>\n", str_usg, myname, str_opt, str_pkg);
// 			printf("%s:\n", str_opt);
// 			addlist(_("  -c, --cascade        remove packages and all packages that depend on them\n"));
// 			addlist(_("  -n, --nosave         remove configuration files\n"));
// 			addlist(_("  -s, --recursive      remove unnecessary dependencies\n"
// 			          "                       (-ss includes explicitly installed dependencies)\n"));
// 			addlist(_("  -u, --unneeded       remove unneeded packages\n"));
// 		} else if(op == UPGRADE) {
// 			printf("%s:  %s {-U --upgrade} [%s] <%s>\n", str_usg, myname, str_opt, str_file);
// 			addlist(_("      --needed         do not reinstall up to date packages\n"));
// 			printf("%s:\n", str_opt);
// 		} else if(op == QUERY) {
// 			printf("%s:  %s {-Q --query} [%s] [%s]\n", str_usg, myname, str_opt, str_pkg);
// 			printf("%s:\n", str_opt);
// 			addlist(_("  -c, --changelog      view the changelog of a package\n"));
// 			addlist(_("  -d, --deps           list packages installed as dependencies [filter]\n"));
// 			addlist(_("  -e, --explicit       list packages explicitly installed [filter]\n"));
// 			addlist(_("  -g, --groups         view all members of a package group\n"));
// 			addlist(_("  -i, --info           view package information (-ii for backup files)\n"));
// addlist(_("  -k, --check          check that package files exist (-kk for file properties)\n"));
// 			addlist(_("  -l, --list           list the files owned by the queried package\n"));
// addlist(_("  -m, --foreign        list installed packages not found in sync db(s) [filter]\n"));
//addlist(_("  -n, --native         list installed packages only found in sync db(s) [filter]\n"));
// 			addlist(_("  -o, --owns <file>    query the package that owns <file>\n"));
// 			addlist(_("  -p, --file <package> query a package file instead of the database\n"));
// 			addlist(_("  -q, --quiet          show less information for query and search\n"));
// 	addlist(_("  -s, --search <regex> search locally-installed packages for matching strings\n"));
// 			addlist(_("  -t, --unrequired     list packages not (optionally) required by any\n"
// 			          "                       package (-tt to ignore optdepends) [filter]\n"));
// 			addlist(_("  -u, --upgrades       list outdated packages [filter]\n"));
// 		} else if(op == SYNC) {
// 			printf("%s:  %s {-S --sync} [%s] [%s]\n", str_usg, myname, str_opt, str_pkg);
// 			printf("%s:\n", str_opt);
//	addlist(_("  -c, --clean          remove old packages from cache directory (-cc for all)\n"));
//		addlist(_("  -g, --groups         view all members of a package group\n"
// 			          "                       (-gg to view all groups and members)\n"));
//	addlist(_("  -i, --info           view package information (-ii for extended information)\n"));
// 			addlist(_("  -l, --list <repo>    view a list of packages in a repo\n"));
// 			addlist(_("  -q, --quiet          show less information for query and search\n"));
// 			addlist(_("  -s, --search <regex> search remote repositories for matching strings\n"));
// 			addlist(_("  -u, --sysupgrade     upgrade installed packages (-uu enables downgrades)\n"));
// 			addlist(_("  -w, --downloadonly   download packages but do not install/upgrade anything\n"));
// 			addlist(_("  -y, --refresh        download fresh package databases from the server\n"
// 			          "                       (-yy to force a refresh even if up to date)\n"));
// 			addlist(_("      --needed         do not reinstall up to date packages\n"));
// 		} else if(op == PM_OP_DATABASE) {
// 			printf("%s:  %s {-D --database} <%s> <%s>\n", str_usg, myname, str_opt, str_pkg);
// 			printf("%s:\n", str_opt);
// 			addlist(_("      --asdeps         mark packages as non-explicitly installed\n"));
// 			addlist(_("      --asexplicit     mark packages as explicitly installed\n"));
//	addlist(_("  -k, --check          test local database for validity (-kk for sync databases)\n"));
// 			addlist(_("  -q, --quiet          suppress output of success messages\n"));
// 		} else if(op == PM_OP_DEPTEST) {
// 			printf("%s:  %s {-T --deptest} [%s] [%s]\n", str_usg, myname, str_opt, str_pkg);
// 			printf("%s:\n", str_opt);
// 		} else if(op == PM_OP_FILES) {
// 			addlist(_("  -l, --list           list the files owned by the queried package\n"));
// 			addlist(_("  -o, --owns <file>    query the package that owns <file>\n"));
// 			addlist(_("  -q, --quiet          show less information for query and search\n"));
// 			addlist(_("  -s, --search <file>  search package file names for matching strings\n"));
// 			addlist(_("  -x, --regex          enable searching using regular expressions\n"));
// 			addlist(_("  -y, --refresh        download fresh package databases from the server\n"
// 			          "                       (-yy to force a refresh even if up to date)\n"));
// 			addlist(_("      --machinereadable\n"
// 			          "                       produce machine-readable output\n"));
// 		}
// 		switch(op) {
// 			case PM_OP_SYNC:
// 			case PM_OP_UPGRADE:
// 				addlist(_("      --overwrite <path>\n"
//		          "                       overwrite conflicting files (can be used more than once)\n"));
// 				addlist(_("      --asdeps         install packages as non-explicitly installed\n"));
// 				addlist(_("      --asexplicit     install packages as explicitly installed\n"));
// 				addlist(_("      --ignore <pkg>   ignore a package upgrade (can be used more than once)\n"));
// 				addlist(_("      --ignoregroup <grp>\n"
// 				          "                       ignore a group upgrade (can be used more than once)\n"));
// 				/* pass through */
// 			case PM_OP_REMOVE:
//		addlist(_("  -d, --nodeps         skip dependency version checks (-dd to skip all checks)\n"));
// 				addlist(_("      --assume-installed <package=version>\n"
// 				          "                       add a virtual package to satisfy dependencies\n"));
// 				addlist(_("      --dbonly         only modify database entries, not package files\n"));
// 				addlist(_("      --noprogressbar  do not show a progress bar when downloading files\n"));
// 				addlist(_("      --noscriptlet    do not execute the install scriptlet if one exists\n"));
// 				addlist(_("  -p, --print          print the targets instead of performing the operation\n"));
// 				addlist(_("      --print-format <string>\n"
// 				          "                       specify how the targets should be printed\n"));
// 				break;
// 		}
//
// 		addlist(_("  -b, --dbpath <path>  set an alternate database location\n"));
// 		addlist(_("  -r, --root <path>    set an alternate installation root\n"));
// 		addlist(_("  -v, --verbose        be verbose\n"));
// 		addlist(_("      --arch <arch>    set an alternate architecture\n"));
// 		addlist(_("      --sysroot        operate on a mounted guest system (root-only)\n"));
// 		addlist(_("      --cachedir <dir> set an alternate package cache location\n"));
// 		addlist(_("      --hookdir <dir>  set an alternate hook location\n"));
// 		addlist(_("      --color <when>   colorize the output\n"));
// 		addlist(_("      --config <path>  set an alternate configuration file\n"));
// 		addlist(_("      --debug          display debug messages\n"));
// 		addlist(_("      --gpgdir <path>  set an alternate home directory for GnuPG\n"));
// 		addlist(_("      --logfile <path> set an alternate log file\n"));
// 		addlist(_("      --noconfirm      do not ask for any confirmation\n"));
// 		addlist(_("      --confirm        always ask for confirmation\n"));
// 		addlist(_("      --disable-download-timeout\n"
// 		          "                       use relaxed timeouts for download\n"));
// 	}
// 	list = alpm_list_msort(list, alpm_list_count(list), options_cmp);
// 	for(i = list; i; i = alpm_list_next(i)) {
// 		fputs((const char *)i->data, stdout);
// 	}
// 	alpm_list_free(list);
// #undef addlist
// }
/** Output pacman version and copyright.
 */
// static void version(void)
// {
// 	printf("\n");
// 	printf(" .--.                  Pacman v%s - libalpm v%s\n", PACKAGE_VERSION, alpm_version());
// 	printf("/ _.-' .-.  .-.  .-.   Copyright (C) 2006-2017 Pacman Development Team\n");
// 	printf("\\  '-. '-'  '-'  '-'   Copyright (C) 2002-2006 Judd Vinet\n");
// 	printf(" '--'\n");
// 	printf(_("                       This program may be freely redistributed under\n"
// 	         "                       the terms of the GNU General Public License.\n"));
// 	printf("\n");
// }

/** Sets up gettext localization. Safe to call multiple times.
 */
/* Inspired by the monotone function localize_monotone. */
// #if defined(ENABLE_NLS)
// static void localize(void)
// {
// 	static int init = 0;
// 	if(!init) {
// 		setlocale(LC_ALL, "");
// 		bindtextdomain(PACKAGE, LOCALEDIR);
// 		textdomain(PACKAGE);
// 		init = 1;
// 	}
// }
// #endif

/// Set user agent environment variable.
fn setuseragent() {
    let agent: String = format!("crystal/{} ({} {})", PACKAGE_VERSION, "linux", "x86_64");
    env::set_var("HTTP_USER_AGENT", agent);
}

pub fn cleanup(ret: i32) {
    //TODO:implement this
    // remove_soft_interrupt_handler();
    // 	/* free alpm library resources */
    // 	if(config.handle && alpm_release(config.handle) == -1) {
    // 		pm_printf(ALPM_LOG_ERROR, "error releasing alpm library\n");
    // 	}
    //
    // /* free memory */
    exit(ret);
}

/// Main function.
pub fn main() {
    let argv: Vec<String> = env::args().collect();
    let mut ret: i32 = 0;
    let mut config: Config;
    let mut handle: Handle;
    let myuid: u32 = unsafe { libc::getuid() };
    let pm_targets: Vec<String>;

    /* set user agent for downloading */
    setuseragent();

    /* init config data */
    config = Config::new();

    // install_soft_interrupt_handler();

    if unsafe { libc::isatty(libc::STDOUT_FILENO as i32) } == 0 {
        /* disable progressbar if the output is redirected */
        config.noprogressbar = true;
    } else {
        /* install signal handler to update output width */
        // unimplemented!();
        // install_winch_handler();
    }

    /* Priority of options:
     * 1. command line
     * 2. config file
     * 3. compiled-in defaults
     * However, we have to parse the command line first because a config file
     * location can be specified here, so we need to make sure we prefer these
     * options over the config file coming second.
     */

    /* parse the command line */
    pm_targets = match config.parseargs(argv) {
        Ok(targets) => targets,
        Err(()) => {
            cleanup(1);
            return;
        }
    };

    /* check if we have sufficient permission for the requested operation */
    if myuid > 0 && config.needs_root() {
        error!("you cannot perform this operation unless you are root.");
        cleanup(1);
    }

    if config.sysroot != "" && (unsafe {
        libc::chroot(&config.sysroot.as_bytes()[0] as *const u8 as *const i8) != 0
    } || !env::set_current_dir(&Path::new("/")).is_ok())
    {
        error!("chroot to {} failed: ()\n", config.sysroot); //, libc::strerror(errno));
        cleanup(1);
    }

    /* we support reading targets from stdin if a cmdline parameter is '-' */
    // if(alpm_list_find_str(pm_targets, "-")) {
    // 	if(!isatty(fileno(stdin))) {
    // 		int target_found = 0;
    // 		char *vdata, *line = NULL;
    // 		size_t line_size = 0;
    // 		ssize_t nread;
    //
    // 		/* remove the '-' from the list */
    // 		pm_targets = alpm_list_remove_str(pm_targets, "-", &vdata);
    // 		free(vdata);
    //
    // 		while((nread = getline(&line, &line_size, stdin)) != -1) {
    // 			if(line[nread - 1] == '\n') {
    // 				/* remove trailing newline */
    // 				line[nread - 1] = '\0';
    // 			}
    // 			if(line[0] == '\0') {
    // 				/* skip empty lines */
    // 				continue;
    // 			}
    // 			if(!alpm_list_append_strdup(&pm_targets, line)) {
    // 				break;
    // 			}
    // 			target_found = 1;
    // 		}
    // 		free(line);
    //
    // 		if(ferror(stdin)) {
    // 			pm_printf(ALPM_LOG_ERROR,
    // 					_("failed to read arguments from stdin: (%s)\n"), strerror(errno));
    // 			cleanup(EXIT_FAILURE);
    // 		}
    //
    // 		if(!freopen(ctermid(NULL), "r", stdin)) {
    // 			pm_printf(ALPM_LOG_ERROR, _("failed to reopen stdin for reading: (%s)\n"),
    // 					strerror(errno));
    // 		}
    //
    // 		if(!target_found) {
    // 			pm_printf(ALPM_LOG_ERROR, _("argument '-' specified with empty stdin\n"));
    // 			cleanup(1);
    // 		}
    // 	} else {
    // 		/* do not read stdin from terminal */
    // 		pm_printf(ALPM_LOG_ERROR, _("argument '-' specified without input on stdin\n"));
    // 		cleanup(1);
    // 	}
    // }

    /* parse the config file */
    match parseconfig(&config.configfile.clone(), &mut config) {
        Err(_) => {
            cleanup(-1);
            return;
        }
        Ok(h) => h,
    };

    handle = match setup_libalpm(&mut config) {
        Err(_) => {
            cleanup(-1);
            return;
        }
        Ok(h) => h,
    };

    /* noask is meant to be non-interactive */
    if config.noask {
        config.noconfirm = true;
    }

    /* set up the print operations */
    if config.print && config.clean == 0 {
        config.noconfirm = true;
        config.flags.no_conflicts = true;
        config.flags.no_lock = true;
        /* Display only errors */
    }

    if config.verbose > 0 {
        print!("Root      : {}\n", handle.get_root());
        print!("Conf File : {}\n", config.configfile);
        print!("DB Path   : {}\n", handle.get_dbpath());
        print!("Cache Dirs: ");
        for dir in handle.get_cachedirs() {
            print!("{}  ", dir);
        }
        print!("\n");
        print!("Hook Dirs : ");
        for dir in handle.get_hookdirs() {
            print!("{}  ", dir);
        }
        print!("\n");
        print!("Lock File : {}\n", handle.get_lockfile());
        print!("Log File  : {}\n", handle.get_logfile());
        print!("GPG Dir   : {}\n", handle.get_gpgdir());
        print!("Targets   :");
        for target in &pm_targets {
            print!("{}  ", target);
        }
        print!("\n");
    }

    // /* Log command line */
    // if(needs_root()) {
    // 	cl_to_log(argc, argv);
    // }

    /* start the requested operation */
    // unimplemented!("Done with parsing");
    match &config.op {
        &Some(Operations::Database) => match pacman_database(pm_targets, config, handle) {
            Err(e) => (ret = e),
            _ => {}
        },
        &Some(Operations::REMOVE) => match pacman_remove(pm_targets, config, handle) {
            Err(e) => (ret = e),
            _ => {}
        },
        &Some(Operations::UPGRADE) => match pacman_upgrade(pm_targets, config, handle) {
            Err(_) => (ret = 1),
            _ => {}
        },
        &Some(Operations::QUERY) => match pacman_query(pm_targets, config, handle) {
            Err(e) => (ret = 1),
            _ => {}
        },
        &Some(Operations::SYNC) => match pacman_sync(pm_targets, config, handle) {
            Err(_) => (ret = 1),
            _ => {}
        },
        &Some(Operations::DEPTEST) => match pacman_deptest(pm_targets, config, handle) {
            Err(e) => (ret = 1),
            _ => {}
        },
        // &Some(FILES) => match pacman_files(pm_targets, &mut config) {
        //     Err(e) => (ret = e),
        //     _ => {}
        // },
        _ => {
            error!("no operation specified (use -h for help)");
            ret = 1;
        }
    }

    cleanup(ret);
}

/// Sets up libalpm global stuff in one go. Called after the command line
/// and initial config file parsing. Once this is complete, we can see if any
/// paths were defined. If a rootdir was defined and nothing else, we want all
/// of our paths to live under the rootdir that was specified. Safe to call
/// multiple times (will only do anything the first time).
pub fn setup_libalpm<'a>(config: &Config) -> Result<Handle> {
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
