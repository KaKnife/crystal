use libc;
use std::env;
pub mod conf;
pub use super::alpm;
pub mod database;
pub mod util;
pub mod remove;
pub mod upgrade;
pub mod sync;
pub mod query;
pub mod deptest;
pub mod package;
pub mod check;
use self::check::*;
use self::package::*;
use self::deptest::*;
use self::query::*;
use self::sync::*;
use self::upgrade::*;
use self::alpm::*;
use self::remove::*;
use self::util::*;
use self::database::*;
use self::conf::*;
use self::Operations::*;

pub use self::conf::Config;
pub use self::conf::Section;

use super::*;
use super::common::*;
// use pacman::conf::PKG_LOCALITY_FOREIGN;
// use pacman::conf::PKG_LOCALITY_NATIVE;

use std;

/*
 *  pacman.c
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
 *  You should have received a copy of the GNUu8 General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* special handling of package version for GIT */
// #if defined(GIT_VERSION)
// #undef PACKAGE_VERSION
// #define PACKAGE_VERSION GIT_VERSION
// #endif
//
// #include <stdlib.h> /* atoi */
// #include <stdio.h>
// #include <ctype.h> /* isspace */
// #include <limits.h>
// #include <getopt.h>
// #include <string.h>
// #include <unistd.h>
// #include <sys/types.h>
// #include <sys/utsname.h> /* uname */
// #include <locale.h> /* setlocale */
// #include <errno.h>
//
// /* alpm */
// #include <alpm.h>
// #include <alpm_list.h>
//
// /* pacman */
// #include "pacman.h"
// #include "util.h"
// #include "conf.h"
// #include "sighandler.h"
// /* list of targets specified on command line */

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
    let agent = format!("crystal/{} ({} {})", PACKAGE_VERSION, "linux", "x86_64");
    // 	if(len >= 100) {
    // 		pm_printf(ALPM_LOG_WARNING, _("HTTP_USER_AGENT truncated\n"));
    // 	}
    //
    env::set_var("HTTP_USER_AGENT", agent);
}

/// Free the resources.
///
/// * `ret` the return value
fn cleanup(ret: i32) {
    //TODO:implement this
    // remove_soft_interrupt_handler();
    // if(config) {
    // 	/* free alpm library resources */
    // 	if(config.handle && alpm_release(config.handle) == -1) {
    // 		pm_printf(ALPM_LOG_ERROR, "error releasing alpm library\n");
    // 	}
    //
    // 	config_free(config);
    // 	config = NULL;
    // }
    //
    // /* free memory */
    // FREELIST(pm_targets);
    std::process::exit(ret);
}

// /** Print command line to logfile.
//  * @param argc
//  * @param argv
//  */
// static void cl_to_log(int argc, char *argv[])
// {
// 	size_t size = 0;
// 	int i;
// 	for(i = 0; i < argc; i++) {
// 		size += strlen(argv[i]) + 1;
// 	}
// 	if(!size) {
// 		return;
// 	}
// 	char *cl_text = malloc(size);
// 	if(!cl_text) {
// 		return;
// 	}
// 	char *p = cl_text;
// 	for(i = 0; i < argc - 1; i++) {
// 		strcpy(p, argv[i]);
// 		p += strlen(argv[i]);
// 		*p++ = ' ';
// 	}
// 	strcpy(p, argv[i]);
// 	alpm_logaction(config.handle, PACMAN_CALLER_PREFIX,
// 			"Running '%s'\n", cl_text);
// 	free(cl_text);
// }

/// Main function.
pub fn main() {
    let argv: Vec<String> = env::args().collect();
    let mut ret: i32 = 0;
    let mut config: Config;
    let mut handle: Handle;
    let myuid: u32 = unsafe { libc::getuid() }; //uid_t myuid = getuid();
    let pm_targets: Vec<String>;

    /* i18n init */
    // #if defined(ENABLE_NLS)
    // 	localize();
    // #endif

    /* set user agent for downloading */
    setuseragent();

    /* init config data */
    config = Config::new();

    // install_soft_interrupt_handler();

    if unsafe { libc::isatty(libc::STDOUT_FILENO as i32) } == 0 {
        /* disable progressbar if the output is redirected */
        config.noprogressbar = 1;
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
    match config.parseargs(argv) {
        Ok(targets) => pm_targets = targets,
        Err(()) => {
            cleanup(1);
            return;
        }
    }

    /* check if we have sufficient permission for the requested operation */
    if myuid > 0 && config.needs_root() {
        error!("you cannot perform this operation unless you are root.");
        cleanup(1);
    }

    if config.sysroot != "" && (unsafe {
        libc::chroot(&config.sysroot.as_bytes()[0] as *const u8 as *const i8) != 0
    } || !env::set_current_dir(&std::path::Path::new("/")).is_ok())
    {
        error!("chroot to {} failed: ()\n", config.sysroot); //, libc::strerror(errno));
        cleanup(1);
    }

    // /* we support reading targets from stdin if a cmdline parameter is '-' */
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
    handle = match parseconfig(&config.configfile.clone(), &mut config) {
        Err(ret) => {
            cleanup(ret as i32);
            return;
        }
        Ok(h) => h
    };

    /* noask is meant to be non-interactive */
    if config.noask {
        config.noconfirm = true;
    }

    /* set up the print operations */
    if config.print && config.op_s_clean == 0 {
        config.noconfirm = true;
        config.flags.NOCONFLICTS = true;
        config.flags.NOLOCK = true;
        /* Display only errors */
        config.logmask.ALPM_LOG_WARNING = false;
    }

    if config.verbose > 0 {
        println!("Root      : {}", handle.alpm_option_get_root());
        println!("Conf File : {}", config.configfile);
        println!("DB Path   : {}", handle.alpm_option_get_dbpath());
        print!("Cache Dirs: ");
        for dir in handle.alpm_option_get_cachedirs() {
            print!("{}  ", dir);
        }
        println!();
        print!("Hook Dirs : ");
        for dir in handle.alpm_option_get_hookdirs() {
            print!("{}  ", dir);
        }
        println!();
        println!("Lock File : {}", handle.alpm_option_get_lockfile());
        println!("Log File  : {}", handle.alpm_option_get_logfile());
        println!("GPG Dir   : {}", handle.alpm_option_get_gpgdir());
        print!("Targets   :");
        for target in &pm_targets {
            print!("{}  ", target);
        }
        println!();
    }

    // /* Log command line */
    // if(needs_root()) {
    // 	cl_to_log(argc, argv);
    // }

    /* start the requested operation */
    // unimplemented!("Done with parsing");
    match &config.op {
        &Some(DATABASE) => match pacman_database(pm_targets, &mut config,&mut handle) {
            Err(e) => (ret = e),
            _ => {}
        },
        &Some(REMOVE) => match pacman_remove(pm_targets, &mut config,&mut handle) {
            Err(e) => (ret = e),
            _ => {}
        },
        &Some(UPGRADE) => match pacman_upgrade(pm_targets, &mut config,&mut handle) {
            Err(_) => (ret = 1),
            _ => {}
        },
        &Some(QUERY) => match pacman_query(pm_targets, &mut config,&mut handle) {
            Err(e) => (ret = e),
            _ => {}
        },
        &Some(SYNC) => match pacman_sync(pm_targets, &mut config, &mut handle) {
            Err(_) => (ret = 1),
            _ => {}
        },
        &Some(DEPTEST) => match pacman_deptest(pm_targets, &mut config,&mut handle) {
            Err(e) => (ret = e),
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
    //
    cleanup(ret);
}
