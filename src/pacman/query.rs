use super::*;
/*
 *  query.c
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

// #include <stdlib.h>
// #include <stdio.h>
// #include <stdint.h>
// #include <limits.h>
// #include <sys/stat.h>
// #include <unistd.h>
// #include <errno.h>
//
// #include <alpm.h>
// #include <alpm_list.h>
//
// /* pacman */
// #include "pacman.h"
// #include "package.h"
// #include "check.h"
// #include "conf.h"
// #include "util.h"

// #define LOCAL_PREFIX "local/"

// /* check if filename exists in PATH */
// static int search_path(char **filename, struct stat *bufptr)
// {
// 	char *envpath, *envpathsplit, *path, *fullname;
// 	size_t flen;
//
// 	if((envpath = getenv("PATH")) == NULL) {
// 		return -1;
// 	}
// 	if((envpath = envpathsplit = strdup(envpath)) == NULL) {
// 		return -1;
// 	}
//
// 	flen = strlen(*filename);
//
// 	while((path = strsep(&envpathsplit, ":")) != NULL) {
// 		size_t plen = strlen(path);
//
// 		/* strip the trailing slash if one exists */
// 		while(path[plen - 1] == '/') {
// 			path[--plen] = '\0';
// 		}
//
// 		fullname = malloc(plen + flen + 2);
// 		if(!fullname) {
// 			free(envpath);
// 			return -1;
// 		}
// 		sprintf(fullname, "{}/{}", path, *filename);
//
// 		if(lstat(fullname, bufptr) == 0) {
// 			free(*filename);
// 			*filename = fullname;
// 			free(envpath);
// 			return 0;
// 		}
// 		free(fullname);
// 	}
// 	free(envpath);
// 	return -1;
// }

// static void print_query_fileowner(const char *filename, alpm_pkg_t *info)
// {
// 	if(!config.quiet) {
// 		const colstr_t *colstr = &config.colstr;
// 		printf(_("{} is owned by {}{} {}{}{}\n"), filename, colstr.title,
// 				alpm_pkg_get_name(info), colstr.version, alpm_pkg_get_version(info),
// 				colstr.nocolor);
// 	} else {
// 		printf("{}\n", alpm_pkg_get_name(info));
// 	}
// }

// /** Resolve the canonicalized absolute path of a symlink.
//  * @param path path to resolve
//  * @param resolved_path destination for the resolved path, will be malloc'd if
//  * NULL
//  * @return the resolved path
//  */
// static char *lrealpath(const char *path, char *resolved_path)
// {
// 	const char *bname = mbasename(path);
// 	char *rpath = NULL, *dname = NULL;
// 	int success = 0;
//
// 	if(strcmp(bname, ".") == 0 || strcmp(bname, "..") == 0) {
// 		/* the entire path needs to be resolved */
// 		return realpath(path, resolved_path);
// 	}
//
// 	if(!(dname = mdirname(path))) {
// 		goto cleanup;
// 	}
// 	if(!(rpath = realpath(dname, NULL))) {
// 		goto cleanup;
// 	}
// 	if(!resolved_path) {
// 		if(!(resolved_path = malloc(strlen(rpath) + strlen(bname) + 2))) {
// 			goto cleanup;
// 		}
// 	}
//
// 	strcpy(resolved_path, rpath);
// 	if(resolved_path[strlen(resolved_path) - 1] != '/') {
// 		strcat(resolved_path, "/");
// 	}
// 	strcat(resolved_path, bname);
// 	success = 1;
//
// cleanup:
// 	free(dname);
// 	free(rpath);
//
// 	return (success ? resolved_path : NULL);
// }

// static int query_fileowner(alpm_list_t *targets)
// {
// 	int ret = 0;
// 	const char *root = alpm_option_get_root(config.handle);
// 	size_t rootlen = strlen(root);
// 	alpm_list_t *t;
// 	alpm_db_t *db_local;
// 	alpm_list_t *packages;
//
// 	/* This code is here for safety only */
// 	if(targets == NULL) {
// 		pm_printf(ALPM_LOG_ERROR, _("no file was specified for --owns\n"));
// 		return 1;
// 	}
//
// 	db_local = alpm_get_localdb(config.handle);
// 	packages = alpm_db_get_pkgcache(db_local);
//
// 	for(t = targets; t; t = alpm_list_next(t)) {
// 		char *filename = NULL;
// 		char rpath[PATH_MAX], *rel_path;
// 		struct stat buf;
// 		alpm_list_t *i;
// 		size_t len, is_dir;
// 		unsigned int found = 0;
//
// 		if((filename = strdup(t.data)) == NULL) {
// 			goto targcleanup;
// 		}
//
// 		/* trailing '/' causes lstat to dereference directory symlinks */
// 		len = strlen(filename) - 1;
// 		while(len > 0 && filename[len] == '/') {
// 			filename[len--] = '\0';
// 		}
//
// 		if(lstat(filename, &buf) == -1) {
// 			/* if it is not a path but a program name, then check in PATH */
// 			if(strchr(filename, '/') == NULL) {
// 				if(search_path(&filename, &buf) == -1) {
// 					pm_printf(ALPM_LOG_ERROR, _("failed to find '{}' in PATH: {}\n"),
// 							filename, strerror(errno));
// 					goto targcleanup;
// 				}
// 			} else {
// 				pm_printf(ALPM_LOG_ERROR, _("failed to read file '{}': {}\n"),
// 						filename, strerror(errno));
// 				goto targcleanup;
// 			}
// 		}
//
// 		if(!lrealpath(filename, rpath)) {
// 			pm_printf(ALPM_LOG_ERROR, _("cannot determine real path for '{}': {}\n"),
// 					filename, strerror(errno));
// 			goto targcleanup;
// 		}
//
// 		if(strncmp(rpath, root, rootlen) != 0) {
// 			/* file is outside root, we know nothing can own it */
// 			pm_printf(ALPM_LOG_ERROR, _("No package owns {}\n"), filename);
// 			goto targcleanup;
// 		}
//
// 		rel_path = rpath + rootlen;
//
// 		if((is_dir = S_ISDIR(buf.st_mode))) {
// 			size_t rlen = strlen(rpath);
// 			if(rlen + 2 >= PATH_MAX) {
// 					pm_printf(ALPM_LOG_ERROR, _("path too long: {}/\n"), rpath);
// 					goto targcleanup;
// 			}
// 			strcat(rpath + rlen, "/");
// 		}
//
// 		for(i = packages; i && (!found || is_dir); i = alpm_list_next(i)) {
// 			if(alpm_filelist_contains(alpm_pkg_get_files(i.data), rel_path)) {
// 				print_query_fileowner(rpath, i.data);
// 				found = 1;
// 			}
// 		}
// 		if(!found) {
// 			pm_printf(ALPM_LOG_ERROR, _("No package owns {}\n"), filename);
// 		}
//
// targcleanup:
// 		if(!found) {
// 			ret++;
// 		}
// 		free(filename);
// 	}
//
// 	return ret;
// }

/// search the local database for a matching package
fn query_search(targets: &Vec<String>, config: &config_t) -> i32 {
    let db_local: &alpm_db_t = config.handle.alpm_get_localdb();
    return dump_pkg_search(db_local, targets, 0);
}

fn pkg_get_locality(pkg: &alpm_pkg_t, config: &config_t) -> u8 {
    let pkgname = &pkg.alpm_pkg_get_name();
    // alpm_list_t *j;
    let sync_dbs = config.handle.alpm_get_syncdbs()
    // {
    //     &Some(ref s) => s,
    //     &None => panic!(),
    // }
    ;

    for data in sync_dbs {
        if data.alpm_db_get_pkg(pkgname).is_some() {
            return PKG_LOCALITY_NATIVE;
        }
    }
    return PKG_LOCALITY_FOREIGN;
}

// static int is_unrequired(alpm_pkg_t *pkg, unsigned short level)
// {
// 	alpm_list_t *requiredby = alpm_pkg_compute_requiredby(pkg);
// 	if(requiredby == NULL) {
// 		if(level == 1) {
// 			requiredby = alpm_pkg_compute_optionalfor(pkg);
// 		}
// 		if(requiredby == NULL) {
// 			return 1;
// 		}
// 	}
// 	FREELIST(requiredby);
// 	return 0;
// }

fn filter(pkg: &alpm_pkg_t, config: &config_t) -> i32 {
    unimplemented!();

    // match pkg.alpm_pkg_get_reason() {
    //     /* check if this package was installed as a dependency */
    //     ALPM_PKG_REASON_DEPEND if config.op_q_explicit != 0 => return 0,
    //     /* check if this package was explicitly installed */
    //     ALPM_PKG_REASON_EXPLICIT if config.op_q_deps != 0 => return 0,
    // }
    // /* check if this pkg is or isn't in a sync DB */
    // if config.op_q_locality != 0 && config.op_q_locality != pkg_get_locality(pkg) {
    //     return 0;
    // }
    // /* check if this pkg is unrequired */
    // if config.op_q_unrequired != 0 && !is_unrequired(pkg, config.op_q_unrequired) {
    //     return 0;
    // }
    // /* check if this pkg is outdated */
    // if config.op_q_upgrade != 0
    //     && (alpm_sync_newversion(pkg, alpm_get_syncdbs(config.handle)) == NULL)
    // {
    //     return 0;
    // }
    // return 1;
}

fn display(pkg: &alpm_pkg_t) -> i32 {
    unimplemented!();
    // 	int ret = 0;
    //
    // 	if(config.op_q_info) {
    // 		if(config.op_q_isfile) {
    // 			dump_pkg_full(pkg, 0);
    // 		} else {
    // 			dump_pkg_full(pkg, config.op_q_info > 1);
    // 		}
    // 	}
    // 	if(config.op_q_list) {
    // 		dump_pkg_files(pkg, config.quiet);
    // 	}
    // 	if(config.op_q_changelog) {
    // 		dump_pkg_changelog(pkg);
    // 	}
    // 	if(config.op_q_check) {
    // 		if(config.op_q_check == 1) {
    // 			ret = check_pkg_fast(pkg);
    // 		} else {
    // 			ret = check_pkg_full(pkg);
    // 		}
    // 	}
    // 	if(!config.op_q_info && !config.op_q_list
    // 			&& !config.op_q_changelog && !config.op_q_check) {
    // 		if(!config.quiet) {
    // 			const colstr_t *colstr = &config.colstr;
    // 			printf("{}{} {}{}{}", colstr.title, alpm_pkg_get_name(pkg),
    // 					colstr.version, alpm_pkg_get_version(pkg), colstr.nocolor);
    //
    // 			if(config.op_q_upgrade) {
    // 				alpm_pkg_t *newpkg = alpm_sync_newversion(pkg, alpm_get_syncdbs(config.handle));
    // 				printf(" . {}{}{}", colstr.version, alpm_pkg_get_version(newpkg), colstr.nocolor);
    //
    // 				if(alpm_pkg_should_ignore(config.handle, pkg)) {
    // 					printf(" {}", _("[ignored]"));
    // 				}
    // 			}
    //
    // 			printf("\n");
    // 		} else {
    // 			printf("{}\n", alpm_pkg_get_name(pkg));
    // 		}
    // 	}
    // 	return ret;
}

fn query_group(targets: &Vec<String>, config: &mut config_t) -> i32 {
    let mut ret = 0;
    let op_q_explicit = config.op_q_explicit;
    let op_q_deps = config.op_q_deps;
    let db_local: &mut alpm_db_t = config.handle.alpm_get_localdb_mut();

    let filter = |pkg: &alpm_pkg_t| -> i32 {
        match pkg.alpm_pkg_get_reason() {
            /* check if this package was installed as a dependency */
            alpm_pkgreason_t::ALPM_PKG_REASON_DEPEND if op_q_explicit != 0 => return 0,
            /* check if this package was explicitly installed */
            alpm_pkgreason_t::ALPM_PKG_REASON_EXPLICIT if op_q_deps != 0 => return 0,
            _ => {}
        }
        unimplemented!();
        // /* check if this pkg is or isn't in a sync DB */
        // if config.op_q_locality != 0 && config.op_q_locality != pkg_get_locality(pkg) {
        //     return 0;
        // }
        // /* check if this pkg is unrequired */
        // if config.op_q_unrequired != 0 && !is_unrequired(pkg, config.op_q_unrequired) {
        //     return 0;
        // }
        // /* check if this pkg is outdated */
        // if config.op_q_upgrade != 0
        //     && (alpm_sync_newversion(pkg, alpm_get_syncdbs(config.handle)) == NULL)
        // {
        //     return 0;
        // }
        // return 1;
    };

    if targets.is_empty() {
        for grp in db_local.alpm_db_get_groupcache() {
            for pkg in &grp.packages {
                if filter(pkg) == 0 {
                    continue;
                }
                println!("{} {}", grp.name, pkg.alpm_pkg_get_name());
            }
        }
    } else {
        for grpname in targets {
            match db_local.alpm_db_get_group(grpname) {
                Some(grp) => for ref data in grp.packages {
                    if filter(data) == 0 {
                        continue;
                    }
                    if !config.quiet {
                        println!("{} {}", grpname, data.alpm_pkg_get_name());
                    } else {
                        println!("{}", data.alpm_pkg_get_name());
                    }
                },
                None => {
                    error!("group '{}' was not found", grpname);
                    ret += 1;
                }
            }
        }
    }
    return ret;
}

pub fn pacman_query(targets: Vec<String>, config: &mut config_t) -> std::result::Result<(), i32> {
    // 	int ret = 0;
    let mut ret = Ok(());
    // 	int match = 0;
    let mut is_match = false;
    // 	alpm_list_t *i;
    // 	alpm_pkg_t *pkg = NULL;
    // 	alpm_db_t *db_local;
    let mut db_local;

    /* First: operations that do not require targets */

    /* search for a package */
    if config.op_q_search != 0 {
        match query_search(&targets, config) {
            0 => return Ok(()),
            e => return Err(e),
        };
    }

    /* looking for groups */
    if config.group != 0 {
        unimplemented!();
        match query_group(&targets, config) {
            0 => return Ok(()),
            e => return Err(e),
        };
    }

    if config.op_q_locality != 0 || config.op_q_upgrade != 0 {
        unimplemented!();
        // 		if(check_syncdbs(1, 1)) {
        // 			return 1;
        // 		}
    }

    db_local = config.handle.alpm_get_localdb();

    /* operations on all packages in the local DB
     * valid: no-op (plain -Q), list, info, check
     * invalid: isfile, owns */
    if targets.is_empty() {
        unimplemented!();
        // 		if(config.op_q_isfile || config.op_q_owns) {
        // 			pm_printf(ALPM_LOG_ERROR, _("no targets specified (use -h for help)\n"));
        // 			return 1;
        // 		}
        //
        // 		for(i = alpm_db_get_pkgcache(db_local); i; i = alpm_list_next(i)) {
        // 			pkg = i.data;
        // 			if(filter(pkg)) {
        // 				int value = display(pkg);
        // 				if(value != 0) {
        // 					ret = 1;
        // 				}
        // 				match = 1;
        // 			}
        // 		}
        // 		if(!match) {
        // 			ret = 1;
        // 		}
        // 		return ret;
    }

    /* Second: operations that require target(s) */

    /* determine the owner of a file */
    if config.op_q_owns != 0 {
        unimplemented!();
        // ret = query_fileowner(targets);
        // return ret;
    }

    /* operations on named packages in the local DB
     * valid: no-op (plain -Q), list, info, check */
    for strname in targets {
        unimplemented!();
        // 		const char *strname = i.data;
        //
        // 		/* strip leading part of "local/pkgname" */
        // 		if(strncmp(strname, LOCAL_PREFIX, strlen(LOCAL_PREFIX)) == 0) {
        // 			strname += strlen(LOCAL_PREFIX);
        // 		}
        //
        // 		if(config.op_q_isfile) {
        // 			alpm_pkg_load(config.handle, strname, 1, 0, &pkg);
        //
        // 			if(pkg == NULL) {
        // 				pm_printf(ALPM_LOG_ERROR,
        // 						_("could not load package '{}': {}\n"), strname,
        // 						alpm_strerror(alpm_errno(config.handle)));
        // 			}
        // 		} else {
        // 			pkg = alpm_db_get_pkg(db_local, strname);
        // 			if(pkg == NULL) {
        // 				pkg = alpm_find_satisfier(alpm_db_get_pkgcache(db_local), strname);
        // 			}
        //
        // 			if(pkg == NULL) {
        // 				pm_printf(ALPM_LOG_ERROR,
        // 						_("package '{}' was not found\n"), strname);
        // 				if(!config.op_q_isfile && access(strname, R_OK) == 0) {
        // 					pm_printf(ALPM_LOG_WARNING,
        // 							_("'{}' is a file, you might want to use {}.\n"),
        // 							strname, "-p/--file");
        // 				}
        // 			}
        // 		}
        //
        // 		if(pkg == NULL) {
        // 			ret = 1;
        // 			continue;
        // 		}
        //
        // 		if(filter(pkg)) {
        // 			int value = display(pkg);
        // 			if(value != 0) {
        // 				ret = 1;
        // 			}
        // 			match = 1;
        // 		}
        //
        // 		if(config.op_q_isfile) {
        // 			alpm_pkg_free(pkg);
        // 			pkg = NULL;
        // 		}
    }

    if !is_match {
        ret = Err(1);
    }

    return ret;
    // Err(1)
}
