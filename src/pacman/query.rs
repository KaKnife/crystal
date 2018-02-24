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
use super::*;
use super::alpm::*;

const LOCAL_PREFIX: &str = "local/";

// /* check if filename exists in PATH */
// fn search_path(filename: &mut String, struct stat *bufptr) -> i32
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

fn print_query_fileowner(filename: &String, info: &Package, config: &Config) {
    if !config.quiet {
        let colstr = &config.colstr;
        print!(
            "{} is owned by {}{} {}{}{}\n",
            filename,
            colstr.title,
            info.get_name(),
            colstr.version,
            info.get_version(),
            colstr.nocolor
        );
    } else {
        print!("{}\n", info.get_name());
    }
}

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

fn query_fileowner(targets: &Vec<String>) -> Result<()> {
    unimplemented!();
    // 	int ret = 0;
    // 	const char *root = alpm_option_get_root(config.handle);
    // 	size_t rootlen = strlen(root);
    // 	alpm_list_t *t;
    // 	Database *db_local;
    // 	alpm_list_t *packages;
    //
    // 	/* This code is here for safety only */
    // 	if(targets == NULL) {
    // 		pm_printf(ALPM_LOG_ERROR, _("no file was specified for --owns\n"));
    // 		return 1;
    // 	}
    //
    // 	db_local = alpm_get_localdb(config.handle);
    // 	packages = get_pkgcache(db_local);
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
    // 			if(alpm_filelist_contains(get_files(i.data), rel_path)) {
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
}

/// search the local database for a matching package
fn query_search(targets: &Vec<String>, config: &Config, handle: &mut Handle) -> Result<()> {
    let tem_handle = &handle.clone();
    let db_local: &mut Database = handle.get_localdb_mut();
    dump_pkg_search(
        db_local,
        targets,
        0,
        &config.colstr,
        tem_handle,
        config.quiet,
    )
}

fn pkg_get_locality(pkg: &Package, handle: &Handle) -> u8 {
    let pkgname = pkg.get_name();
    let sync_dbs = handle.get_syncdbs();

    for data in sync_dbs {
        if data.get_pkg(pkgname).is_ok() {
            return PKG_LOCALITY_NATIVE;
        }
    }
    return PKG_LOCALITY_FOREIGN;
}

fn is_unrequired(pkg: &Package, level: u8, db_local: &Database, dbs_sync: &Vec<Database>) -> bool {
    let mut requiredby = pkg.compute_requiredby(false, db_local, dbs_sync).unwrap();
    if requiredby.is_empty() {
        if level == 1 {
            requiredby = pkg.compute_optionalfor(db_local, dbs_sync).unwrap();
        }
        if requiredby.is_empty() {
            return true;
        }
    }
    return false;
}

fn filter(pkg: &Package, config: &Config, handle: &Handle) -> bool {
    match pkg.get_reason() {
        /* check if this package was installed as a dependency */
        Ok(&PackageReason::Dependency) if config.op_q_explicit != 0 => return false,
        /* check if this package was explicitly installed */
        Ok(&PackageReason::Explicit) if config.op_q_deps != 0 => return false,
        _ => {}
    }
    /* check if this pkg is or isn't in a sync DB */
    if config.op_q_locality != 0 && config.op_q_locality != pkg_get_locality(pkg, handle) {
        return false;
    }
    /* check if this pkg is unrequired */
    if config.op_q_unrequired != 0
        && !is_unrequired(
            pkg,
            config.op_q_unrequired,
            &handle.db_local,
            &handle.dbs_sync,
        ) {
        return false;
    }
    /* check if this pkg is outdated */
    if config.op_q_upgrade != 0 && pkg.newversion(handle.get_syncdbs()).is_none() {
        return false;
    }
    return true;
}

fn display(pkg: &Package, config: &Config, handle: &Handle) -> i32 {
    let mut ret = 0;

    if config.op_q_info != 0 {
        if config.op_q_isfile != 0 {
            match pkg.dump_full(false, &handle.db_local, &handle.dbs_sync) {
                Err(e) => error!("Error dumping package {} ({})", pkg.get_name(), e),
                Ok(_) => {}
            };
        } else {
            match pkg.dump_full(config.op_q_info > 1, &handle.db_local, &handle.dbs_sync) {
                Err(e) => error!("Error dumping package {} ({})", pkg.get_name(), e),
                Ok(_) => {}
            };;
        }
    }
    if config.op_q_list {
        dump_pkg_files(pkg, config.quiet);
    }
    if config.op_q_changelog != 0 {
        dump_pkg_changelog(pkg);
    }
    match config.op_q_check {
        0 => {}
        1 => ret = pkg.check_fast(),
        _ => ret = pkg.check_full(),
    }
    if config.op_q_info == 0 && !config.op_q_list && config.op_q_changelog == 0
        && config.op_q_check == 0
    {
        if !config.quiet {
            let colstr = &config.colstr;
            print!("{} {}", pkg.get_name(), pkg.get_version(),);

            if config.op_q_upgrade != 0 {
                let newpkg = pkg.newversion(handle.get_syncdbs()).unwrap();
                print!(" . {}", newpkg.get_version(),);

                if handle.pkg_should_ignore(pkg) {
                    print!(" {}", "[ignored]");
                }
            }

            print!("\n");
        } else {
            print!("{}\n", pkg.get_name());
        }
    }
    return ret;
}

fn query_group(targets: &Vec<String>, config: &Config, handle: &mut Handle) -> Result<()> {
    let mut ret = 0;
    let handle_clone = &mut handle.clone();
    let db_local: &mut Database = handle.get_localdb_mut();

    let op_q_explicit = config.op_q_explicit;
    let op_q_deps = config.op_q_deps;

    if targets.is_empty() {
        for grp in db_local.get_groupcache_mut() {
            for pkg in &mut grp.packages {
                if !filter(pkg, config, handle_clone) {
                    continue;
                }
                print!("{} {}\n", grp.name, pkg.get_name());
            }
        }
    } else {
        for grpname in targets {
            match db_local.get_group_mut(grpname) {
                Ok(grp) => for ref mut data in &mut grp.packages {
                    if !filter(data, config, handle_clone) {
                        continue;
                    }
                    if !config.quiet {
                        print!("{} {}\n", grpname, data.get_name());
                    } else {
                        print!("{}\n", data.get_name());
                    }
                },
                Err(_) => {
                    error!("group '{}' was not found", grpname);
                    ret += 1;
                }
            }
        }
    }
    return Err(Error::Other);
}

pub fn pacman_query(targets: Vec<String>, config: &mut Config, handle: &mut Handle) -> Result<()> {
    // let handle_clone: &Handle = &handle.clone();
    let op_q_explicit = config.op_q_explicit;
    let op_q_deps = config.op_q_deps;
    let pkg_cache;
    let mut ret: Result<()> = Ok(());
    let mut is_match: bool = false;
    let mut pkg: &Package;
    let mut db_local: &Database;

    {
        // let handle_clone = &handle.clone();
        handle.get_localdb_mut().load_pkgcache();
    }

    /* First: operations that do not require targets */

    /* search for a package */
    if config.op_q_search {
        return query_search(&targets, config, handle);
    }

    /* looking for groups */
    if config.group != 0 {
        return query_group(&targets, config, handle);
    }

    if config.op_q_locality != 0 || config.op_q_upgrade != 0 {
        check_syncdbs(1, true, handle)?;
    }

    db_local = handle.get_localdb();
    pkg_cache = db_local.get_pkgcache()?;
    /* operations on all packages in the local DB
     * valid: no-op (plain -Q), list, info, check
     * invalid: isfile, owns */
    if targets.is_empty() {
        if config.op_q_isfile != 0 || config.op_q_owns != 0 {
            error!("no targets specified (use -h for help)");
            return Err(Error::Other);
        }

        match db_local.get_pkgcache() {
            Ok(d) => for mut pkg in d {
                if filter(pkg, config, handle) {
                    let value = display(&mut pkg, config, handle);
                    if value != 0 {
                        ret = Err(Error::Other);
                    }
                    is_match = true;
                }
            },
            Err(e) => unimplemented!("{}", e),
        }

        if !is_match {
            ret = Err(Error::Other);
        }
        return ret;
    }

    /* Second: operations that require target(s) */

    /* determine the owner of a file */
    if config.op_q_owns != 0 {
        return query_fileowner(&targets);
    }

    /* operations on named packages in the local DB
     * valid: no-op (plain -Q), list, info, check */
    for strname in targets {
        /* strip leading part of "local/pkgname" */
        let strname = String::from(strname.trim_left_matches(LOCAL_PREFIX));
        if config.op_q_isfile != 0 {
            pkg = match handle.pkg_load(&strname, 1, &SigLevel::default()) {
                Ok(pkg) => pkg,
                Err(e) => {
                    error!("could not load package '{}': {}", strname, e);
                    ret = Err(Error::Other);
                    continue;
                }
            }
        } else {
            pkg = match db_local.get_pkg(&strname) {
                Err(_) => {
                    match alpm::alpm_find_satisfier(&pkg_cache, &strname) {
                        None => {
                            error!("package '{}' was not found", strname);
                            unimplemented!();
                            // if(!config.op_q_isfile && access(strname, R_OK) == 0) {
                            // 	pm_printf(ALPM_LOG_WARNING,
                            // 			_("'{}' is a file, you might want to use {}.\n"),
                            // 			strname, "-p/--file");
                            // }
                            ret = Err(Error::Other);
                            continue;
                        }
                        Some(pkg) => pkg,
                    }
                }
                Ok(pkg) => pkg,
            };
        }

        if filter(pkg, config, handle) {
            if display(pkg, config, handle) != 0 {
                ret = Err(Error::Other);
            }
            is_match = true;
        }

        if config.op_q_isfile != 0 {
            unimplemented!();
            // 	free(pkg);
            // pkg = NULL;
        }
    }

    if !is_match {
        ret = Err(Error::Other);
    }

    return ret;
}
