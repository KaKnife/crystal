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
use super::{check_syncdbs, dump_pkg_changelog, dump_pkg_files, dump_pkg_search, Config,
            PKG_LOCALITY_FOREIGN, PKG_LOCALITY_NATIVE};
use alpm::{find_satisfier, SigLevel};
use {Database, Error, Handle, Package, PackageReason, Result};

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
        info!(
            "{} is owned by {} {}",
            filename,
            info.get_name(),
            info.get_version(),
        );
    } else {
        info!("{}\n", info.get_name());
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
    // 	const char *root = option_get_root(config.handle);
    // 	size_t rootlen = strlen(root);
    // 	list_t *t;
    // 	Database *db_local;
    // 	list_t *packages;
    //
    // 	/* This code is here for safety only */
    // 	if(targets == NULL) {
    // 		pm_printf(ALPM_LOG_ERROR, _("no file was specified for --owns\n"));
    // 		return 1;
    // 	}
    //
    // 	db_local = get_localdb(config.handle);
    // 	packages = get_pkgcache(db_local);
    //
    // 	for(t = targets; t; t = list_next(t)) {
    // 		char *filename = NULL;
    // 		char rpath[PATH_MAX], *rel_path;
    // 		struct stat buf;
    // 		list_t *i;
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
    // 		for(i = packages; i && (!found || is_dir); i = list_next(i)) {
    // 			if(filelist_contains(get_files(i.data), rel_path)) {
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
    dump_pkg_search(db_local, targets, 0, tem_handle, config.quiet)
}

fn pkg_get_locality(pkg: &Package, handle: &Handle) -> usize {
    for data in handle.get_syncdbs() {
        if data.get_pkg(pkg.get_name()).is_ok() {
            return PKG_LOCALITY_NATIVE;
        }
    }
    PKG_LOCALITY_FOREIGN
}

fn is_unrequired(
    pkg: &Package,
    level: usize,
    db_local: &Database,
    dbs_sync: &Vec<Database>,
) -> bool {
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
        Ok(&PackageReason::Dependency) if config.explicit => return false,
        /* check if this package was explicitly installed */
        Ok(&PackageReason::Explicit) if config.deps => return false,
        _ => {}
    }
    /* check if this pkg is or isn't in a sync DB */
    if config.locality != 0 && config.locality != pkg_get_locality(pkg, handle) {
        return false;
    }
    /* check if this pkg is unrequired */
    if config.unrequired != 0
        && !is_unrequired(pkg, config.unrequired, &handle.db_local, &handle.dbs_sync)
    {
        return false;
    }
    /* check if this pkg is outdated */
    if config.q_upgrade && pkg.newversion(handle.get_syncdbs()).is_none() {
        return false;
    }
    return true;
}

fn display(pkg: &Package, config: &Config, handle: &Handle) -> i32 {
    let mut ret = 0;

    if config.info != 0 {
        if config.isfile {
            if let Err(e) = pkg.dump_full(false, &handle.db_local, &handle.dbs_sync) {
                error!("Error dumping package {} ({})", pkg.get_name(), e);
            }
        } else {
            if let Err(e) = pkg.dump_full(config.info > 1, &handle.db_local, &handle.dbs_sync) {
                error!("Error dumping package {} ({})", pkg.get_name(), e);
            }
        }
    }
    if config.list {
        dump_pkg_files(pkg, config.quiet);
    }
    if config.changelog {
        dump_pkg_changelog(pkg);
    }
    match config.check {
        0 => {}
        1 => ret = pkg.check_fast(),
        _ => ret = pkg.check_full(),
    }
    if config.info == 0 && !config.list && !config.changelog && config.check == 0 {
        if !config.quiet {
            let print = format!("{} {}", pkg.get_name(), pkg.get_version(),);

            if config.q_upgrade {
                let newpkg = pkg.newversion(handle.get_syncdbs()).unwrap();
                let print = format!("{} . {}", print, newpkg.get_version(),);

                if handle.pkg_should_ignore(pkg) {
                    let print = format!("{} {}", print, "[ignored]");
                }
            }

            info!("{}", print);
        } else {
            info!("{}", pkg.get_name());
        }
    }
    return ret;
}

fn query_group(targets: &Vec<String>, config: &Config, handle: &mut Handle) -> Result<()> {
    let mut ret = 0;
    let handle_clone = &mut handle.clone();
    let db_local: &mut Database = handle.get_localdb_mut();

    let op_q_explicit = config.explicit;
    let op_q_deps = config.deps;

    if targets.is_empty() {
        for grp in db_local.get_groupcache_mut() {
            for pkg in &mut grp.packages {
                if !filter(pkg, config, handle_clone) {
                    continue;
                }
                info!("{} {}", grp.name, pkg.get_name());
            }
        }
    } else {
        for grpname in targets {
            if let Ok(grp) = db_local.get_group_mut(grpname) {
                for ref mut data in &mut grp.packages {
                    if !filter(data, config, handle_clone) {
                        continue;
                    }
                    if !config.quiet {
                        info!("{} {}", grpname, data.get_name());
                    } else {
                        info!("{}", data.get_name());
                    }
                }
            } else {
                error!("group '{}' was not found", grpname);
                ret += 1;
            }
        }
    }
    return Err(Error::Other);
}

pub fn pacman_query(targets: Vec<String>, config: Config, mut handle: Handle) -> Result<()> {
    // let handle_clone: &Handle = &handle.clone();
    let op_q_explicit = config.explicit;
    let op_q_deps = config.deps;
    let pkg_cache;
    let mut ret: Result<()> = Ok(());
    let mut is_match: bool = false;
    let mut pkg: &Package;
    let mut db_local: &Database;

    handle.get_localdb_mut().load_pkgcache();

    /* First: operations that do not require targets */

    /* search for a package */
    if config.search {
        return query_search(&targets, &config, &mut handle);
    }

    /* looking for groups */
    if config.group != 0 {
        return query_group(&targets, &config, &mut handle);
    }

    if config.locality != 0 || config.q_upgrade {
        check_syncdbs(1, true, &mut handle)?;
    }

    db_local = handle.get_localdb();
    pkg_cache = db_local.get_pkgcache()?;
    /* operations on all packages in the local DB
     * valid: no-op (plain -Q), list, info, check
     * invalid: isfile, owns */
    if targets.is_empty() {
        if config.isfile || config.owns {
            error!("no targets specified (use -h for help)");
            return Err(Error::Other);
        }

        match db_local.get_pkgcache() {
            Ok(d) => for mut pkg in d {
                if filter(pkg, &config, &handle) {
                    let value = display(&mut pkg, &config, &handle);
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
    if config.owns {
        return query_fileowner(&targets);
    }

    /* operations on named packages in the local DB
     * valid: no-op (plain -Q), list, info, check */
    for strname in targets {
        /* strip leading part of "local/pkgname" */
        let strname = String::from(strname.trim_left_matches(LOCAL_PREFIX));
        if config.isfile {
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
                Ok(pkg) => pkg,
                Err(_) => {
                    match find_satisfier(&pkg_cache, &strname) {
                        None => {
                            error!("package '{}' was not found", strname);
                            unimplemented!();
                            // if(!config.isfile && access(strname, R_OK) == 0) {
                            // warn!(
                            //     "'{}' is a file, you might want to use {}.",
                            //     strname, "-p/--file"
                            // );
                            // }
                            ret = Err(Error::Other);
                            continue;
                        }
                        Some(pkg) => pkg,
                    }
                }
            };
        }

        if filter(pkg, &config, &handle) {
            if display(pkg, &config, &handle) != 0 {
                ret = Err(Error::Other);
            }
            is_match = true;
        }
    }

    if !is_match {
        ret = Err(Error::Other);
    }

    return ret;
}
