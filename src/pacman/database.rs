use super::*;
use super::alpm::*;
/*
 *  database.c
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

/// Modify the 'local' package database.
///
/// * `targets` - a list of packages (as strings) to modify
/// * return - 0 on success, 1 on failure
fn change_install_reason(targets: Vec<String>, config: &mut Config, handle: &mut Handle) -> i32 {
    let mut ret: i32 = 0;
    let reason: PackageReason;

    if targets.len() == 0 {
        error!("no targets specified (use -h for help)");
        return 1;
    }

    if config.flags.all_deps {
        /* --asdeps */
        reason = PackageReason::Dependency;
    } else if config.flags.all_explicit {
        /* --asexplicit */
        reason = PackageReason::Explicit;
    } else {
        error!("no install reason specified (use -h for help)");
        return 1;
    }

    /* Lock database */
    if trans_init(&TransactionFlag::default(), false, handle).is_err() {
        return 1;
    }
    {
        let db_local: &mut Database = handle.get_localdb_mut();
        for pkgname in targets {
            match db_local.get_pkg_mut(&pkgname) {
                None => {
                    error!(
                        "could not set install reason for package {} ()",
                        pkgname /*strerror(errno(config->handle))*/,
                    );
                    ret = 1;
                }
                Some(pkg) => {
                    if pkg.set_reason(reason) != 0 {
                        error!(
                            "could not set install reason for package {} ()",
                            pkgname /*strerror(errno(config->handle))*/,
                        );
                        ret = 1;
                    } else if !config.quiet {
                        match reason {
                            PackageReason::Dependency => {
                                print!(
                                    "{}: install reason has been set to 'installed as dependency'\n",
                                    pkgname
                                );
                            }
                            _ => {
                                print!(
                                    "{}: install reason has been set to 'explicitly installed'\n",
                                    pkgname
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /* Unlock database */
    if !trans_release(handle) {
        return 1;
    }
    return ret;
}

fn check_db_missing_deps(pkglist: &Vec<&Package>, handle: &Handle) -> i32 {
    let mut ret: i32 = 0;
    /* check dependencies */
    let deps = match handle.checkdeps(None, None, pkglist, 0) {
        Err(_) => return -1,
        Ok(deps) => deps,
    };
    for miss in deps {
        let depstring: String = miss.depend.dep_compute_string();
        error!("missing '{}' dependency for '{}'", depstring, miss.target);
        ret += 1;
    }
    return ret;
}

fn check_db_local_files(config: &conf::Config, handle: &mut Handle) -> i32 {
    use std::fs;
    let dbpath: &String;
    let mut ret: i32 = 0;
    let dbdir: fs::ReadDir;
    let mut path: String;

    dbpath = handle.get_dbpath();
    path = format!("{}local", dbpath);
    dbdir = match fs::read_dir(path) {
        Ok(d) => d,
        Err(e) => {
            error!("could not open local database directory: {}", e);
            return 1;
        }
    };

    for entw in dbdir {
        let ent: fs::DirEntry = entw.unwrap();
        let file_name: String = ent.file_name().into_string().unwrap();
        if file_name == "." || file_name == ".." || file_name == "ALPM_DB_VERSION" {
            continue;
        }
        /* check for expected db files in local database */
        path = format!("{}local/{}/desc", dbpath, file_name);
        match fs::File::open(path) {
            Ok(_) => {}
            Err(_e) => {
                error!("'{}': description file is missing", file_name);
                ret += 1;
            }
        }
        path = format!("{}local/{}/files", dbpath, file_name);
        match fs::File::open(path) {
            Ok(_) => {}
            Err(_e) => {
                error!("'{}': file list is missing", file_name);
                ret += 1;
            }
        }
    }

    return ret;
}

fn check_db_local_package_conflicts(pkglist: &Vec<&Package>, handle: &Handle) -> i32 {
    let mut ret: i32 = 0;
    /* check conflicts */
    let data = handle.checkconflicts(&pkglist);
    for conflict in data {
        error!(
            "'{}' conflicts with '{}'",
            conflict.package1, conflict.package2
        );
        ret += 1;
    }
    return ret;
}

struct FileItem {
    file: File,
    pkg: Package,
}

// fn FileItem_cmp(const void *p1, const void *p2): i32
// {
// 	const struct FileItem * fi1 = p1;
// 	const struct FileItem * fi2 = p2;
// 	return strcmp(fi1->file->name, fi2->file->name);
// }

fn check_db_local_filelist_conflicts(pkglist: &Vec<&Package>) -> i32 {
    unimplemented!();
    // 	list_t *i;
    let mut ret = 0;
    // // 	size_t list_size = 4096;
    // // 	size_t offset = 0, j;
    // // 	struct FileItem *all_files;
    // // 	struct FileItem *prev_FileItem = NULL;
    // //
    // // 	all_files = malloc(list_size * sizeof(struct FileItem));
    // let all_files = Vec::new();
    // //
    for pkg in pkglist {
        unimplemented!();
        //     // 		Package *pkg = i->data;
        //     // filelist_t *filelist = pkg_get_files(pkg);
        // let filelist = pkg.pkg_get_files();
        // for file in filelist {
        //         // file_t *file = filelist->files + j;
        //         /* only add files, not directories, to our big list */
        //         if file.name.ends_with('/') {
        //             continue;
        //         }
        //
        //         /* we can finally add it to the list */
        //         all_files.push(FileItem{file:file, pkg:pkg.clone()});
        //     }
    }
    //
    // 	/* now sort the list so we can find duplicates */
    // 	qsort(all_files, offset, sizeof(struct FileItem), FileItem_cmp);
    //
    // 	/* do a 'uniq' style check on the list */
    // 	for(j = 0; j < offset; j++) {
    // 		struct FileItem *FileItem = all_files + j;
    // 		if(prev_FileItem && FileItem_cmp(prev_FileItem, FileItem) == 0) {
    // 			pm_printf(ALPM_LOG_ERROR, "file owned by '%s' and '%s': '%s'\n",
    // 					pkg_get_name(prev_FileItem->pkg),
    // 					pkg_get_name(FileItem->pkg),
    // 					FileItem->file->name);
    // 		}
    // 		prev_FileItem = FileItem;
    // 	}
    //
    // 	free(all_files);
    return ret;
}

/// Check 'local' package database for consistency
///
/// * return - 0 on success, >=1 on failure
fn check_db_local(config: &mut Config, handle: &mut Handle) -> i32 {
    let mut ret: i32 = 0;
    let mut pkglist: Vec<&Package>;
    let handle_clone = &handle.clone();

    ret = check_db_local_files(&config, handle);
    if ret != 0 {
        return ret;
    }
    {
        let db: &Database;
        db = handle.get_localdb();
        pkglist = match db.get_pkgcache() {
            Err(e) => {
                debug!("{}", e);
                return 1;
            }
            Ok(pkglist) => pkglist,
        };
    }
    ret += check_db_missing_deps(&mut pkglist, handle);
    ret += check_db_local_package_conflicts(&pkglist, handle);
    ret += check_db_local_filelist_conflicts(&pkglist);

    ret
}

/// Check 'sync' package databases for consistency
///
/// * return - 0 on success, >=1 on failure
fn check_db_sync(config: &mut Config, handle: &mut Handle) -> i32 {
    let mut syncpkglist = Vec::new();
    let handle_clone = &handle.clone();

    for mut db in &mut handle.dbs_sync {
        let mut pkglist: Vec<&Package>;
        pkglist = match db.get_pkgcache() {
            Err(e) => {
                debug!("{}", e);
                return 1;
            }
            Ok(pkglist) => pkglist,
        };
        syncpkglist.append(&mut pkglist);
    }

    check_db_missing_deps(&mut syncpkglist, handle_clone)
}

pub fn pacman_database(
    targets: Vec<String>,
    config: &mut Config,
    handle: &mut Handle,
) -> std::result::Result<(), i32> {
    let mut ret: i32 = 0;

    if config.check != 0 {
        if config.check == 1 {
            ret = check_db_local(config, handle);
        } else {
            ret = check_db_sync(config, handle);
        }

        if ret == 0 && !config.quiet {
            print!("No database errors have been found!\n");
        }
    }

    if config.flags.all_deps && config.flags.all_explicit {
        ret = change_install_reason(targets, config, handle);
    }

    if ret != 0 {
        return Err(ret);
    }
    Ok(())
}
