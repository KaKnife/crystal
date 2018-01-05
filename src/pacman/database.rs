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

/**
 * @brief Modify the 'local' package database.
 *
 * @param targets a list of packages (as strings) to modify
 *
 * @return 0 on success, 1 on failure
 */
fn change_install_reason(targets: Vec<String>, config: &super::conf::config_t) -> i32 {
    // 	alpm_list_t *i;
    let db_local; // 	alpm_db_t *db_local;
    let mut ret = 0;
    let reason: alpm_pkgreason_t;

    if targets.len() == 0 {
        eprintln!("no targets specified (use -h for help)");
        return 1;
    }

    if config.flags.ALLDEPS {
        /* --asdeps */
        reason = alpm_pkgreason_t::ALPM_PKG_REASON_DEPEND;
    } else if config.flags.ALLEXPLICIT {
        /* --asexplicit */
        reason = alpm_pkgreason_t::ALPM_PKG_REASON_EXPLICIT;
    } else {
        eprintln!("no install reason specified (use -h for help)\n");
        return 1;
    }

    /* Lock database */
    if trans_init(&alpm_transflag_t::default(), 0, config) == -1 {
        return 1;
    }

    db_local = config.handle.alpm_get_localdb();
    for pkgname in targets {
        // 		char *pkgname = i->data;
        // alpm_pkg_t *pkg = alpm_db_get_pkg(db_local, pkgname);
        let pkg = db_local.alpm_db_get_pkg(&pkgname);
        if pkg.is_none() || pkg.unwrap().alpm_pkg_set_reason(&reason) != 0 {
            eprintln!(
                "could not set install reason for package {} ()",
                pkgname /*alpm_strerror(alpm_errno(config->handle))*/,
            );
            ret = 1;
        } else {
            if !config.quiet {
                match reason {
                    alpm_pkgreason_t::ALPM_PKG_REASON_DEPEND => {
                        println!(
                            "{}: install reason has been set to 'installed as dependency'",
                            pkgname
                        );
                    }
                    _ => {
                        println!(
                            "{}: install reason has been set to 'explicitly installed'",
                            pkgname
                        );
                    }
                }
            }
        }
    }

    /* Unlock database */
    if !trans_release(config) {
        return 1;
    }
    return ret;
}

fn check_db_missing_deps(config: &conf::config_t, pkglist: &mut Vec<alpm_pkg_t>) -> i32 {
    // alpm_list_t *data, *i;
    // let data;
    // let i;
    let mut ret = 0;
    // /* check dependencies */

    for miss in config.handle.alpm_checkdeps(None, None, pkglist, 0) {
        //     let miss = i.data;
        let depstring = miss.depend.alpm_dep_compute_string();
        eprintln!("missing '{}' dependency for '{}'", depstring, miss.target);
        ret += 1;
    }
    // // FREELIST(data);
    return ret;
}

fn check_db_local_files(config: &conf::config_t) -> i32 {
    // let ent; // struct dirent *ent;
    let dbpath; // const char *dbpath;
                // char path[PATH_MAX];
    let mut ret = 0;
    let dbdir; // DIR *dbdir;

    dbpath = config.handle.alpm_option_get_dbpath();
    let mut path = format!("{}local", dbpath);
    use std;
    dbdir = match std::fs::read_dir(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("could not open local database directory: {}", e);
            return 1;
        }
    };

    for entw in dbdir {
        let ent = entw.unwrap();
        let file_name = ent.file_name().into_string().unwrap();
        if file_name == "." || file_name == ".." || file_name == "ALPM_DB_VERSION" {
            continue;
        }
        /* check for expected db files in local database */
        path = format!("{}local/{}/desc", dbpath, file_name);
        match std::fs::File::open(path) {
            Ok(_) => {}
            Err(_e) => {
                eprintln!("'{}': description file is missing", file_name);
                ret += 1;
            }
        }
        path = format!("{}local/{}/files", dbpath, file_name);
        match std::fs::File::open(path) {
            Ok(_) => {}
            Err(_e) => {
                eprintln!("'{}': file list is missing", file_name);
                ret += 1;
            }
        }
    }

    return ret;
}

fn check_db_local_package_conflicts(pkglist: &Vec<alpm_pkg_t>, config: &conf::config_t) -> i32 {
    // alpm_list_t *data, *i;
    let mut ret = 0;
    // /* check conflicts */
    let data = config.handle.alpm_checkconflicts(&pkglist);
    for conflict in data {
        // alpm_conflict_t *conflict = i->data;
        eprintln!(
            "'{}' conflicts with '{}'",
            conflict.package1, conflict.package2
        );
        ret += 1;
    }
    // FREELIST(data);
    return ret;
}

struct fileitem {
    file: alpm_file_t,
    pkg: alpm_pkg_t,
}

// static int fileitem_cmp(const void *p1, const void *p2)
// {
// 	const struct fileitem * fi1 = p1;
// 	const struct fileitem * fi2 = p2;
// 	return strcmp(fi1->file->name, fi2->file->name);
// }
//
fn check_db_local_filelist_conflicts(pkglist: &Vec<alpm_pkg_t>) -> i32 {
    unimplemented!();
    // 	alpm_list_t *i;
    // let mut ret = 0;
    // // 	size_t list_size = 4096;
    // // 	size_t offset = 0, j;
    // // 	struct fileitem *all_files;
    // // 	struct fileitem *prev_fileitem = NULL;
    // //
    // // 	all_files = malloc(list_size * sizeof(struct fileitem));
    // let all_files = Vec::new();
    // //
    // for pkg in pkglist {
    //     unimplemented!();
    //     // 		alpm_pkg_t *pkg = i->data;
    //     // alpm_filelist_t *filelist = alpm_pkg_get_files(pkg);
    //     let filelist = alpm_pkg_get_files(pkg);
    //     for file in filelist {
    //         // alpm_file_t *file = filelist->files + j;
    //         /* only add files, not directories, to our big list */
    //         if file.name.ends_with('/') {
    //             continue;
    //         }
    //
    //         /* we can finally add it to the list */
    //         all_files.push(fileitem{file:file, pkg:pkg.clone()});
    //     }
    // }
    //
    // 	/* now sort the list so we can find duplicates */
    // 	qsort(all_files, offset, sizeof(struct fileitem), fileitem_cmp);
    //
    // 	/* do a 'uniq' style check on the list */
    // 	for(j = 0; j < offset; j++) {
    // 		struct fileitem *fileitem = all_files + j;
    // 		if(prev_fileitem && fileitem_cmp(prev_fileitem, fileitem) == 0) {
    // 			pm_printf(ALPM_LOG_ERROR, "file owned by '%s' and '%s': '%s'\n",
    // 					alpm_pkg_get_name(prev_fileitem->pkg),
    // 					alpm_pkg_get_name(fileitem->pkg),
    // 					fileitem->file->name);
    // 		}
    // 		prev_fileitem = fileitem;
    // 	}
    //
    // 	free(all_files);
    // return ret;
}

/**
 * @brief Check 'local' package database for consistency
 *
 * @return 0 on success, >=1 on failure
 */
fn check_db_local(config: &conf::config_t) -> i32 {
    let mut ret = 0;
    let mut db;
    let mut pkglist;
    // // alpm_db_t *db = NULL;
    // // alpm_list_t *pkglist;

    ret = check_db_local_files(&config);
    if ret != 0 {
        return ret;
    }

    db = config.handle.alpm_get_localdb();
    pkglist = db.alpm_db_get_pkgcache();
    ret += check_db_missing_deps(config, &mut pkglist);
    ret += check_db_local_package_conflicts(&pkglist, config);
    ret += check_db_local_filelist_conflicts(&pkglist);

    ret
}

/**
 * @brief Check 'sync' package databases for consistency
 *
 * @return 0 on success, >=1 on failure
 */
fn check_db_sync(config: &mut config_t) -> i32 {
    // // alpm_list_t *i, *dblist, *pkglist, *syncpkglist = NULL;
    // let dblist;
    // let i;
    let mut pkglist;
    let mut syncpkglist = Vec::new();
    //
    match config.handle.dbs_sync {
        Some(ref mut dblist) => for mut db in dblist {
            pkglist = db.alpm_db_get_pkgcache();
            syncpkglist.append(&mut pkglist);
        },
        _ => unimplemented!(),
    };

    check_db_missing_deps(config, &mut syncpkglist)
}

pub fn pacman_database(targets: Vec<String>, config: &mut config_t) -> Result<(), i32> {
    let mut ret = 0;

    if config.op_q_check != 0 {
        if config.op_q_check == 1 {
            ret = check_db_local(&config);
        } else {
            ret = check_db_sync(config);
        }

        if ret == 0 && !config.quiet {
            println!("No database errors have been found!");
        }
    }

    if config.flags.ALLDEPS && config.flags.ALLEXPLICIT {
        ret = change_install_reason(targets, config);
    }

    if ret != 0 {
        return Err(ret);
    }
    Ok(())
}
