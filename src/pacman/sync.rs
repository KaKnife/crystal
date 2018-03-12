use pacman::{check_syncdbs, sync_syncdbs, trans_init, trans_release, yesno, Config};
use package::dump_pkg_search;
use alpm::DatabaseUsage;
use std::fs::{read_dir, remove_dir_all};
use {Error, Handle, Package, TransactionFlag};
use Result;
use Database;
use DepMissing;

fn unlink_verbose(pathname: &String, ignore_missing: bool) -> i32 {
    unimplemented!();
    // 	int ret = unlink(pathname);
    // 	if(ret) {
    // 		if(ignore_missing && errno == ENOENT) {
    // 			ret = 0;
    // 		} else {
    // 			pm_printf(ALPM_LOG_ERROR, _("could not remove %s: %s\n"),
    // 					pathname, strerror(errno));
    // 		}
    // 	}
    // 	return ret;
}

fn sync_cleandb(dbpath: String, handle: &mut Handle) -> i32 {
    let syncdbs;
    let mut ret = 0;

    let dir = match read_dir(&dbpath) {
        Ok(d) => d,
        Err(_) => {
            error!("could not access database directory");
            return 1;
        }
    };

    syncdbs = handle.get_syncdbs();

    /* step through the directory one file at a time */
    for entr in dir {
        let ent = entr.unwrap();
        let path;
        let mut found = false;
        let dname = ent.file_name().into_string().unwrap();
        let mut dbname = String::new();
        let len;

        if dname == "." || dname == ".." {
            continue;
        }

        /* build the full path */
        path = format!("{}{}", &dbpath, dname);

        /* remove all non-skipped directories and non-database files */
        match remove_dir_all(&path) {
            Ok(_) => {}
            Err(e) => {
                error!("could not remove {}: {}", path, e);
                continue;
            }
        }

        len = dname.len();
        if len > 3 && dname.ends_with(".db") {
            dbname = dname.split_at(len - 3).0.to_string();
        } else if len > 7 && dname.ends_with(".db.sig") {
            dbname = dname.split_at(len - 7).0.to_string();
        } else if len > 6 && dname.ends_with(".files") {
            dbname = dname.split_at(len - 6).0.to_string();
        } else if len > 6 && dname.ends_with(".files.sig") {
            dbname = dname.split_at(len - 10).0.to_string();
        } else {
            ret += unlink_verbose(&path, false);
            continue;
        }

        for db in syncdbs {
            found = *db.get_name() == dbname;
        }

        /* We have a file that doesn't match any syncdb. */
        if !found {
            ret += unlink_verbose(&path, false);
        }
    }
    return ret;
}

fn sync_cleandb_all(config: &Config, handle: &mut Handle) -> i32 {
    let syncdbpath;
    let mut ret = 0;
    {
        let dbpath = handle.get_dbpath();
        info!("Database directory: {}", dbpath);
        if !yesno(
            String::from("Do you want to remove unused repositories?"),
            config,
        ) {
            return 0;
        }
        info!("removing unused sync repositories...");
        syncdbpath = format!("{}{}", dbpath, "sync/");
    }
    ret += sync_cleandb(syncdbpath, handle);

    return ret;
}

fn sync_cleancache(level: i32) -> i32 {
    unimplemented!();
    // 	alpm_list_t *i;
    // 	alpm_list_t *sync_dbs = alpm_get_syncdbs(config->handle);
    // 	Database *db_local = alpm_get_localdb(config->handle);
    // 	alpm_list_t *cachedirs = alpm_option_get_cachedirs(config->handle);
    // 	int ret = 0;
    //
    // 	if(!config->cleanmethod) {
    // 		/* default to KeepInstalled if user did not specify */
    // 		config->cleanmethod = PM_CLEAN_KEEPINST;
    // 	}
    //
    // 	if(level == 1) {
    // 		printf(_("Packages to keep:\n"));
    // 		if(config->cleanmethod & PM_CLEAN_KEEPINST) {
    // 			printf(_("  All locally installed packages\n"));
    // 		}
    // 		if(config->cleanmethod & PM_CLEAN_KEEPCUR) {
    // 			printf(_("  All current sync database packages\n"));
    // 		}
    // 	}
    // 	printf("\n");
    //
    // 	for(i = cachedirs; i; i = alpm_list_next(i)) {
    // 		const char *cachedir = i->data;
    // 		DIR *dir;
    // 		struct dirent *ent;
    //
    // 		printf(_("Cache directory: %s\n"), (const char *)i->data);
    //
    // 		if(level == 1) {
    // 			if(!yesno(_("Do you want to remove all other packages from cache?"))) {
    // 				printf("\n");
    // 				continue;
    // 			}
    // 			printf(_("removing old packages from cache...\n"));
    // 		} else {
    // 			if(!noyes(_("Do you want to remove ALL files from cache?"))) {
    // 				printf("\n");
    // 				continue;
    // 			}
    // 			printf(_("removing all files from cache...\n"));
    // 		}
    //
    // 		dir = opendir(cachedir);
    // 		if(dir == NULL) {
    // 			pm_printf(ALPM_LOG_ERROR,
    // 					_("could not access cache directory %s\n"), cachedir);
    // 			ret++;
    // 			continue;
    // 		}
    //
    // 		rewinddir(dir);
    // 		/* step through the directory one file at a time */
    // 		while((ent = readdir(dir)) != NULL) {
    // 			char path[PATH_MAX];
    // 			int delete = 1;
    // 			Package *localpkg = NULL, *pkg = NULL;
    // 			const char *local_name, *local_version;
    //
    // 			if(strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
    // 				continue;
    // 			}
    //
    // 			if(level <= 1) {
    // 				static const char *const glob_skips[] = {
    // 					/* skip signature files - they are removed with their package file */
    // 					"*.sig",
    // 					/* skip package databases within the cache directory */
    // 					"*.db*", "*.files*",
    // 					/* skip source packages within the cache directory */
    // 					"*.src.tar.*",
    // 					/* skip package deltas, we aren't smart enough to clean these yet */
    // 					"*.delta"
    // 				};
    // 				size_t j;
    //
    // 				for(j = 0; j < ARRAYSIZE(glob_skips); j++) {
    // 					if(fnmatch(glob_skips[j], ent->d_name, 0) == 0) {
    // 						delete = 0;
    // 						break;
    // 					}
    // 				}
    // 				if(delete == 0) {
    // 					continue;
    // 				}
    // 			}
    //
    // 			/* build the full filepath */
    // 			snprintf(path, PATH_MAX, "%s%s", cachedir, ent->d_name);
    //
    // 			/* short circuit for removing all files from cache */
    // 			if(level > 1) {
    // 				ret += unlink_verbose(path, 0);
    // 				continue;
    // 			}
    //
    // 			/* attempt to load the file as a package. if we cannot load the file,
    // 			 * simply skip it and move on. we don't need a full load of the package,
    // 			 * just the metadata. */
    // 			if(alpm_pkg_load(config->handle, path, 0, 0, &localpkg) != 0) {
    // 				pm_printf(ALPM_LOG_DEBUG, "skipping %s, could not load as package\n",
    // 						path);
    // 				continue;
    // 			}
    // 			local_name = alpm_pkg_get_name(localpkg);
    // 			local_version = alpm_pkg_get_version(localpkg);
    //
    // 			if(config->cleanmethod & PM_CLEAN_KEEPINST) {
    // 				/* check if this package is in the local DB */
    // 				pkg = alpm_db_get_pkg(db_local, local_name);
    // 				if(pkg != NULL && alpm_pkg_vercmp(local_version,
    // 							alpm_pkg_get_version(pkg)) == 0) {
    // 					/* package was found in local DB and version matches, keep it */
    // 					pm_printf(ALPM_LOG_DEBUG, "package %s-%s found in local db\n",
    // 							local_name, local_version);
    // 					delete = 0;
    // 				}
    // 			}
    // 			if(config->cleanmethod & PM_CLEAN_KEEPCUR) {
    // 				alpm_list_t *j;
    // 				/* check if this package is in a sync DB */
    // 				for(j = sync_dbs; j && delete; j = alpm_list_next(j)) {
    // 					Database *db = j->data;
    // 					pkg = alpm_db_get_pkg(db, local_name);
    // 					if(pkg != NULL && alpm_pkg_vercmp(local_version,
    // 								alpm_pkg_get_version(pkg)) == 0) {
    // 						/* package was found in a sync DB and version matches, keep it */
    // 						pm_printf(ALPM_LOG_DEBUG, "package %s-%s found in sync db\n",
    // 								local_name, local_version);
    // 						delete = 0;
    // 					}
    // 				}
    // 			}
    // 			/* free the local file package */
    // 			alpm_pkg_free(localpkg);
    //
    // 			if(delete) {
    // 				size_t pathlen = strlen(path);
    // 				ret += unlink_verbose(path, 0);
    // 				/* unlink a signature file if present too */
    // 				if(PATH_MAX - 5 >= pathlen) {
    // 					strcpy(path + pathlen, ".sig");
    // 					ret += unlink_verbose(path, 1);
    // 				}
    // 			}
    // 		}
    // 		closedir(dir);
    // 		printf("\n");
    // 	}
    //
    // 	return ret;
}

/// search the sync dbs for a matching package
fn sync_search(
    syncs: &mut Vec<Database>,
    targets: &Vec<String>,
    config: &Config,
    handle: &mut Handle,
) -> bool {
    let mut found = 0;

    for db in syncs {
        found == found || dump_pkg_search(db, targets, 1, handle, config.quiet).is_err();
    }

    return found == 0;
}

fn sync_group(level: i32, syncs: &Vec<Database>, targets: Vec<String>, quiet: bool) -> i32 {
    let mut ret = 0;

    if !targets.is_empty() {
        let mut found;
        for grpname in targets {
            found = false;
            for db in syncs {
                if let Ok(grp) = db.get_group(&grpname) {
                    found = true;
                    /* get names of packages in group */
                    for pkg in &grp.packages {
                        if !quiet {
                            info!("{} {}", grpname, pkg.get_name());
                        } else {
                            info!("{}", pkg.get_name());
                        }
                    }
                }
            }
            if !found {
                ret = 1;
            }
        }
    } else {
        ret = 1;
        for db in syncs {
            for grp in db.get_groupcache() {
                ret = 0;

                if level > 1 {
                    for pkg in &grp.packages {
                        info!("{} {}", grp.name, pkg.get_name());
                    }
                } else {
                    /* print grp names only, no package names */
                    // if(!alpm_list_find_str (s, grp->name)) {
                    // 	s = alpm_list_add (s, grp->name);
                    // 	printf("%s\n", grp->name);
                    // }
                    unimplemented!();
                }
            }
        }
    }

    return ret;
}

fn sync_info(mut syncs: &Vec<Database>, targets: &Vec<String>) -> Result<()> {
    let mut ret = Ok(());
    if !targets.is_empty() {
        for target in targets {
            let repo;
            let pkgstr;
            let mut founddb = false;
            let mut foundpkg = false;

            let tmp: Vec<&str> = target.splitn(2, "/").collect();
            if tmp.len() == 2 {
                repo = tmp[0];
                pkgstr = tmp[1];
            } else {
                repo = "";
                pkgstr = tmp[0];
            }

            for db in syncs {
                if repo != "" && repo != db.get_name() {
                    continue;
                }
                founddb = true;

                for pkg in db.get_pkgcache()? {
                    if pkg.get_name() == pkgstr {
                        unimplemented!();
                        // pkg.dump_full(config.op_s_info > 1);
                        foundpkg = true;
                        break;
                    }
                }
            }

            if !founddb {
                error!("repository '{}' does not exist", repo);
                ret = Err(Error::RepoNotFound);
            }
            if !foundpkg {
                error!("package '{}' was not found", target);
                ret = Err(Error::PkgNotFound);
            }
        }
    } else {
        for db in syncs.iter() {
            for pkg in db.get_pkgcache() {
                unimplemented!();
                // dump_pkg_full(pkg, config.op_s_info > 1);
            }
        }
    }

    ret
}

fn sync_list(syncs: &mut Vec<Database>, targets: &Vec<String>) -> Result<()> {
    unimplemented!();
    // 	alpm_list_t *i, *j, *ls = NULL;
    // 	Database *db_local = alpm_get_localdb(config->handle);
    // 	int ret = 0;
    //
    // 	if(targets) {
    // 		for(i = targets; i; i = alpm_list_next(i)) {
    // 			const char *repo = i->data;
    // 			Database *db = NULL;
    //
    // 			for(j = syncs; j; j = alpm_list_next(j)) {
    // 				Database *d = j->data;
    //
    // 				if(strcmp(repo, alpm_db_get_name(d)) == 0) {
    // 					db = d;
    // 					break;
    // 				}
    // 			}
    //
    // 			if(db == NULL) {
    // 				pm_printf(ALPM_LOG_ERROR,
    // 					_("repository \"%s\" was not found.\n"), repo);
    // 				ret = 1;
    // 			}
    //
    // 			ls = alpm_list_add(ls, db);
    // 		}
    // 	} else {
    // 		ls = syncs;
    // 	}
    //
    // 	for(i = ls; i; i = alpm_list_next(i)) {
    // 		Database *db = i->data;
    //
    // 		for(j = alpm_db_get_pkgcache(db); j; j = alpm_list_next(j)) {
    // 			Package *pkg = j->data;
    //
    // 			if(!config->quiet) {
    // 				const colstr_t *colstr = &config->colstr;
    // 				printf("%s%s %s%s %s%s%s", colstr->repo, alpm_db_get_name(db),
    // 						colstr->title, alpm_pkg_get_name(pkg),
    // 						colstr->version, alpm_pkg_get_version(pkg), colstr->nocolor);
    // 				print_installed(db_local, pkg);
    // 				printf("\n");
    // 			} else {
    // 				printf("%s\n", alpm_pkg_get_name(pkg));
    // 			}
    // 		}
    // 	}
    //
    // 	if(targets) {
    // 		alpm_list_free(ls);
    // 	}
    //
    // 	return ret;
}

fn get_db(dbname: &String) -> Database {
    unimplemented!();
    // 	alpm_list_t *i;
    // 	for(i = alpm_get_syncdbs(config->handle); i; i = i->next) {
    // 		Database *db = i->data;
    // 		if(strcmp(alpm_db_get_name(db), dbname) == 0) {
    // 			return db;
    // 		}
    // 	}
    // 	return NULL;
}

fn process_pkg(pkg: &Package) -> i32 {
    unimplemented!();
    // 	int ret = alpm_add_pkg(config->handle, pkg);
    //
    // 	if(ret == -1) {
    // 		errno_t err = alpm_errno(config->handle);
    // 		if(err == ALPM_ERR_TRANS_DUP_TARGET) {
    // 			/* just skip duplicate targets */
    // 			pm_printf(ALPM_LOG_WARNING, _("skipping target: %s\n"), alpm_pkg_get_name(pkg));
    // 			return 0;
    // 		} else {
    // 			pm_printf(ALPM_LOG_ERROR, "'%s': %s\n", alpm_pkg_get_name(pkg),
    // 					alpm_strerror(err));
    // 			return 1;
    // 		}
    // 	}
    // 	config->explicit_adds = alpm_list_add(config->explicit_adds, pkg);
    // 	return 0;
}

fn process_group<T>(dbs: Vec<T>, group: &String, error: i32) -> i32 {
    unimplemented!();
    // 	int ret = 0;
    // 	alpm_list_t *i;
    // 	alpm_list_t *pkgs = alpm_find_group_pkgs(dbs, group);
    // 	int count = alpm_list_count(pkgs);
    //
    // 	if(!count) {
    // 		pm_printf(ALPM_LOG_ERROR, _("target not found: %s\n"), group);
    // 		return 1;
    // 	}
    //
    // 	if(error) {
    // 		/* we already know another target errored. there is no reason to prompt the
    // 		 * user here; we already validated the group name so just move on since we
    // 		 * won't actually be installing anything anyway. */
    // 		goto cleanup;
    // 	}
    //
    // 	if(config->print == 0) {
    // 		char *array = malloc(count);
    // 		int n = 0;
    // 		const colstr_t *colstr = &config->colstr;
    // 		colon_printf(_n("There is %d member in group %s%s%s:\n",
    // 				"There are %d members in group %s%s%s:\n", count),
    // 				count, colstr->groups, group, colstr->title);
    // 		select_display(pkgs);
    // 		if(!array) {
    // 			ret = 1;
    // 			goto cleanup;
    // 		}
    // 		if(multiselect_question(array, count)) {
    // 			ret = 1;
    // 			free(array);
    // 			goto cleanup;
    // 		}
    // 		for(i = pkgs, n = 0; i; i = alpm_list_next(i)) {
    // 			Package *pkg = i->data;
    //
    // 			if(array[n++] == 0) {
    // 				continue;
    // 			}
    //
    // 			if(process_pkg(pkg) == 1) {
    // 				ret = 1;
    // 				free(array);
    // 				goto cleanup;
    // 			}
    // 		}
    // 		free(array);
    // 	} else {
    // 		for(i = pkgs; i; i = alpm_list_next(i)) {
    // 			Package *pkg = i->data;
    //
    // 			if(process_pkg(pkg) == 1) {
    // 				ret = 1;
    // 				goto cleanup;
    // 			}
    // 		}
    // 	}
    //
    // cleanup:
    // 	alpm_list_free(pkgs);
    // 	return ret;
}

fn process_targname<T>(dblist: Vec<T>, targname: &String, error: i32, handle: &mut Handle) -> i32 {
    let pkg: Option<Package> = handle.find_dbs_satisfier(&dblist, targname);

    /* skip ignored packages when user says no */
    // match config.handle.alpm_errno() {
    //     errno_t::ALPM_ERR_PKG_IGNORED => {
    //         // pm_printf(ALPM_LOG_WARNING, _("skipping target: %s\n"), targname);
    //         return 0;
    //     }
    //     _ => {}
    // }

    match pkg {
        Some(pkg) => return process_pkg(&pkg),
        _ => {}
    }

    /* fallback on group */
    return process_group(dblist, targname, error);
}

fn process_target(target: &String, error: i32) -> i32 {
    unimplemented!();
    /* process targets */
    let targstring = target.clone();
    // 	char *targname = strchr(targstring, '/');
    let ret = 0;
    // 	alpm_list_t *dblist;
    //
    // 	if(targname && targname != targstring)
    {
        let mut db: Database;
        let dbname: &String;
        let mut usage: DatabaseUsage = DatabaseUsage::default();

        // *targname = '\0';
        // targname++;
        // dbname = targstring;
        // db = get_db(dbname);
        // if(!db) {
        // 	pm_printf(ALPM_LOG_ERROR, _("database not found: %s\n"),
        // 			dbname);
        // 	ret = 1;
        // 	goto cleanup;
        // }

        /* explicitly mark this repo as valid for installs since
         * a repo name was given with the target */
        // db.alpm_db_get_usage(&mut usage);
        // db.alpm_db_set_usage(usage|ALPM_DB_USAGE_INSTALL);
        //
        // dblist = alpm_list_add(NULL, db);
        // ret = process_targname(dblist, targname, error);
        // alpm_list_free(dblist);
        //
        /* restore old usage so we don't possibly disturb later
         * targets */
        // db.alpm_db_set_usage(usage);
    }
    // else
    {
        // 		targname = targstring;
        // 		dblist = alpm_get_syncdbs(config->handle);
        // 		ret = process_targname(dblist, targname, error);
    }

    /*cleanup:*/
    // 	if(ret && access(target, R_OK) == 0) {
    // 		pm_printf(ALPM_LOG_WARNING,
    // 				_("'%s' is a file, did you mean %s instead of %s?\n"),
    // 				target, "-U/--upgrade", "-S/--sync");
    // 	}
    return ret;
}

fn sync_trans(targets: &Vec<String>, config: &mut Config, handle: &mut Handle) -> Result<()> {
    let retval = 0;

    /* Step 1: create a new transaction... */
    trans_init(&config.flags.clone(), true, handle)?;

    /* process targets */
    for targ in targets {
        if process_target(targ, retval) == 1 {
            trans_release(handle);
            return Err(Error::Other);
        }
    }

    if config.s_upgrade != 0 {
        if !config.print {
            info!("Starting full system upgrade...");
        }
        if let Err(e) = handle.sync_sysupgrade(config.s_upgrade >= 2) {
            error!("{}", e);
            if let Err(e) = handle.trans_release() {
                error!("failed to release transaction: {}", e);
            }
            return Err(e);
        }
    }
    sync_prepare_execute(config, handle)
}

fn print_broken_dep(miss: &DepMissing) {
    unimplemented!();
    // 	char *depstring = alpm_dep_compute_string(miss->depend);
    // 	alpm_list_t *trans_add = alpm_trans_get_add(config->handle);
    // 	Package *pkg;
    // if (miss.causingpkg == NULL) {
    //     /* package being installed/upgraded has unresolved dependency */
    //     info!(
    //         "unable to satisfy dependency '{}' required by {}",
    //         depstring, miss.target,
    //     );
    // } else if ((pkg = alpm_pkg_find(trans_add, miss.causingpkg))) {
    //     /* upgrading a package breaks a local dependency */
    //     // 		colon_printf(_("installing %s (%s) breaks dependency '%s' required by %s\n"),
    //     // 				miss->causingpkg, alpm_pkg_get_version(pkg), depstring, miss->target);
    // } else {
    //     /* removing a package breaks a local dependency */
    //     info!(
    //         "removing {} breaks dependency '{}' required by {}",
    //         miss.causingpkg, depstring, miss.target
    //     );
    // }
}

pub fn sync_prepare_execute(config: &Config, handle: &mut Handle) -> Result<()> {
    let mut packages;
    let retval = Ok(());
    let mut data = Vec::new();

    /* Step 2: "compute" the transaction based on targets and flags */
    if let Err(err) = handle.trans_prepare(&mut data) {
        // == -1 {
        error!("failed to prepare transaction ({})", err);
        match err {
            Error::PkgInvalidArch => {
                for pkg in data {
                    unimplemented!();
                    // colon_printf(_("package %s does not have a valid architecture\n"), pkg);
                }
            }
            Error::UnsatisfiedDeps => {
                for pkg in data {
                    unimplemented!();
                    // print_broken_dep(pkg);
                }
            }
            Error::ConflictingDeps => {
                for conflict in data {
                    unimplemented!();
                    // 	alpm_conflict_t *conflict = i->data;
                    // 	/* only print reason if it contains new information */
                    // 	if(conflict->reason->mod == ALPM_DEP_MOD_ANY) {
                    // 		colon_printf(_("%s and %s are in conflict\n"),
                    // 				conflict->package1, conflict->package2);
                    // 	} else {
                    // 		char *reason = alpm_dep_compute_string(conflict->reason);
                    // 		colon_printf(_("%s and %s are in conflict (%s)\n"),
                    // 				conflict->package1, conflict->package2, reason);
                    // 		free(reason);
                    // 	}
                    // 	alpm_conflict_free(conflict);
                }
            }
            _ => {}
        }
        unimplemented!();
        // 		retval = 1;
        // 		goto cleanup;
    }

    if handle.trans.add.is_empty() {
        /* nothing to do: just exit without complaining */
        if !config.print {
            info!("there is nothing to do");
        }
        if !trans_release(handle) {
            return Err(Error::Other);
        }

        return retval;
    }
    packages = &handle.trans.add;

    // 	/* Step 3: actually perform the operation */
    // 	if(config->print) {
    // 		print_packages(packages);
    // 		goto cleanup;
    // 	}

    // 	display_targets();
    // 	printf("\n");

    // 	int confirm;
    // 	if(config->op_s_downloadonly) {
    // 		confirm = yesno(_("Proceed with download?"));
    // 	} else {
    // 		confirm = yesno(_("Proceed with installation?"));
    // 	}
    // 	if(!confirm) {
    // 		retval = 1;
    // 		goto cleanup;
    // 	}

    // 	if(alpm_trans_commit(config->handle, &data) == -1) {
    // 		errno_t err = alpm_errno(config->handle);
    // 		pm_printf(ALPM_LOG_ERROR, _("failed to commit transaction (%s)\n"),
    // 		        alpm_strerror(err));
    // 		switch(err) {
    // 			case ALPM_ERR_FILE_CONFLICTS:
    // 				if(config->flags & ALPM_TRANS_FLAG_FORCE) {
    // 					printf(_("unable to %s directory-file conflicts\n"), "--force");
    // 				}
    // 				for(i = data; i; i = alpm_list_next(i)) {
    // 					alpm_fileconflict_t *conflict = i->data;
    // 					switch(conflict->type) {
    // 						case ALPM_FILECONFLICT_TARGET:
    // 							printf(_("%s exists in both '%s' and '%s'\n"),
    // 									conflict->file, conflict->target, conflict->ctarget);
    // 							break;
    // 						case ALPM_FILECONFLICT_FILESYSTEM:
    // 							if(conflict->ctarget[0]) {
    // 								printf(_("%s: %s exists in filesystem (owned by %s)\n"),
    // 										conflict->target, conflict->file, conflict->ctarget);
    // 							} else {
    // 								printf(_("%s: %s exists in filesystem\n"),
    // 										conflict->target, conflict->file);
    // 							}
    // 							break;
    // 					}
    // 					alpm_fileconflict_free(conflict);
    // 				}
    // 				break;
    // 			case ALPM_ERR_PKG_INVALID:
    // 			case ALPM_ERR_PKG_INVALID_CHECKSUM:
    // 			case ALPM_ERR_PKG_INVALID_SIG:
    // 			case ALPM_ERR_DLT_INVALID:
    // 				for(i = data; i; i = alpm_list_next(i)) {
    // 					char *filename = i->data;
    // 					printf(_("%s is invalid or corrupted\n"), filename);
    // 					free(filename);
    // 				}
    // 				break;
    // 			default:
    // 				break;
    // 		}
    // 		/* TODO: stderr? */
    // 		printf(_("Errors occurred, no packages were upgraded.\n"));
    // 		retval = 1;
    // 		goto cleanup;
    // 	}
    unimplemented!();

    /* Step 4: release transaction resources */
    /* cleanup: */
    if !trans_release(handle) {
        return Err(Error::Other);
    }

    return retval;
}

pub fn pacman_sync(targets: Vec<String>, mut config: Config, mut handle: Handle) -> Result<()> {
    let mut sync_dbs: Vec<Database>;

    /* clean the cache */
    if config.clean != 0 {
        let mut ret = 0;

        trans_init(&TransactionFlag::default(), false, &mut handle)?;

        ret += sync_cleancache(config.clean as i32);
        ret += sync_cleandb_all(&config, &mut handle);

        if !trans_release(&mut handle) {
            return Err(Error::Other);
        }

        return Ok(());
    }

    check_syncdbs(1, true, &mut handle)?;

    sync_dbs = handle.get_syncdbs().clone();

    if config.sync != 0 {
        /* grab a fresh package list */
        info!("Synchronizing package databases...");
        sync_syncdbs(config.sync as i32, &mut sync_dbs, &mut handle)?;
    }

    check_syncdbs(1, true, &mut handle)?;

    /* search for a package */
    if config.search {
        return if sync_search(&mut sync_dbs, &targets, &config, &mut handle) {
            Err(Error::Other)
        } else {
            Ok(())
        };
    }

    /* look for groups */
    if config.group != 0 {
        return if sync_group(config.group as i32, &sync_dbs, targets, config.quiet) == 0 {
            Err(Error::Other)
        } else {
            Ok(())
        };
    }

    /* get package info */
    if config.info != 0 {
        return sync_info(&mut sync_dbs, &targets);
    }

    /* get a listing of files in sync DBs */
    if config.list {
        return sync_list(&mut sync_dbs, &targets);
    }

    if targets.is_empty() {
        if config.s_upgrade != 0 {
            /* proceed */
        } else if config.sync != 0 {
            return Ok(());
        } else {
            /* don't proceed here unless we have an operation that doesn't require a
             * target list */
            error!("no targets specified (use -h for help)");
            return Err(Error::WrongArgs);
        }
    }

    sync_trans(&targets, &mut config, &mut handle)
}
