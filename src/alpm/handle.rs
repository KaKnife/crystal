// #[macro_use]
// mod util;
use super::*;
use std;
// use std::error::Error;
use std::fs::File;
// use std::io::Result;
// use std::ffi::OsString;
// use self::Error::*;
use std::fs;
use super::deps::find_dep_satisfier;
/*
 *  handle.c
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
 *  Copyright (c) 2005, 2006 by Miklos Vajna <vmiklos@frugalware.org>
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

// alpm_cb_log SYMEXPORT alpm_option_get_logcb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->logcb;
// }
//
// alpm_cb_download SYMEXPORT alpm_option_get_dlcb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->dlcb;
// }
//
// alpm_cb_fetch SYMEXPORT alpm_option_get_fetchcb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->fetchcb;
// }
// alpm_cb_totaldl SYMEXPORT alpm_option_get_totaldlcb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->totaldlcb;
// }
//
// alpm_cb_event SYMEXPORT alpm_option_get_eventcb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->eventcb;
// }
//
// alpm_cb_question SYMEXPORT alpm_option_get_questioncb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->questioncb;
// }
//
// alpm_cb_progress SYMEXPORT alpm_option_get_progresscb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->progresscb;
// }

// #[derive(Default, Debug)]
///TODO: Implement this
// pub type alpm_list_t<T> = Vec<T>;
pub struct Archive {}
pub struct ArchiveEntry {}

impl Handle {
    /// Run ldconfig in a chroot. Returns 0 on success, 1 on error
    pub fn _alpm_ldconfig(&self) -> i32 {
        use std::fs::metadata;
        let mut line: String;

        debug!("running ldconfig");

        line = format!("{}etc/ld.so.conf", self.root);
        if metadata(line).is_ok() {
            unimplemented!();
            // // unimplemented due to lack of global var LDCONFIG
            // line = format!("{}{}", self.root, LDCONFIG);
            // if metadata(line).is_ok() {
            //     let arg0: &str = "ldconfig";
            //     let argv: [&str; 1] = [arg0];
            //     return _alpm_run_chroot(self, LDCONFIG, argv, NULL, NULL);
            // }
        }

        return 0;
    }

    /// Initialize the transaction.
    pub fn alpm_trans_init(&mut self, flags: &TransactionFlag) -> Result<()> {
        let mut trans: Transaction = Transaction::default();

        /* lock db */
        if !flags.no_lock {
            if self._alpm_handle_lock().is_err() {
                return Err(Error::ALPM_ERR_HANDLE_LOCK);
            }
        }

        trans.flags = flags.clone();
        trans.state = AlpmTransstate::Initialized;

        self.trans = trans;

        Ok(())
    }

    pub fn check_arch(&mut self, pkgs: &mut Vec<Package>) -> Vec<String> {
        let mut invalid = Vec::new();
        let arch: &str = &self.arch;
        for pkg in pkgs {
            let pkgarch = pkg.alpm_pkg_get_arch(&mut self.db_local).clone();
            if pkgarch != "" && pkgarch == arch && pkgarch == "any" {
                let string;
                let pkgname = &pkg.name;
                let pkgver = &pkg.version;
                string = format!("{}-{}-{}", pkgname, pkgver, pkgarch);
                invalid.push(string);
            }
        }
        return invalid;
    }

    /** Prepare a transaction. */
    pub fn alpm_trans_prepare(&mut self, data: &mut Vec<String>) -> Result<i32> {
        unimplemented!();
        // 	alpm_trans_t *trans;
        //
        // 	/* Sanity checks */
        // 	CHECK_HANDLE(handle, return -1);
        // 	ASSERT(data != NULL, RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1));
        //
        let mut trans = self.trans.clone();
        //
        // 	ASSERT(trans != NULL, RET_ERR(handle, ALPM_ERR_TRANS_NULL, -1));
        // 	ASSERT(trans->state == STATE_INITIALIZED, RET_ERR(handle, ALPM_ERR_TRANS_NOT_INITIALIZED, -1));

        /* If there's nothing to do, return without complaining */
        if trans.add.is_empty() && trans.remove.is_empty() {
            return Ok(0);
        }

        // 	alpm_list_t *invalid = check_arch(handle, trans->add);
        let invalid = &self.check_arch(&mut trans.add);
        if !invalid.is_empty() {
            // if data {
            *data = invalid.clone();
            // }
            return Err(Error::ALPM_ERR_PKG_INVALID_ARCH);
        }

        if trans.add.is_empty() {
            if self._alpm_remove_prepare(data) == -1 {
                /* pm_errno is set by _alpm_remove_prepare() */
                // return -1;
                unimplemented!();
            }
        } else {
            if self._alpm_sync_prepare(data) == -1 {
                /* pm_errno is set by _alpm_sync_prepare() */
                // return -1;
                unimplemented!();
            }
        }

        if !trans.flags.no_deps {
            debug!("sorting by dependencies");
            if !trans.add.is_empty() {
                unimplemented!();
                // let add_orig = trans.add;
                // trans.add = _alpm_sortbydeps(handle, add_orig, trans->remove, 0);
                // alpm_list_free(add_orig);
            }
            if !trans.remove.is_empty() {
                unimplemented!();
                // let rem_orig = trans.remove;
                // trans->remove = _alpm_sortbydeps(handle, rem_orig, NULL, 1);
                // alpm_list_free(rem_orig);
            }
        }

        trans.state = AlpmTransstate::PREPARED;

        return Ok(0);
    }

    /** Commit a transaction. */
    pub fn alpm_trans_commit<T>(&self, data: &Vec<T>) -> i32 {
        unimplemented!();
        // 	alpm_trans_t *trans;
        // 	alpm_event_any_t event;
        //
        // 	/* Sanity checks */
        // 	CHECK_HANDLE(handle, return -1);
        //
        // 	trans = handle->trans;
        //
        // 	ASSERT(trans != NULL, RET_ERR(handle, ALPM_ERR_TRANS_NULL, -1));
        // 	ASSERT(trans->state == STATE_PREPARED, RET_ERR(handle, ALPM_ERR_TRANS_NOT_PREPARED, -1));
        //
        //ASSERT(!(trans->flags & ALPM_TRANS_FLAG_NOLOCK), RET_ERR(handle, ALPM_ERR_TRANS_NOT_LOCKED, -1));
        //
        // 	/* If there's nothing to do, return without complaining */
        // 	if(trans->add == NULL && trans->remove == NULL) {
        // 		return 0;
        // 	}
        //
        // 	if(trans->add) {
        // 		if(_alpm_sync_load(handle, data) != 0) {
        // 			/* pm_errno is set by _alpm_sync_load() */
        // 			return -1;
        // 		}
        // 		if(trans->flags & ALPM_TRANS_FLAG_DOWNLOADONLY) {
        // 			return 0;
        // 		}
        // 		if(_alpm_sync_check(handle, data) != 0) {
        // 			/* pm_errno is set by _alpm_sync_check() */
        // 			return -1;
        // 		}
        // 	}
        //
        // 	if(_alpm_hook_run(handle, ALPM_HOOK_PRE_TRANSACTION) != 0) {
        // 		RET_ERR(handle, ALPM_ERR_TRANS_HOOK_FAILED, -1);
        // 	}
        //
        // 	trans->state = STATE_COMMITING;
        //
        // 	alpm_logaction(handle, ALPM_CALLER_PREFIX, "transaction started\n");
        // 	event.type = ALPM_EVENT_TRANSACTION_START;
        // 	EVENT(handle, (void *)&event);
        //
        // 	if(trans->add == NULL) {
        // 		if(_alpm_remove_packages(handle, 1) == -1) {
        // 			/* pm_errno is set by _alpm_remove_packages() */
        // 			Error save = handle->pm_errno;
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "transaction failed\n");
        // 			handle->pm_errno = save;
        // 			return -1;
        // 		}
        // 	} else {
        // 		if(_alpm_sync_commit(handle) == -1) {
        // 			/* pm_errno is set by _alpm_sync_commit() */
        // 			Error save = handle->pm_errno;
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "transaction failed\n");
        // 			handle->pm_errno = save;
        // 			return -1;
        // 		}
        // 	}
        //
        // 	if(trans->state == STATE_INTERRUPTED) {
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX, "transaction interrupted\n");
        // 	} else {
        // 		event.type = ALPM_EVENT_TRANSACTION_DONE;
        // 		EVENT(handle, (void *)&event);
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX, "transaction completed\n");
        // 		_alpm_hook_run(handle, ALPM_HOOK_POST_TRANSACTION);
        // 	}
        //
        // 	trans->state = STATE_COMMITED;
        //
        // 	return 0;
    }

    /// Interrupt a transaction.
    /// note: Safe to call from inside signal handlers.
    pub fn alpm_trans_interrupt(&self) {
        // 	alpm_trans_t *trans;
        //
        // 	/* Sanity checks */
        // 	CHECK_HANDLE(handle, return -1);
        //
        // 	trans = handle->trans;
        // 	ASSERT(trans != NULL, RET_ERR_ASYNC_SAFE(handle, ALPM_ERR_TRANS_NULL, -1));
        // 	ASSERT(trans->state == STATE_COMMITING || trans->state == STATE_INTERRUPTED,
        // 			RET_ERR_ASYNC_SAFE(handle, ALPM_ERR_TRANS_TYPE, -1));
        //
        // 	trans->state = STATE_INTERRUPTED;
        //
        // 	return 0;
    }

    ///Remove packages in the current transaction.
    ///@param handle the context handle
    ///@param run_ldconfig whether to run ld_config after removing the packages
    ///@return 0 on success, -1 if errors occurred while removing files
    pub fn _alpm_remove_packages(&self, run_ldconfig: i32) -> i32 {
        unimplemented!();
        // 	alpm_list_t *targ;
        // 	size_t pkg_count, targ_count;
        // 	alpm_trans_t *trans = handle->trans;
        // 	int ret = 0;
        //
        // 	pkg_count = alpm_list_count(trans->remove);
        // 	targ_count = 1;
        //
        // 	for(targ = trans->remove; targ; targ = targ->next) {
        // 		Package *pkg = targ->data;
        //
        // 		if(trans->state == STATE_INTERRUPTED) {
        // 			return ret;
        // 		}
        //
        // 		if(_alpm_remove_single_package(handle, pkg, NULL,
        // 					targ_count, pkg_count) == -1) {
        // 			handle->pm_errno = ALPM_ERR_TRANS_ABORT;
        // 			/* running ldconfig at this point could possibly screw system */
        // 			run_ldconfig = 0;
        // 			ret = -1;
        // 		}
        //
        // 		targ_count++;
        // 	}
        //
        // 	if(run_ldconfig) {
        // 		/* run ldconfig if it exists */
        // 		_alpm_ldconfig(handle);
        // 	}
        //
        // 	return ret;
    }

    /** Release a transaction. */
    pub fn alpm_trans_release(&self) -> Result<i32> {
        unimplemented!();
        // 	alpm_trans_t *trans;
        //
        // 	/* Sanity checks */
        // 	CHECK_HANDLE(handle, return -1);
        //
        // 	trans = handle->trans;
        // 	ASSERT(trans != NULL, RET_ERR(handle, ALPM_ERR_TRANS_NULL, -1));
        // 	ASSERT(trans->state != STATE_IDLE, RET_ERR(handle, ALPM_ERR_TRANS_NULL, -1));
        //
        // 	int nolock_flag = trans->flags & ALPM_TRANS_FLAG_NOLOCK;
        //
        // 	_alpm_trans_free(trans);
        // 	handle->trans = NULL;
        //
        // 	/* unlock db */
        // 	if(!nolock_flag) {
        // 		_alpm_handle_unlock(handle);
        // 	}
        //
        // 	return 0;
    }

    ///Form a signature path given a file path.
    ///Caller must free the result.
    ///`path` - the full path to a file.
    pub fn _alpm_sigpath(&self, path: &Option<String>) -> Option<String> {
        match path {
            &None => None,
            &Some(ref path) => Some(format!("{}.sig", path)),
        }
    }

    fn no_dep_version(&self) -> bool {
        self.trans.flags.no_depversion
    }

    ///Checks dependencies and returns missing ones in a list.
    ///Dependencies can include versions with depmod operators.
    /// * `pkglist` the list of local packages
    /// * `remove` an alpm_list_t* of packages to be removed
    /// * `upgrade` an alpm_list_t* of packages to be upgraded (remove-then-upgrade)
    /// * `reversedeps` handles the backward dependencies
    /// * returns an alpm_list_t* of depmissing_t pointers.
    pub fn alpm_checkdeps(
        &self,
        pkglist: Option<Vec<Package>>,
        remw: Option<Vec<Package>>,
        upgrade: &mut Vec<Package>,
        reversedeps: i32,
    ) -> Vec<DepMissing> {
        unimplemented!();
        // 	alpm_list_t *i, *j;
        // 	alpm_list_t *dblist = NULL, *modified = NULL;
        let mut dblist = Vec::new();
        let mut modified = Vec::new();
        let mut baddeps = Vec::new(); // 	alpm_list_t *baddeps = NULL;
        let nodepversion; // 	int nodepversion;
        let mut rem; //

        if remw.is_some() {
            rem = remw.unwrap();
        } else {
            rem = Vec::new();
        }
        if pkglist.is_some() {
            for pkg in pkglist.unwrap() {
                // Package *pkg = i->data;
                if alpm_pkg_find(upgrade, &pkg.name).is_some()
                    || alpm_pkg_find(&mut rem, &pkg.name).is_some()
                {
                    modified.push(pkg);
                } else {
                    dblist.push(pkg);
                }
            }
        }

        nodepversion = self.no_dep_version();

        /* look for unsatisfied dependencies of the upgrade list */
        for ref mut tp in &*upgrade {
            // Package *tp = i->data;
            // _alpm_log(
            //     handle,
            //     ALPM_LOG_DEBUG,
            //     "checkdeps: package %s-%s\n",
            //     tp.name,
            //     tp.version,
            // );

            for mut depend in &tp.depends {
                // Dependency *depend = j->data;
                let orig_mod = depend.depmod.clone();
                // if (nodepversion) {
                //     depend.depmod = alpm_depmod_t::ALPM_DEP_MOD_ANY;
                // }
                /* 1. we check the upgrade list */
                /* 2. we check database for untouched satisfying packages */
                /* 3. we check the dependency ignore list */
                if find_dep_satisfier(upgrade, &depend).is_none()
                    && find_dep_satisfier(&dblist, &depend).is_none()
                    && depend._alpm_depcmp_provides(&self.assumeinstalled)
                {
                    unimplemented!();
                    /* Unsatisfied dependency in the upgrade list */
                    // depmissing_t *miss;
                    // let missdepstring = alpm_dep_compute_string(depend);
                    // _alpm_log(handle, ALPM_LOG_DEBUG,
                    //"checkdeps: missing dependency '%s' for package '%s'\n",
                    // 		missdepstring, tp->name);
                    // free(missdepstring);
                    // miss = depmiss_new(tp->name, depend, NULL);
                    // baddeps = alpm_list_add(baddeps, miss);
                }
                // depend.depmod = orig_mod;
            }
        }

        if reversedeps != 0 {
            unimplemented!();
            // 		/* reversedeps handles the backwards dependencies, ie,
            // 		 * the packages listed in the requiredby field. */
            // 		for(i = dblist; i; i = i->next) {
            // 			Package *lp = i->data;
            // 			for(j = alpm_pkg_get_depends(lp); j; j = j->next) {
            // 				Dependency *depend = j->data;
            // 				alpm_depmod_t orig_mod = depend->mod;
            // 				if(nodepversion) {
            // 					depend->mod = ALPM_DEP_MOD_ANY;
            // 				}
            // 				Package *causingpkg = find_dep_satisfier(modified, depend);
            // 				/* we won't break this depend, if it is already broken, we ignore it */
            // 				/* 1. check upgrade list for satisfiers */
            // 				/* 2. check dblist for satisfiers */
            // 				/* 3. we check the dependency ignore list */
            // 				if(causingpkg &&
            // 						!find_dep_satisfier(upgrade, depend) &&
            // 						!find_dep_satisfier(dblist, depend) &&
            // 						!_alpm_depcmp_provides(depend, handle->assumeinstalled)) {
            // 					depmissing_t *miss;
            // 					char *missdepstring = alpm_dep_compute_string(depend);
            //_alpm_log(handle, ALPM_LOG_DEBUG,
            //"checkdeps: transaction would break '%s' dependency of '%s'\n",
            // 							missdepstring, lp->name);
            // 					free(missdepstring);
            // 					miss = depmiss_new(lp->name, depend, causingpkg->name);
            // 					baddeps = alpm_list_add(baddeps, miss);
            // 				}
            // 				depend->mod = orig_mod;
            // 			}
            // 		}
        }

        // 	alpm_list_free(modified);
        // 	alpm_list_free(dblist);
        //
        return baddeps;
    }

    /// Find a package satisfying a specified dependency.
    /// First look for a literal, going through each db one by one. Then look for
    /// providers. The first satisfier found is returned.
    /// The dependency can include versions with depmod operators.
    ///* `handle` the context handle
    ///* `dbs` an alpm_list_t* of Database where the satisfier will be searched
    ///* `depstring` package or provision name, versioned or not
    ///* returns a Package* satisfying depstring
    pub fn alpm_find_dbs_satisfier<T>(&self, dbs: &Vec<T>, depstring: &String) -> Option<Package> {
        unimplemented!();
        // 	Dependency *dep;
        // 	Package *pkg;
        //
        // 	CHECK_HANDLE(handle, return NULL);
        // 	ASSERT(dbs, RET_ERR(handle, ALPM_ERR_WRONG_ARGS, NULL));
        //
        // 	dep = alpm_dep_from_string(depstring);
        // 	ASSERT(dep, return NULL);
        // 	pkg = resolvedep(handle, dep, dbs, NULL, 1);
        // 	alpm_dep_free(dep);
        // 	return pkg;
    }

    ///Check the package conflicts in a database
    ///* `pkglist` the list of packages to check
    ///* returns an alpm_list_t of conflict_t
    pub fn alpm_checkconflicts(&self, pkglist: &Vec<Package>) -> Vec<Conflict> {
        unimplemented!();
        // CHECK_HANDLE(handle, return NULL);
        // return _alpm_innerconflicts(handle, pkglist);
    }

    pub fn _alpm_db_register_sync(&mut self, treename: &String, level: SigLevel) -> Database {
        // 	_alpm_log(handle, ALPM_LOG_DEBUG, "registering sync database '%s'\n", treename);

        // #ifndef HAVE_LIBGPGME
        // 	if(level != ALPM_SIG_USE_DEFAULT) {
        // 		RET_ERR(handle, ALPM_ERR_WRONG_ARGS, NULL);
        // 	}
        // #endif

        let mut db = Database::_alpm_db_new(treename, false);
        db.ops_type = db_ops_type::sync;
        // db->ops = &sync_db_ops;
        // db.handle = handle;
        db.siglevel = level;
        db.create_path(&self.dbpath, &self.dbext);
        db.sync_db_validate(self);

        // handle.dbs_sync.push(db);
        return db;
    }

    pub fn get_sync_dir(&mut self) -> Result<String> {
        let syncpath = format!("{}{}", self.dbpath, "sync/");
        match std::fs::metadata(&syncpath) {
            Err(_e) => {
                debug!("database dir '{}' does not exist, creating it", syncpath);
                if fs::create_dir_all(&syncpath).is_err() {
                    return Err(Error::System);
                }
            }
            Ok(m) => {
                if !m.is_dir() {
                    warn!("removing invalid file: {}", syncpath);
                    if std::fs::remove_file(&syncpath).is_err()
                        || fs::create_dir_all(&syncpath).is_err()
                    {
                        return Err(Error::System);
                    }
                }
            }
        }

        return Ok(syncpath);
    }

    /// Load a package and create the corresponding Package struct.
    ///* `pkgfile` path to the package file
    ///* `full` whether to stop the load after metadata is read or continue
    ///through the full archive
    fn _alpm_pkg_load_internal(&self, pkgfile: &String, full: i32) -> Package {
        unimplemented!();
        // 	int ret, fd;
        // 	int config = 0;
        // 	int hit_mtree = 0;
        // 	struct archive *archive;
        // 	struct archive_entry *entry;
        // 	Package *newpkg;
        // 	struct stat st;
        // 	size_t files_size = 0;
        //
        // 	if(pkgfile == NULL || strlen(pkgfile) == 0) {
        // 		RET_ERR(handle, ALPM_ERR_WRONG_ARGS, NULL);
        // 	}
        //
        // 	fd = _alpm_open_archive(handle, pkgfile, &st, &archive, ALPM_ERR_PKG_OPEN);
        // 	if(fd < 0) {
        // 		if(errno == ENOENT) {
        // 			handle->pm_errno = ALPM_ERR_PKG_NOT_FOUND;
        // 		} else if(errno == EACCES) {
        // 			handle->pm_errno = ALPM_ERR_BADPERMS;
        // 		} else {
        // 			handle->pm_errno = ALPM_ERR_PKG_OPEN;
        // 		}
        // 		return NULL;
        // 	}
        //
        // 	newpkg = _alpm_pkg_new();
        // 	if(newpkg == NULL) {
        // 		handle->pm_errno = ALPM_ERR_MEMORY;
        // 		goto error;
        // 	}
        // 	STRDUP(newpkg->filename, pkgfile,
        // 			handle->pm_errno = ALPM_ERR_MEMORY; goto error);
        // 	newpkg->size = st.st_size;
        //
        // 	_alpm_log(handle, ALPM_LOG_DEBUG, "starting package load for %s\n", pkgfile);
        //
        // 	/* If full is false, only read through the archive until we find our needed
        // 	 * metadata. If it is true, read through the entire archive, which serves
        // 	 * as a verification of integrity and allows us to create the filelist. */
        // 	while((ret = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        // 		const char *entry_name = archive_entry_pathname(entry);
        //
        // 		if(strcmp(entry_name, ".PKGINFO") == 0) {
        // 			/* parse the info file */
        // 			if(parse_descfile(handle, archive, newpkg) != 0) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("could not parse package description file in %s\n"),
        // 						pkgfile);
        // 				goto pkg_invalid;
        // 			}
        // 			if(newpkg->name == NULL || strlen(newpkg->name) == 0) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("missing package name in %s\n"), pkgfile);
        // 				goto pkg_invalid;
        // 			}
        // 			if(newpkg->version == NULL || strlen(newpkg->version) == 0) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("missing package version in %s\n"), pkgfile);
        // 				goto pkg_invalid;
        // 			}
        // 			if(strchr(newpkg->version, '-') == NULL) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("invalid package version in %s\n"), pkgfile);
        // 				goto pkg_invalid;
        // 			}
        // 			config = 1;
        // 			continue;
        // 		} else if(full && strcmp(entry_name, ".MTREE") == 0) {
        // 			/* building the file list: cheap way
        // 			 * get the filelist from the mtree file rather than scanning
        // 			 * the whole archive  */
        // 			hit_mtree = build_filelist_from_mtree(handle, newpkg, archive) == 0;
        // 			continue;
        // 		} else if(handle_simple_path(newpkg, entry_name)) {
        // 			continue;
        // 		} else if(full && !hit_mtree) {
        // 			/* building the file list: expensive way */
        // 			if(add_entry_to_files_list(&newpkg->files, &files_size, entry, entry_name) < 0) {
        // 				goto error;
        // 			}
        // 		}
        //
        // 		if(archive_read_data_skip(archive)) {
        // 			_alpm_log(handle, ALPM_LOG_ERROR, _("error while reading package %s: %s\n"),
        // 					pkgfile, archive_error_string(archive));
        // 			handle->pm_errno = ALPM_ERR_LIBARCHIVE;
        // 			goto error;
        // 		}
        //
        // 		/* if we are not doing a full read, see if we have all we need */
        // 		if((!full || hit_mtree) && config) {
        // 			break;
        // 		}
        // 	}
        //
        // 	if(ret != ARCHIVE_EOF && ret != ARCHIVE_OK) { /* An error occurred */
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("error while reading package %s: %s\n"),
        // 				pkgfile, archive_error_string(archive));
        // 		handle->pm_errno = ALPM_ERR_LIBARCHIVE;
        // 		goto error;
        // 	}
        //
        // 	if(!config) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("missing package metadata in %s\n"), pkgfile);
        // 		goto pkg_invalid;
        // 	}
        //
        // 	_alpm_archive_read_free(archive);
        // 	close(fd);
        //
        // 	/* internal fields for package struct */
        // 	newpkg->origin = ALPM_PKG_FROM_FILE;
        // 	newpkg->origin_data.file = strdup(pkgfile);
        // 	newpkg->ops = get_file_pkg_ops();
        // 	newpkg->handle = handle;
        // 	newpkg->infolevel = INFRQ_BASE | INFRQ_DESC | INFRQ_SCRIPTLET;
        // 	newpkg->validation = ALPM_PKG_VALIDATION_NONE;
        //
        // 	if(full) {
        // 		if(newpkg->files.files) {
        // 			/* attempt to hand back any memory we don't need */
        // 			newpkg->files.files = realloc(newpkg->files.files,
        // 					sizeof(alpm_file_t) * newpkg->files.count);
        // 			/* "checking for conflicts" requires a sorted list, ensure that here */
        // 			_alpm_log(handle, ALPM_LOG_DEBUG,
        // 					"sorting package filelist for %s\n", pkgfile);
        //
        // 			_alpm_filelist_sort(&newpkg->files);
        // 		}
        // 		newpkg->infolevel |= INFRQ_FILES;
        // 	}
        //
        // 	return newpkg;
        //
        // pkg_invalid:
        // 	handle->pm_errno = ALPM_ERR_PKG_INVALID;
        // error:
        // 	_alpm_pkg_free(newpkg);
        // 	_alpm_archive_read_free(archive);
        // 	if(fd >= 0) {
        // 		close(fd);
        // 	}
        //
        // 	return NULL;
    }

    ///adopted limit from repo-add
    const MAX_SIGFILE_SIZE: i16 = 16384;

    pub fn read_sigfile(sigpath: &String, sig: &mut String) -> i32 {
        unimplemented!();
        // 	struct stat st;
        // 	FILE *fp;
        //
        // 	if((fp = fopen(sigpath, "rb")) == NULL) {
        // 		return -1;
        // 	}
        //
        // 	if(fstat(fileno(fp), &st) != 0 || st.st_size > MAX_SIGFILE_SIZE) {
        // 		fclose(fp);
        // 		return -1;
        // 	}
        //
        // 	MALLOC(*sig, st.st_size, fclose(fp); return -1);
        //
        // 	if(fread(*sig, st.st_size, 1, fp) != 1) {
        // 		free(*sig);
        // 		fclose(fp);
        // 		return -1;
        // 	}
        //
        // 	fclose(fp);
        // 	return st.st_size;
    }

    pub fn alpm_pkg_load(
        &self,
        filename: &String,
        full: i32,
        level: &SigLevel,
        pkg: &Package,
    ) -> Result<i32> {
        unimplemented!();
        // 	int validation = 0;
        // 	char *sigpath;
        //
        // 	CHECK_HANDLE(handle, return -1);
        // 	ASSERT(pkg != NULL, RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1));
        //
        // 	sigpath = _alpm_sigpath(handle, filename);
        // 	if(sigpath && !_alpm_access(handle, NULL, sigpath, R_OK)) {
        // 		if(level & ALPM_SIG_PACKAGE) {
        // 			alpm_list_t *keys = NULL;
        // 			int fail = 0;
        // 			unsigned char *sig = NULL;
        // 			int len = read_sigfile(sigpath, &sig);
        //
        // 			if(len == -1) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR,
        // 					_("failed to read signature file: %s\n"), sigpath);
        // 				free(sigpath);
        // 				return -1;
        // 			}
        //
        // 			if(alpm_extract_keyid(handle, filename, sig, len, &keys) == 0) {
        // 				alpm_list_t *k;
        // 				for(k = keys; k; k = k->next) {
        // 					char *key = k->data;
        // 					if(_alpm_key_in_keychain(handle, key) == 0) {
        // 						if(_alpm_key_import(handle, key) == -1) {
        // 							fail = 1;
        // 						}
        // 					}
        // 				}
        // 				FREELIST(keys);
        // 			}
        //
        // 			free(sig);
        //
        // 			if(fail) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("required key missing from keyring\n"));
        // 				free(sigpath);
        // 				return -1;
        // 			}
        // 		}
        // 	}
        // 	free(sigpath);
        //
        // 	if(_alpm_pkg_validate_internal(handle, filename, NULL, level, NULL,
        // 				&validation) == -1) {
        // 		/* pm_errno is set by pkg_validate */
        // 		return -1;
        // 	}
        // 	*pkg = _alpm_pkg_load_internal(handle, filename, full);
        // 	if(*pkg == NULL) {
        // 		/* pm_errno is set by pkg_load */
        // 		return -1;
        // 	}
        // 	(*pkg)->validation = validation;
        //
        // 	return 0;
    }

    ///Test if a package should be ignored.
    ///Checks if the package is ignored via IgnorePkg, or if the package is
    ///in a group ignored via IgnoreGroup.
    pub fn alpm_pkg_should_ignore(&self, pkg: &Package) -> bool {
        unimplemented!();
        // 	alpm_list_t *groups = NULL;
        //
        // 	/* first see if the package is ignored */
        // if alpm_list_find(self.ignorepkg, pkg.name, _alpm_fnmatch) {
        //     return true;
        // }
        //
        // /* next see if the package is in a group that is ignored */
        // for grp in pkg.alpm_pkg_get_groups() {
        //     // char *grp = groups->data;
        //     if alpm_list_find(self.ignoregroup, grp, _alpm_fnmatch) {
        //         return true;
        //     }
        // }
        //
        // return false;
    }

    /// Unregister all package databases.
    pub fn alpm_unregister_all_syncdbs(&self) -> i32 {
        unimplemented!();
        // 	alpm_list_t *i;
        // 	Database *db;
        //
        // 	/* Sanity checks */
        // 	CHECK_HANDLE(handle, return -1);
        // 	/* Do not unregister a database if a transaction is on-going */
        // 	ASSERT(handle->trans == NULL, RET_ERR(handle, ALPM_ERR_TRANS_NOT_NULL, -1));
        //
        // 	/* unregister all sync dbs */
        // 	for(i = handle->dbs_sync; i; i = i->next) {
        // 		db = i->data;
        // 		db->ops->unregister(db);
        // 		i->data = NULL;
        // 	}
        // 	FREELIST(handle->dbs_sync);
        // 	return 0;
    }

    /// Register a sync database of packages.
    pub fn alpm_register_syncdb(
        &mut self,
        treename: &String,
        siglevel: SigLevel,
    ) -> Result<Database> {
        /* ensure database name is unique */
        if treename == "local" {
            return Err(Error::ALPM_ERR_DB_NOT_NULL);
        }
        for d in &self.dbs_sync {
            if treename == &d.treename {
                return Err(Error::ALPM_ERR_DB_NOT_NULL);
            }
        }

        Ok(self._alpm_db_register_sync(&treename, siglevel))
    }

    pub fn _alpm_db_register_local(&mut self) -> Result<&Database> {
        let mut db;
        debug!("registering local database");

        db = Database::_alpm_db_new(&String::from("local"), true);
        // db.ops = &local_db_ops;
        db.ops_type = db_ops_type::local;
        db.usage.all = true;
        db.create_path(&self.dbpath, &self.dbext)?;
        db.local_db_validate()?;

        self.db_local = db;
        return Ok(&self.db_local);
    }

    /// Add a package to the transaction.
    pub fn alpm_add_pkg(&mut self, pkg: &mut Package) -> Result<()> {
        let trans: &mut Transaction = &mut self.trans;
        let pkgname: &String = &pkg.name;
        let pkgver: String = pkg.version.clone();

        debug!("adding package '{}'", pkgname);

        if alpm_pkg_find(&mut trans.add, &pkgname).is_some() {
            return Err(Error::ALPM_ERR_TRANS_DUP_TARGET);
        }

        match self.db_local._alpm_db_get_pkgfromcache(pkgname) {
            Some(local) => {
                let localpkgname: &String = &local.name;
                let localpkgver: &String = &local.version;
                let cmp: i8 = pkg._alpm_pkg_compare_versions(&local);

                if cmp == 0 {
                    if trans.flags.needed {
                        /* with the NEEDED flag, packages up to date are not reinstalled */
                        warn!(
                            "{}-{} is up to date -- skipping\n",
                            localpkgname, localpkgver
                        );
                        return Ok(());
                    } else if !trans.flags.download_only {
                        warn!(
                            "{}-{} is up to date -- reinstalling\n",
                            localpkgname, localpkgver
                        );
                    }
                } else if cmp < 0 && !trans.flags.download_only {
                    /* local version is newer */
                    warn!(
                        "downgrading package {} ({} => {})\n",
                        localpkgname, localpkgver, pkgver
                    );
                }
            }
            None => {}
        }

        /* add the package to the transaction */
        pkg.reason = PackageReason::ALPM_PKG_REASON_EXPLICIT;
        debug!(
            "adding package {}-{} to the transaction add list\n",
            pkgname, pkgver
        );
        trans.add.push(pkg.clone());
        Ok(())
    }

    pub fn perform_extraction(
        &self,
        archive: &Archive,
        entry: &ArchiveEntry,
        filename: &String,
    ) -> i32 {
        unimplemented!();
        // 	int ret;
        // 	struct archive *archive_writer;
        // 	const int archive_flags = ARCHIVE_EXTRACT_OWNER |
        // 	                          ARCHIVE_EXTRACT_PERM |
        // 	                          ARCHIVE_EXTRACT_TIME |
        // 	                          ARCHIVE_EXTRACT_UNLINK |
        // 	                          ARCHIVE_EXTRACT_SECURE_SYMLINKS;
        //
        // 	archive_entry_set_pathname(entry, filename);
        //
        // 	archive_writer = archive_write_disk_new();
        // 	if (archive_writer == NULL) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("cannot allocate disk archive object"));
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 				"error: cannot allocate disk archive object");
        // 		return 1;
        // 	}
        //
        // 	archive_write_disk_set_options(archive_writer, archive_flags);
        //
        // 	ret = archive_read_extract2(archive, entry, archive_writer);
        //
        // 	archive_write_free(archive_writer);
        //
        // 	if(ret == ARCHIVE_WARN && archive_errno(archive) != ENOSPC) {
        // 		/* operation succeeded but a "non-critical" error was encountered */
        // 		_alpm_log(handle, ALPM_LOG_WARNING, _("warning given when extracting {} ({})\n"),
        // 				filename, archive_error_string(archive));
        // 	} else if(ret != ARCHIVE_OK) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not extract {} ({})\n"),
        // 				filename, archive_error_string(archive));
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 				"error: could not extract {} ({})\n",
        // 				filename, archive_error_string(archive));
        // 		return 1;
        // 	}
        // 	return 0;
    }

    pub fn _alpm_upgrade_packages(&mut self) -> Result<()> {
        let mut skip_ldconfig: bool = false;
        let mut ret: Result<()> = Ok(());
        let pkg_count: usize;
        let mut pkg_current: usize;

        if self.trans.add.is_empty() {
            return Ok(());
        }

        pkg_count = self.trans.add.len();
        pkg_current = 1;

        /* loop through our package list adding/upgrading one at a time */
        for newpkg in &self.trans.add {
            match &self.trans.state {
                &AlpmTransstate::Initialized => {
                    return ret;
                }
                _ => {}
            }

            if self.commit_single_pkg(&newpkg, pkg_current, pkg_count) != 0 {
                /* something screwed up on the commit, abort the trans */
                self.trans.state = AlpmTransstate::Initialized;
                /* running ldconfig at this point could possibly screw system */
                skip_ldconfig = true;
                ret = Err(Error::ALPM_ERR_TRANS_ABORT);
            }

            pkg_current += 1;
        }

        if !skip_ldconfig {
            /* run ldconfig if it exists */
            self._alpm_ldconfig();
        }

        ret
    }

    pub fn try_rename(&self, src: &String, dest: &String) -> i32 {
        match std::fs::rename(src, dest) {
            Err(e) => {
                error!("could not rename {} to {} ({})\n", src, dest, e);
                return 1;
            }
            Ok(()) => {}
        }
        return 0;
    }

    pub fn extract_db_file(
        &self,
        archive: &Archive,
        entry: &ArchiveEntry,
        newpkg: &Package,
        entryname: &String,
    ) -> i32 {
        unimplemented!();
        // 	char filename[PATH_MAX]; /* the actual file we're extracting */
        // 	const char *dbfile = NULL;
        // 	if(strcmp(entryname, ".INSTALL") == 0) {
        // 		dbfile = "install";
        // 	} else if(strcmp(entryname, ".CHANGELOG") == 0) {
        // 		dbfile = "changelog";
        // 	} else if(strcmp(entryname, ".MTREE") == 0) {
        // 		dbfile = "mtree";
        // 	} else if(*entryname == '.') {
        // 		/* reserve all files starting with '.' for future possibilities */
        // 		debug!("skipping extraction of '{}'\n", entryname);
        // 		archive_read_data_skip(archive);
        // 		return 0;
        // 	}
        // 	archive_entry_set_perm(entry, 0644);
        // 	snprintf(filename, PATH_MAX, "{}{}-{}/{}",
        // 			_alpm_db_path(handle->db_local), newpkg->name, newpkg->version, dbfile);
        // 	return perform_extraction(handle, archive, entry, filename);
    }

    pub fn extract_single_file(
        &self,
        archive: &Archive,
        entry: &ArchiveEntry,
        newpkg: &Package,
        oldpkg: &Package,
    ) -> i32 {
        unimplemented!();
        // 	const char *entryname = archive_entry_pathname(entry);
        // 	mode_t entrymode = archive_entry_mode(entry);
        // 	alpm_backup_t *backup = _alpm_needbackup(entryname, newpkg);
        // 	char filename[PATH_MAX]; /* the actual file we're extracting */
        // 	int needbackup = 0, notouch = 0;
        // 	const char *hash_orig = NULL;
        // 	int isnewfile = 0, errors = 0;
        // 	struct stat lsbuf;
        // 	size_t filename_len;
        //
        // 	if(*entryname == '.') {
        // 		return extract_db_file(handle, archive, entry, newpkg, entryname);
        // 	}
        //
        // 	if (!alpm_filelist_contains(&newpkg->files, entryname)) {
        // 		_alpm_log(handle, ALPM_LOG_WARNING,
        // 				_("file not found in file list for package {}. skipping extraction of {}\n"),
        // 				newpkg->name, entryname);
        // 		return 0;
        // 	}
        //
        // 	/* build the new entryname relative to handle->root */
        // 	filename_len = snprintf(filename, PATH_MAX, "{}{}", handle->root, entryname);
        // 	if(filename_len >= PATH_MAX) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR,
        // 				_("unable to extract {}{}: path too long"), handle->root, entryname);
        // 		return 1;
        // 	}
        //
        // 	/* if a file is in NoExtract then we never extract it */
        // 	if(_alpm_fnmatch_patterns(handle->noextract, entryname) == 0) {
        // 		debug!("{} is in NoExtract,"
        // 				" skipping extraction of {}\n",
        // 				entryname, filename);
        // 		archive_read_data_skip(archive);
        // 		return 0;
        // 	}
        //
        // 	/* Check for file existence. This is one of the more crucial parts
        // 	 * to get 'right'. Here are the possibilities, with the filesystem
        // 	 * on the left and the package on the top:
        // 	 * (F=file, N=node, S=symlink, D=dir)
        // 	 *               |  F/N  |   D
        // 	 *  non-existent |   1   |   2
        // 	 *  F/N          |   3   |   4
        // 	 *  D            |   5   |   6
        // 	 *
        // 	 *  1,2- extract, no magic necessary. lstat (llstat) will fail here.
        // 	 *  3,4- conflict checks should have caught this. either overwrite
        // 	 *      or backup the file.
        // 	 *  5- file replacing directory- don't allow it.
        // 	 *  6- skip extraction, dir already exists.
        // 	 */
        //
        // 	isnewfile = llstat(filename, &lsbuf) != 0;
        // 	if(isnewfile) {
        // 		/* cases 1,2: file doesn't exist, skip all backup checks */
        // 	} else if(S_ISDIR(lsbuf.st_mode) && S_ISDIR(entrymode)) {
        // #if 0
        // 		uid_t entryuid = archive_entry_uid(entry);
        // 		gid_t entrygid = archive_entry_gid(entry);
        // #endif
        //
        // 		/* case 6: existing dir, ignore it */
        // 		if(lsbuf.st_mode != entrymode) {
        // 			/* if filesystem perms are different than pkg perms, warn user */
        // 			mode_t mask = 07777;
        // 			_alpm_log(handle, ALPM_LOG_WARNING, _("directory permissions differ on {}\n"
        // 					"filesystem: %o  package: %o\n"), filename, lsbuf.st_mode & mask,
        // 					entrymode & mask);
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 					"warning: directory permissions differ on {}\n"
        // 					"filesystem: %o  package: %o\n", filename, lsbuf.st_mode & mask,
        // 					entrymode & mask);
        // 		}
        //
        // #if 0
        // 		/* Disable this warning until our user management in packages has improved.
        // 		   Currently many packages have to create users in post_install and chown the
        // 		   directories. These all resulted in "false-positive" warnings. */
        //
        // 		if((entryuid != lsbuf.st_uid) || (entrygid != lsbuf.st_gid)) {
        // 			_alpm_log(handle, ALPM_LOG_WARNING, _("directory ownership differs on {}\n"
        // 					"filesystem: %u:%u  package: %u:%u\n"), filename,
        // 					lsbuf.st_uid, lsbuf.st_gid, entryuid, entrygid);
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 					"warning: directory ownership differs on {}\n"
        // 					"filesystem: %u:%u  package: %u:%u\n", filename,
        // 					lsbuf.st_uid, lsbuf.st_gid, entryuid, entrygid);
        // 		}
        // #endif
        //
        // 		debug!("extract: skipping dir extraction of {}\n",
        // 				filename);
        // 		archive_read_data_skip(archive);
        // 		return 0;
        // 	} else if(S_ISDIR(lsbuf.st_mode)) {
        // 		/* case 5: trying to overwrite dir with file, don't allow it */
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("extract: not overwriting dir with file {}\n"),
        // 				filename);
        // 		archive_read_data_skip(archive);
        // 		return 1;
        // 	} else if(S_ISDIR(entrymode)) {
        // 		/* case 4: trying to overwrite file with dir */
        // 		debug!("extract: overwriting file with dir {}\n",
        // 				filename);
        // 	} else {
        // 		/* case 3: trying to overwrite file with file */
        // 		/* if file is in NoUpgrade, don't touch it */
        // 		if(_alpm_fnmatch_patterns(handle->noupgrade, entryname) == 0) {
        // 			notouch = 1;
        // 		} else {
        // 			alpm_backup_t *oldbackup;
        // 			if(oldpkg && (oldbackup = _alpm_needbackup(entryname, oldpkg))) {
        // 				hash_orig = oldbackup->hash;
        // 				needbackup = 1;
        // 			} else if(backup) {
        // 				/* allow adding backup files retroactively */
        // 				needbackup = 1;
        // 			}
        // 		}
        // 	}
        //
        // 	if(notouch || needbackup) {
        // 		if(filename_len + strlen(".pacnew") >= PATH_MAX) {
        // 			_alpm_log(handle, ALPM_LOG_ERROR,
        // 					_("unable to extract {}.pacnew: path too long"), filename);
        // 			return 1;
        // 		}
        // 		strcpy(filename + filename_len, ".pacnew");
        // 		isnewfile = (llstat(filename, &lsbuf) != 0 && errno == ENOENT);
        // 	}
        //
        // 	debug!("extracting {}\n", filename);
        // 	if(perform_extraction(handle, archive, entry, filename)) {
        // 		errors++;
        // 		return errors;
        // 	}
        //
        // 	if(backup) {
        // 		FREE(backup->hash);
        // 		backup->hash = alpm_compute_md5sum(filename);
        // 	}
        //
        // 	if(notouch) {
        // 		alpm_event_pacnew_created_t event = {
        // 			.type = ALPM_EVENT_PACNEW_CREATED,
        // 			.from_noupgrade = 1,
        // 			.oldpkg = oldpkg,
        // 			.newpkg = newpkg,
        // 			.file = filename
        // 		};
        // 		/* "remove" the .pacnew suffix */
        // 		filename[filename_len] = '\0';
        // 		EVENT(handle, &event);
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 				"warning: {} installed as {}.pacnew\n", filename, filename);
        // 	} else if(needbackup) {
        // 		char *hash_local = NULL, *hash_pkg = NULL;
        // 		char origfile[PATH_MAX] = "";
        //
        // 		strncat(origfile, filename, filename_len);
        //
        // 		hash_local = alpm_compute_md5sum(origfile);
        // 		hash_pkg = backup ? backup->hash : alpm_compute_md5sum(filename);
        //
        // 		debug!("checking hashes for {}\n", origfile);
        // 		debug!("current:  {}\n", hash_local);
        // 		debug!("new:      {}\n", hash_pkg);
        // 		debug!("original: {}\n", hash_orig);
        //
        // 		if(hash_local && hash_pkg && strcmp(hash_local, hash_pkg) == 0) {
        // 			/* local and new files are the same, updating anyway to get
        // 			 * correct timestamps */
        // 			debug!("action: installing new file: {}\n",
        // 					origfile);
        // 			if(try_rename(handle, filename, origfile)) {
        // 				errors++;
        // 			}
        // 		} else if(hash_orig && hash_pkg && strcmp(hash_orig, hash_pkg) == 0) {
        // 			/* original and new files are the same, leave the local version alone,
        // 			 * including any user changes */
        // 			debug!(
        // 					"action: leaving existing file in place\n");
        // 			if(isnewfile) {
        // 				unlink(filename);
        // 			}
        // 		} else if(hash_orig && hash_local && strcmp(hash_orig, hash_local) == 0) {
        // 			/* installed file has NOT been changed by user,
        // 			 * update to the new version */
        // 		debug!(action: installing new file: {}\n",
        // 					origfile);
        // 			if(try_rename(handle, filename, origfile)) {
        // 				errors++;
        // 			}
        // 		} else {
        // 			/* none of the three files matched another,  leave the unpacked
        // 			 * file alongside the local file */
        // 			alpm_event_pacnew_created_t event = {
        // 				.type = ALPM_EVENT_PACNEW_CREATED,
        // 				.from_noupgrade = 0,
        // 				.oldpkg = oldpkg,
        // 				.newpkg = newpkg,
        // 				.file = origfile
        // 			};
        // 			debug!(
        // 					"action: keeping current file and installing"
        // 					" new one with .pacnew ending\n");
        // 			EVENT(handle, &event);
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 					"warning: {} installed as {}\n", origfile, filename);
        // 		}
        //
        // 		free(hash_local);
        // 		if(!backup) {
        // 			free(hash_pkg);
        // 		}
        // 	}
        // 	return errors;
    }

    pub fn commit_single_pkg(&self, newpkg: &Package, pkg_current: usize, pkg_count: usize) -> i32 {
        unimplemented!();
        // 	int i, ret = 0, errors = 0;
        // 	int is_upgrade = 0;
        let oldpkg: &Option<Package>;
        // 	Package *oldpkg = NULL;
        // 	Database *db = handle->db_local;
        // 	alpm_trans_t *trans = handle->trans;
        // 	alpm_progress_t progress = ALPM_PROGRESS_ADD_START;
        // 	alpm_event_package_operation_t event;
        // 	const char *log_msg = "adding";
        // 	const char *pkgfile;
        // 	struct archive *archive;
        // 	struct archive_entry *entry;
        // 	int fd, cwdfd;
        // 	struct stat buf;
        //
        // 	ASSERT(trans != NULL, return -1);

        /* see if this is an upgrade. if so, remove the old package first */
        // match newpkg.oldpkg {
        //     Some(ref oldpkg) => {
        //         // int cmp = _alpm_pkg_compare_versions(newpkg, oldpkg);
        //         let cpm = newpkg._alpm_pkg_compare_versions(oldpkg);
        //         // 		if(cmp < 0) {
        //         // 			log_msg = "downgrading";
        //         // 			progress = ALPM_PROGRESS_DOWNGRADE_START;
        //         // 			event.operation = ALPM_PACKAGE_DOWNGRADE;
        //         // 		} else if(cmp == 0) {
        //         // 			log_msg = "reinstalling";
        //         // 			progress = ALPM_PROGRESS_REINSTALL_START;
        //         // 			event.operation = ALPM_PACKAGE_REINSTALL;
        //         // 		} else {
        //         // 			log_msg = "upgrading";
        //         // 			progress = ALPM_PROGRESS_UPGRADE_START;
        //         // 			event.operation = ALPM_PACKAGE_UPGRADE;
        //         // 		}
        //         // 		is_upgrade = 1;
        //         //
        //         // 		/* copy over the install reason */
        //         // 		newpkg->reason = alpm_pkg_get_reason(oldpkg);
        //     }
        //     None => {
        //         // event.operation = ALPM_PACKAGE_INSTALL;
        //     }
        // };

        // 	event.type = ALPM_EVENT_PACKAGE_OPERATION_START;
        // 	event.oldpkg = oldpkg;
        // 	event.newpkg = newpkg;
        // 	EVENT(handle, &event);
        //
        // 	pkgfile = newpkg->origin_data.file;
        //
        // 	debug!("{} package {}-{}\n",
        // 			log_msg, newpkg->name, newpkg->version);
        /* pre_install/pre_upgrade scriptlet */
        // 	if(alpm_pkg_has_scriptlet(newpkg) &&
        // 			!(trans->flags & ALPM_TRANS_FLAG_NOSCRIPTLET)) {
        // 		const char *scriptlet_name = is_upgrade ? "pre_upgrade" : "pre_install";
        //
        // 		_alpm_runscriptlet(handle, pkgfile, scriptlet_name,
        // 				newpkg->version, oldpkg ? oldpkg->version : NULL, 1);
        // 	}

        /* we override any pre-set reason if we have alldeps or allexplicit set */
        // 	if(trans->flags & ALPM_TRANS_FLAG_ALLDEPS) {
        // 		newpkg->reason = ALPM_PKG_REASON_DEPEND;*
        // 	} else if(trans->flags & ALPM_TRANS_FLAG_ALLEXPLICIT) {
        // 		newpkg->reason = ALPM_PKG_REASON_EXPLICIT;
        // 	}

        // 	if(oldpkg) {
        // 		/* set up fake remove transaction */
        // 		if(_alpm_remove_single_package(handle, oldpkg, newpkg, 0, 0) == -1) {
        // 			handle->pm_errno = ALPM_ERR_TRANS_ABORT;
        // 			ret = -1;
        // 			goto cleanup;
        // 		}
        // 	}

        /* prepare directory for database entries so permissions are correct after
        	   changelog/install script installation */
        // 	if(_alpm_local_db_prepare(db, newpkg)) {
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 				"error: could not create database entry {}-{}\n",
        // 				newpkg->name, newpkg->version);
        // 		handle->pm_errno = ALPM_ERR_DB_WRITE;
        // 		ret = -1;
        // 		goto cleanup;
        // 	}
        //
        // 	fd = _alpm_open_archive(db->handle, pkgfile, &buf,
        // 			&archive, ALPM_ERR_PKG_OPEN);
        // 	if(fd < 0) {
        // 		ret = -1;
        // 		goto cleanup;
        // 	}
        //
        // 	/* save the cwd so we can restore it later */
        // 	OPEN(cwdfd, ".", O_RDONLY | O_CLOEXEC);
        // 	if(cwdfd < 0) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not get current working directory\n"));
        // 	}
        //
        // 	/* libarchive requires this for extracting hard links */
        // 	if(chdir(handle->root) != 0) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not change directory to {} ({})\n"),
        // 				handle->root, strerror(errno));
        // 		_alpm_archive_read_free(archive);
        // 		if(cwdfd >= 0) {
        // 			close(cwdfd);
        // 		}
        // 		close(fd);
        // 		ret = -1;
        // 		goto cleanup;
        // 	}
        //
        // 	if(trans->flags & ALPM_TRANS_FLAG_DBONLY) {
        // 		debug!("extracting db files\n");
        // 		while(archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
        // 			const char *entryname = archive_entry_pathname(entry);
        // 			if(entryname[0] == '.') {
        // 				errors += extract_db_file(handle, archive, entry, newpkg, entryname);
        // 			} else {
        // 				archive_read_data_skip(archive);
        // 			}
        // 		}
        // 	} else {
        // 		debug!("extracting files\n");
        //
        // 		/* call PROGRESS once with 0 percent, as we sort-of skip that here */
        // 		PROGRESS(handle, progress, newpkg->name, 0, pkg_count, pkg_current);
        //
        // 		for(i = 0; archive_read_next_header(archive, &entry) == ARCHIVE_OK; i++) {
        // 			int percent;
        //
        // 			if(newpkg->size != 0) {
        // 				/* Using compressed size for calculations here, as newpkg->isize is not
        // 				 * exact when it comes to comparing to the ACTUAL uncompressed size
        // 				 * (missing metadata sizes) */
        // 				int64_t pos = _alpm_archive_compressed_ftell(archive);
        // 				percent = (pos * 100) / newpkg->size;
        // 				if(percent >= 100) {
        // 					percent = 100;
        // 				}
        // 			} else {
        // 				percent = 0;
        // 			}
        //
        // 			PROGRESS(handle, progress, newpkg->name, percent, pkg_count, pkg_current);
        //
        // 			/* extract the next file from the archive */
        // 			errors += extract_single_file(handle, archive, entry, newpkg, oldpkg);
        // 		}
        // 	}
        //
        // 	_alpm_archive_read_free(archive);
        // 	close(fd);
        //
        // 	/* restore the old cwd if we have it */
        // 	if(cwdfd >= 0) {
        // 		if(fchdir(cwdfd) != 0) {
        // 			_alpm_log(handle, ALPM_LOG_ERROR,
        // 					_("could not restore working directory ({})\n"), strerror(errno));
        // 		}
        // 		close(cwdfd);
        // 	}
        //
        // 	if(errors) {
        // 		ret = -1;
        // 		if(is_upgrade) {
        // 			_alpm_log(handle, ALPM_LOG_ERROR, _("problem occurred while upgrading {}\n"),
        // 					newpkg->name);
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 					"error: problem occurred while upgrading {}\n",
        // 					newpkg->name);
        // 		} else {
        // 			_alpm_log(handle, ALPM_LOG_ERROR, _("problem occurred while installing {}\n"),
        // 					newpkg->name);
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 					"error: problem occurred while installing {}\n",
        // 					newpkg->name);
        // 		}
        // 	}
        //
        // 	/* make an install date (in UTC) */
        // 	newpkg->installdate = time(NULL);
        //
        // 	debug!("updating database\n");
        // 	debug!("adding database entry '{}'\n", newpkg->name);
        //
        // 	if(_alpm_local_db_write(db, newpkg, INFRQ_ALL)) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not update database entry {}-{}\n"),
        // 				newpkg->name, newpkg->version);
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 				"error: could not update database entry {}-{}\n",
        // 				newpkg->name, newpkg->version);
        // 		handle->pm_errno = ALPM_ERR_DB_WRITE;
        // 		ret = -1;
        // 		goto cleanup;
        // 	}
        //
        // 	if(_alpm_db_add_pkgincache(db, newpkg) == -1) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not add entry '{}' in cache\n"),
        // 				newpkg->name);
        // 	}
        //
        // 	PROGRESS(handle, progress, newpkg->name, 100, pkg_count, pkg_current);
        //
        // 	switch(event.operation) {
        // 		case ALPM_PACKAGE_INSTALL:
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "installed {} ({})\n",
        // 					newpkg->name, newpkg->version);
        // 			break;
        // 		case ALPM_PACKAGE_DOWNGRADE:
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "downgraded {} ({} -> {})\n",
        // 					newpkg->name, oldpkg->version, newpkg->version);
        // 			break;
        // 		case ALPM_PACKAGE_REINSTALL:
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "reinstalled {} ({})\n",
        // 					newpkg->name, newpkg->version);
        // 			break;
        // 		case ALPM_PACKAGE_UPGRADE:
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "upgraded {} ({} -> {})\n",
        // 					newpkg->name, oldpkg->version, newpkg->version);
        // 			break;
        // 		default:
        // 			/* we should never reach here */
        // 			break;
        // 	}
        //
        // 	/* run the post-install script if it exists */
        // 	if(alpm_pkg_has_scriptlet(newpkg)
        // 			&& !(trans->flags & ALPM_TRANS_FLAG_NOSCRIPTLET)) {
        // 		char *scriptlet = _alpm_local_db_pkgpath(db, newpkg, "install");
        // 		const char *scriptlet_name = is_upgrade ? "post_upgrade" : "post_install";
        //
        // 		_alpm_runscriptlet(handle, scriptlet, scriptlet_name,
        // 				newpkg->version, oldpkg ? oldpkg->version : NULL, 0);
        // 		free(scriptlet);
        // 	}
        //
        // 	event.type = ALPM_EVENT_PACKAGE_OPERATION_DONE;
        // 	EVENT(handle, &event);
        //
        // cleanup:
        // 	return ret;
    }

    pub fn alpm_option_get_root(&self) -> String {
        return self.root.clone();
    }

    pub fn alpm_option_get_hookdirs(&self) -> Vec<String> {
        self.hookdirs.clone()
    }

    pub fn alpm_option_get_dbpath(&self) -> &String {
        return &self.dbpath;
    }

    pub fn alpm_option_get_cachedirs(&self) -> Vec<String> {
        return self.cachedirs.clone();
    }

    pub fn alpm_option_get_logfile(&self) -> String {
        self.logfile.clone()
    }

    pub fn alpm_option_get_lockfile(&self) -> String {
        self.lockfile.clone()
    }

    pub fn alpm_option_get_gpgdir(&self) -> String {
        self.gpgdir.clone()
    }

    pub fn alpm_option_get_usesyslog(&self) -> i32 {
        return self.usesyslog;
    }

    pub fn alpm_option_get_noupgrades(&self) -> &Vec<String> {
        &self.noupgrade
    }

    pub fn alpm_option_get_noextracts(&self) -> &Vec<String> {
        &self.noextract
    }

    pub fn alpm_option_get_ignorepkgs(&self) -> &Vec<String> {
        &self.ignorepkg
    }

    pub fn alpm_option_get_ignoregroups(&self) -> &Vec<String> {
        &self.ignoregroup
    }

    pub fn alpm_option_get_overwrite_files(&self) -> &Vec<String> {
        &self.overwrite_files
    }

    // alpm_list_t SYMEXPORT *alpm_option_get_assumeinstalled(&self)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->assumeinstalled;
    // }

    // const char SYMEXPORT *alpm_option_get_arch(&self)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->arch;
    // }

    // double SYMEXPORT alpm_option_get_deltaratio(&self)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	return handle->deltaratio;
    // }

    // int SYMEXPORT alpm_option_get_checkspace(&self)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	return handle->checkspace;
    // }

    pub fn alpm_option_get_dbext(&self) -> &String {
        &self.dbext
    }

    // pub fn alpm_option_set_logcb(&mut self,  cb: alpm_cb_log)
    // {
    // 	self.logcb = cb;
    // }

    // int SYMEXPORT alpm_option_set_dlcb(&self, alpm_cb_download cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->dlcb = cb;
    // 	return 0;
    // }

    // fn alpm_option_set_fetchcb(&mut self, cb: alpm_cb_fetch) {
    //     self.fetchcb = cb;
    // }

    // int SYMEXPORT alpm_option_set_totaldlcb(&self, alpm_cb_totaldl cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->totaldlcb = cb;
    // 	return 0;
    // }

    // int SYMEXPORT alpm_option_set_eventcb(Handle *handle, alpm_cb_event cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->eventcb = cb;
    // 	return 0;
    // }

    // int SYMEXPORT alpm_option_set_questioncb(Handle *handle, alpm_cb_question cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->questioncb = cb;
    // 	return 0;
    // }

    // int SYMEXPORT alpm_option_set_progresscb(Handle *handle, alpm_cb_progress cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->progresscb = cb;
    // 	return 0;
    // }

    pub fn alpm_option_add_hookdir(&mut self, hookdir: &String) -> Result<i32> {
        // 	char *newhookdir;
        let newhookdir = match std::fs::canonicalize(hookdir) {
            Err(_) => {
                return Err(Error::Memory);
            }
            Ok(h) => h,
        };
        self.hookdirs
            .push(newhookdir.into_os_string().into_string().unwrap());
        // 	_alpm_log(handle, ALPM_LOG_DEBUG, "option 'hookdir' = %s\n", newhookdir);
        return Ok(0);
    }

    // int SYMEXPORT alpm_option_set_hookdirs(Handle *handle, alpm_list_t *hookdirs)
    // {
    // 	alpm_list_t *i;
    // 	CHECK_HANDLE(handle, return -1);
    // 	if(handle->hookdirs) {
    // 		FREELIST(handle->hookdirs);
    // 	}
    // 	for(i = hookdirs; i; i = i->next) {
    // 		int ret = alpm_option_add_hookdir(handle, i->data);
    // 		if(ret) {
    // 			return ret;
    // 		}
    // 	}
    // 	return 0;
    // }
    //
    // int SYMEXPORT alpm_option_remove_hookdir(Handle *handle, const char *hookdir)
    // {
    // 	char *vdata = NULL;
    // 	char *newhookdir;
    // 	CHECK_HANDLE(handle, return -1);
    // 	ASSERT(hookdir != NULL, RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1));
    //
    // 	newhookdir = canonicalize_path(hookdir);
    // 	if(!newhookdir) {
    // 		RET_ERR(handle, ALPM_ERR_MEMORY, -1);
    // 	}
    // 	handle->hookdirs = alpm_list_remove_str(handle->hookdirs, newhookdir, &vdata);
    // 	FREE(newhookdir);
    // 	if(vdata != NULL) {
    // 		FREE(vdata);
    // 		return 1;
    // 	}
    // 	return 0;
    // }

    pub fn alpm_option_add_cachedir(&mut self, cachedir: &String) -> Result<i32> {
        // 	char *newcachedir;
        //
        /* don't stat the cachedir yet, as it may not even be needed. we can
         * fail later if it is needed and the path is invalid. */
        //
        let newcachedir = match std::fs::canonicalize(cachedir) {
            Err(_) => {
                return Err(Error::Memory);
            }
            Ok(n) => n.into_os_string(),
        };
        self.cachedirs.push(newcachedir.into_string().unwrap());
        // 	_alpm_log(handle, ALPM_LOG_DEBUG, "option 'cachedir' = %s\n", newcachedir);
        return Ok(0);
    }

    pub fn alpm_option_set_cachedirs(&mut self, cachedirs: &Vec<String>) -> Result<i32> {
        // 	alpm_list_t *i;
        for dir in cachedirs {
            self.alpm_option_add_cachedir(&dir)?;
        }
        return Ok(0);
    }

    // int SYMEXPORT alpm_option_remove_cachedir(Handle *handle, const char *cachedir)
    // {
    // 	char *vdata = NULL;
    // 	char *newcachedir;
    // 	CHECK_HANDLE(handle, return -1);
    // 	ASSERT(cachedir != NULL, RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1));
    //
    // 	newcachedir = canonicalize_path(cachedir);
    // 	if(!newcachedir) {
    // 		RET_ERR(handle, ALPM_ERR_MEMORY, -1);
    // 	}
    // 	handle->cachedirs = alpm_list_remove_str(handle->cachedirs, newcachedir, &vdata);
    // 	FREE(newcachedir);
    // 	if(vdata != NULL) {
    // 		FREE(vdata);
    // 		return 1;
    // 	}
    // 	return 0;
    // }

    pub fn alpm_option_set_logfile(&mut self, logfile: &String) -> Result<i32> {
        if logfile == "" {
            return Err(Error::ALPM_ERR_WRONG_ARGS);
        }

        self.logfile = logfile.clone();

        /* close the stream so logaction
         * will reopen a new stream on the new logfile */
        // if handle.logstream {
        // 	fclose(handle->logstream);
        // 	handle.logstream = NULL;
        // }
        // _alpm_log(handle, ALPM_LOG_DEBUG, "option 'logfile' = %s\n", handle->logfile);
        return Ok(0);
    }

    pub fn alpm_option_set_gpgdir(&mut self, gpgdir: &String) -> Result<()> {
        match _alpm_set_directory_option(gpgdir, &mut self.gpgdir, false) {
            Err(err) => return Err(err),
            Ok(_) => Ok(()),
        }
        // 	_alpm_log(handle, ALPM_LOG_DEBUG, "option 'gpgdir' = %s\n", handle->gpgdir);
    }

    pub fn alpm_option_set_usesyslog(&mut self, usesyslog: i32) {
        self.usesyslog = usesyslog;
    }

    // static int _alpm_option_strlist_add(Handle *handle, alpm_list_t **list, const char *str)
    // {
    // 	char *dup;
    // 	CHECK_HANDLE(handle, return -1);
    // 	STRDUP(dup, str, RET_ERR(handle, ALPM_ERR_MEMORY, -1));
    // 	*list = alpm_list_add(*list, dup);
    // 	return 0;
    // }

    fn _alpm_option_strlist_set(&self, list: &mut Vec<String>, newlist: &Vec<String>) {
        *list = newlist.clone();
    }

    // static int _alpm_option_strlist_rem(Handle *handle, alpm_list_t **list, const char *str)
    // {
    // 	char *vdata = NULL;
    // 	CHECK_HANDLE(handle, return -1);
    // 	*list = alpm_list_remove_str(*list, str, &vdata);
    // 	if(vdata != NULL) {
    // 		FREE(vdata);
    // 		return 1;
    // 	}
    // 	return 0;
    // }
    //
    // int SYMEXPORT alpm_option_add_noupgrade(Handle *handle, const char *pkg)
    // {
    // 	return _alpm_option_strlist_add(handle, &(handle->noupgrade), pkg);
    // }

    pub fn alpm_option_set_noupgrades(&mut self, noupgrade: &Vec<String>) {
        self.noupgrade = noupgrade.clone()
    }

    // int SYMEXPORT alpm_option_remove_noupgrade(Handle *handle, const char *pkg)
    // {
    // 	return _alpm_option_strlist_rem(handle, &(handle->noupgrade), pkg);
    // }
    //
    // int SYMEXPORT alpm_option_match_noupgrade(Handle *handle, const char *path)
    // {
    // 	return _alpm_fnmatch_patterns(handle->noupgrade, path);
    // }
    //
    // int SYMEXPORT alpm_option_add_noextract(Handle *handle, const char *path)
    // {
    // 	return _alpm_option_strlist_add(handle, &(handle->noextract), path);
    // }

    pub fn alpm_option_set_noextracts(&mut self, noextract: &Vec<String>) {
        self.noextract = noextract.clone();
    }

    // int SYMEXPORT alpm_option_remove_noextract(Handle *handle, const char *path)
    // {
    // 	return _alpm_option_strlist_rem(handle, &(handle->noextract), path);
    // }
    //
    // int SYMEXPORT alpm_option_match_noextract(Handle *handle, const char *path)
    // {
    // 	return _alpm_fnmatch_patterns(handle->noextract, path);
    // }
    //
    // int SYMEXPORT alpm_option_add_ignorepkg(Handle *handle, const char *pkg)
    // {
    // 	return _alpm_option_strlist_add(handle, &(handle->ignorepkg), pkg);
    // }

    pub fn alpm_option_set_ignorepkgs(&mut self, ignorepkgs: &Vec<String>) {
        self.ignorepkg = ignorepkgs.clone();
    }

    // int SYMEXPORT alpm_option_remove_ignorepkg(Handle *handle, const char *pkg)
    // {
    // 	return _alpm_option_strlist_rem(handle, &(handle->ignorepkg), pkg);
    // }
    //
    // int SYMEXPORT alpm_option_add_ignoregroup(Handle *handle, const char *grp)
    // {
    // 	return _alpm_option_strlist_add(handle, &(handle->ignoregroup), grp);
    // }

    pub fn alpm_option_set_ignoregroups(&mut self, ignoregrps: &Vec<String>) {
        self.ignoregroup = ignoregrps.clone();
    }

    // int SYMEXPORT alpm_option_remove_ignoregroup(Handle *handle, const char *grp)
    // {
    // 	return _alpm_option_strlist_rem(handle, &(handle->ignoregroup), grp);
    // }
    //
    // int SYMEXPORT alpm_option_add_overwrite_file(Handle *handle, const char *glob)
    // {
    // 	return _alpm_option_strlist_add(handle, &(handle->overwrite_files), glob);
    // }

    pub fn alpm_option_set_overwrite_files(&mut self, globs: &Vec<String>) {
        self.overwrite_files = globs.clone();
    }

    // int SYMEXPORT alpm_option_remove_overwrite_file(Handle *handle, const char *glob)
    // {
    // 	return _alpm_option_strlist_rem(handle, &(handle->overwrite_files), glob);
    // }

    pub fn alpm_option_add_assumeinstalled(&mut self, dep: &Dependency) {
        use std::hash::{Hash, Hasher};
        let mut depcpy = Dependency::default();
        let mut hasher = SdbmHasher::default();
        /* fill in name_hash in case dep was built by hand */
        dep.name.hash(&mut hasher);
        depcpy.name_hash = hasher.finish();
        self.assumeinstalled.push(depcpy);
    }

    // int SYMEXPORT alpm_option_set_assumeinstalled(Handle *handle, alpm_list_t *deps)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	if(handle->assumeinstalled) {
    // 		alpm_list_free_inner(handle->assumeinstalled, (alpm_list_fn_free)alpm_dep_free);
    // 		alpm_list_free(handle->assumeinstalled);
    // 	}
    // 	while(deps) {
    // 		if(alpm_option_add_assumeinstalled(handle, deps->data) != 0) {
    // 			return -1;
    // 		}
    // 		deps = deps->next;
    // 	}
    // 	return 0;
    // }
    //
    // static int assumeinstalled_cmp(const void *d1, const void *d2)
    // {
    // 	const Dependency *dep1 = d1;
    // 	const Dependency *dep2 = d2;
    //
    // 	if(dep1->name_hash != dep2->name_hash
    // 			|| strcmp(dep1->name, dep2->name) != 0) {
    // 		return -1;
    // 	}
    //
    // 	if(dep1->version && dep2->version
    // 			&& strcmp(dep1->version, dep2->version) == 0) {
    // 		return 0;
    // 	}
    //
    // 	if(dep1->version == NULL && dep2->version == NULL) {
    // 		return 0;
    // 	}
    //
    //
    // 	return -1;
    // }

    pub fn alpm_option_remove_assumeinstalled(&self, dep: &Dependency) -> i32 {
        unimplemented!();
        // Dependency *vdata = NULL;

        // self.assumeinstalled = alpm_list_remove(handle->assumeinstalled, dep,
        // &assumeinstalled_cmp, (void **)&vdata);
        // if(vdata != NULL) {
        // 	alpm_dep_free(vdata);
        // 	return 1;
        // }

        // return 0;
    }

    pub fn alpm_option_set_arch(&mut self, arch: &String) {
        self.arch = arch.clone();
    }

    pub fn alpm_option_set_deltaratio(&mut self, ratio: f64) -> Result<()> {
        if ratio < 0.0 || ratio > 2.0 {
            return Err(Error::ALPM_ERR_WRONG_ARGS);
        }
        self.deltaratio = ratio;
        Ok(())
    }

    pub fn alpm_get_localdb(&self) -> &Database {
        return &self.db_local;
    }

    pub fn alpm_get_localdb_mut(&mut self) -> &mut Database {
        return &mut self.db_local;
    }

    pub fn alpm_get_syncdbs(&self) -> &Vec<Database> {
        return &self.dbs_sync;
    }

    pub fn alpm_get_syncdbs_mut(&mut self) -> &mut Vec<Database> {
        return &mut self.dbs_sync;
    }

    pub fn alpm_option_set_checkspace(&mut self, checkspace: i32) {
        self.checkspace = checkspace;
    }

    pub fn alpm_option_set_dbext(&mut self, dbext: &String) {
        self.dbext = dbext.clone();

        // _alpm_log(handle, ALPM_LOG_DEBUG, "option 'dbext' = %s\n", handle->dbext);
    }

    pub fn alpm_option_set_default_siglevel(&mut self, level: &SigLevel) -> i32 {
        // #ifdef HAVE_LIBGPGME
        self.siglevel = level.clone();
        // #else
        // 	if(level != 0 && level != ALPM_SIG_USE_DEFAULT) {
        // 		RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1);
        // 	}
        // #endif
        return 0;
    }

    fn alpm_option_get_default_siglevel(&self) -> SigLevel {
        // CHECK_HANDLE(handle, return -1);
        return self.siglevel;
    }

    pub fn alpm_option_set_local_file_siglevel(&mut self, level: SigLevel) -> Result<i32> {
        // CHECK_HANDLE(handle, return -1);
        if cfg!(HAVE_LIBGPGME) {
            self.localfilesiglevel = level;
        } else if
        /*level != 0 &&*/
        level.use_default {
            // RET_ERR!(self, ALPM_ERR_WRONG_ARGS, -1);
            return Err(Error::ALPM_ERR_WRONG_ARGS);
        }

        return Ok(0);
    }

    pub fn alpm_option_get_local_file_siglevel(&self) -> SigLevel {
        // CHECK_HANDLE(handle, return -1);
        if self.localfilesiglevel.use_default {
            return self.siglevel;
        } else {
            return self.localfilesiglevel;
        }
    }

    pub fn alpm_option_set_remote_file_siglevel(&mut self, level: SigLevel) {
        // unimplemented!();
        // #ifdef HAVE_LIBGPGME
        self.remotefilesiglevel = level;
        // #else
        // 	if(level != 0 && level != ALPM_SIG_USE_DEFAULT) {
        // 		RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1);
        // 	}
        // #endif
        // 	return 0;
    }

    pub fn alpm_option_get_remote_file_siglevel(&self) -> SigLevel {
        // CHECK_HANDLE(handle, return -1);
        if self.remotefilesiglevel.use_default {
            return self.siglevel;
        } else {
            return self.remotefilesiglevel;
        }
    }

    pub fn alpm_option_set_disable_dl_timeout(&mut self, disable_dl_timeout: u16) -> i32 {
        // 	CHECK_HANDLE(handle, return -1);
        if cfg!(HAVE_LIBCURL) {
            self.disable_dl_timeout = disable_dl_timeout;
        }
        return 0;
    }

    pub fn _alpm_handle_new() -> Handle {
        let mut handle = Handle::default();
        handle.deltaratio = 0.0;
        handle.lockfd = None;

        return handle;
    }

    /// Lock the database
    pub fn _alpm_handle_lock(&mut self) -> std::io::Result<()> {
        assert!(self.lockfile != "");
        assert!(self.lockfd.is_none());

        /* create the dir of the lockfile first */
        match File::create(&self.lockfile) {
            Ok(f) => self.lockfd = Some(f),
            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// Remove the database lock file
    pub fn alpm_unlock(&mut self) -> std::io::Result<()> {
        // ASSERT(handle->lockfile != NULL, return 0);
        // ASSERT(handle->lockfd >= 0, return 0);

        // handle.lockfd.close();
        self.lockfd = None;

        if std::fs::remove_file(&self.lockfile).is_err() {
            unimplemented!();
            // RET_ERR_ASYNC_SAFE(handle, ALPM_ERR_SYSTEM, -1);
        }
        return Ok(());
    }

    pub fn _alpm_handle_unlock(&mut self) -> std::io::Result<()> {
        match self.alpm_unlock() {
            Err(e) => {
                eprintln!("{}", e);
                return Err(e);
                // if(errno == ENOENT) {
                // 	_alpm_log(handle, ALPM_LOG_WARNING,
                // 			_("lock file missing %s\n"), handle->lockfile);
                // 	alpm_logaction(handle, ALPM_CALLER_PREFIX,
                // 			"warning: lock file missing %s\n", handle->lockfile);
                // 	return 0;
                // } else {
                // 	_alpm_log(handle, ALPM_LOG_WARNING,
                // 			_("could not remove lock file %s\n"), handle->lockfile);
                // 	alpm_logaction(handle, ALPM_CALLER_PREFIX,
                // 			"warning: could not remove lock file %s\n", handle->lockfile);
                // 	return -1;
                // }
            }
            _ => {}
        }

        return Ok(());
    }

    /**
     * @brief Transaction preparation for remove actions.
     *
     * This functions takes a pointer to a alpm_list_t which will be
     * filled with a list of depmissing_t* objects representing
     * the packages blocking the transaction.
     *
     * @param handle the context handle
     * @param data a pointer to an alpm_list_t* to fill
     *
     * @return 0 on success, -1 on error
     */
    fn _alpm_remove_prepare(&self, data: &Vec<String>) -> i32 {
        unimplemented!();
        // 	alpm_list_t *lp;
        // 	alpm_trans_t *trans = handle->trans;
        // 	Database *db = handle->db_local;
        // 	alpm_event_t event;
        //
        // 	if((trans->flags & ALPM_TRANS_FLAG_RECURSE)
        // 			&& !(trans->flags & ALPM_TRANS_FLAG_CASCADE)) {
        // 		_alpm_log(handle, ALPM_LOG_DEBUG, "finding removable dependencies\n");
        // 		if(_alpm_recursedeps(db, &trans->remove,
        // 				trans->flags & ALPM_TRANS_FLAG_RECURSEALL)) {
        // 			return -1;
        // 		}
        // 	}
        //
        // 	if(!(trans->flags & ALPM_TRANS_FLAG_NODEPS)) {
        // 		event.type = ALPM_EVENT_CHECKDEPS_START;
        // 		EVENT(handle, &event);
        //
        // 		_alpm_log(handle, ALPM_LOG_DEBUG, "looking for unsatisfied dependencies\n");
        // 		lp = alpm_checkdeps(handle, _alpm_db_get_pkgcache(db), trans->remove, NULL, 1);
        // 		if(lp != NULL) {
        //
        // 			if(trans->flags & ALPM_TRANS_FLAG_CASCADE) {
        // 				if(remove_prepare_cascade(handle, lp)) {
        // 					return -1;
        // 				}
        // 			} else if(trans->flags & ALPM_TRANS_FLAG_UNNEEDED) {
        // 				/* Remove needed packages (which would break dependencies)
        // 				 * from target list */
        // 				remove_prepare_keep_needed(handle, lp);
        // 			} else {
        // 				if(data) {
        // 					*data = lp;
        // 				} else {
        // 					alpm_list_free_inner(lp,
        // 							(alpm_list_fn_free)alpm_depmissing_free);
        // 					alpm_list_free(lp);
        // 				}
        // 				RET_ERR(handle, ALPM_ERR_UNSATISFIED_DEPS, -1);
        // 			}
        // 		}
        // 	}
        //
        // 	/* -Rcs == -Rc then -Rs */
        // 	if((trans->flags & ALPM_TRANS_FLAG_CASCADE)
        // 			&& (trans->flags & ALPM_TRANS_FLAG_RECURSE)) {
        // 		_alpm_log(handle, ALPM_LOG_DEBUG, "finding removable dependencies\n");
        // 		if(_alpm_recursedeps(db, &trans->remove,
        // 					trans->flags & ALPM_TRANS_FLAG_RECURSEALL)) {
        // 			return -1;
        // 		}
        // 	}
        //
        // 	/* Note packages being removed that are optdepends for installed packages */
        // 	if(!(trans->flags & ALPM_TRANS_FLAG_NODEPS)) {
        // 		remove_notify_needed_optdepends(handle, trans->remove);
        // 	}
        //
        // 	if(!(trans->flags & ALPM_TRANS_FLAG_NODEPS)) {
        // 		event.type = ALPM_EVENT_CHECKDEPS_DONE;
        // 		EVENT(handle, &event);
        // 	}
        //
        // 	return 0;
    }

    fn _alpm_sync_prepare(&self, data: &Vec<String>) -> i32 {
        // 	alpm_list_t *i, *j;
        // 	alpm_list_t *deps = NULL;
        // 	alpm_list_t *unresolvable = NULL;
        let mut from_sync = false;
        let ret = 0;
        let trans = &self.trans;
        // 	alpm_event_t event;

        // 	if(data) {
        // 		*data = NULL;
        // 	}

        for spkg in &trans.add {
            match spkg.origin {
                PackageFrom::ALPM_PKG_FROM_SYNCDB => {
                    from_sync = true;
                    break;
                }
                _ => {}
            }
        }

        /* ensure all sync database are valid if we will be using them */
        for db in &self.dbs_sync {
            if db.status.invalid {
                unimplemented!();
                // RET_ERR(handle, ALPM_ERR_DB_INVALID, -1);
            }
            /* missing databases are not allowed if we have sync targets */
            if from_sync && db.status.missing {
                unimplemented!();
                // RET_ERR(handle, ALPM_ERR_DB_NOT_FOUND, -1);
            }
        }

        if !trans.flags.no_deps {
            unimplemented!();
            // 		alpm_list_t *resolved = NULL;
            // 		alpm_list_t *remove = alpm_list_copy(trans.remove);
            // 		alpm_list_t *localpkgs;
            //
            // 		/* Build up list by repeatedly resolving each transaction package */
            // 		/* Resolve targets dependencies */
            // 		event.type = ALPM_EVENT_RESOLVEDEPS_START;
            // 		EVENT(handle, &event);
            // 		debug!("resolving target's dependencies\n");
            //
            // 		/* build remove list for resolvedeps */
            // 		for(i = trans.add; i; i = i.next) {
            // 			Package *spkg = i.data;
            // 			for(j = spkg.removes; j; j = j.next) {
            // 				remove = alpm_list_add(remove, j->data);
            // 			}
            // 		}
            //
            // 		/* Compute the fake local database for resolvedeps (partial fix for the
            // 		 * phonon/qt issue) */
            // 		localpkgs = alpm_list_diff(_alpm_db_get_pkgcache(handle->db_local),
            // 				trans->add, _alpm_pkg_cmp);
            //
            // 		/* Resolve packages in the transaction one at a time, in addition
            // 		   building up a list of packages which could not be resolved. */
            // 		for(i = trans->add; i; i = i->next) {
            // 			Package *pkg = i->data;
            // 			if(_alpm_resolvedeps(handle, localpkgs, pkg, trans->add,
            // 						&resolved, remove, data) == -1) {
            // 				unresolvable = alpm_list_add(unresolvable, pkg);
            // 			}
            // 			/* Else, [resolved] now additionally contains [pkg] and all of its
            // 			   dependencies not already on the list */
            // 		}
            // 		alpm_list_free(localpkgs);
            // 		alpm_list_free(remove);
            //
            // 		/* If there were unresolvable top-level packages, prompt the user to
            // 		   see if they'd like to ignore them rather than failing the sync */
            // 		if(unresolvable != NULL) {
            // 			alpm_question_remove_pkgs_t question = {
            // 				.type = ALPM_QUESTION_REMOVE_PKGS,
            // 				.skip = 0,
            // 				.packages = unresolvable
            // 			};
            // 			QUESTION(handle, &question);
            // 			if(question.skip) {
            // 				/* User wants to remove the unresolvable packages from the
            // 				   transaction. The packages will be removed from the actual
            // 				   transaction when the transaction packages are replaced with a
            // 				   dependency-reordered list below */
            // 				handle->pm_errno = ALPM_ERR_OK;
            // 				if(data) {
            // 					alpm_list_free_inner(*data,
            // 							(alpm_list_fn_free)alpm_depmissing_free);
            // 					alpm_list_free(*data);
            // 					*data = NULL;
            // 				}
            // 			} else {
            // 				/* pm_errno was set by resolvedeps, callback may have overwrote it */
            // 				handle->pm_errno = ALPM_ERR_UNSATISFIED_DEPS;
            // 				alpm_list_free(resolved);
            // 				alpm_list_free(unresolvable);
            // 				ret = -1;
            // 				goto cleanup;
            // 			}
            // 		}
            //
            // 		/* Set DEPEND reason for pulled packages */
            // 		for(i = resolved; i; i = i->next) {
            // 			Package *pkg = i->data;
            // 			if(!alpm_pkg_find(trans->add, pkg->name)) {
            // 				pkg->reason = ALPM_PKG_REASON_DEPEND;
            // 			}
            // 		}
            //
            // 		/* Unresolvable packages will be removed from the target list; set these
            // 		 * aside in the transaction as a list we won't operate on. If we free them
            // 		 * before the end of the transaction, we may kill pointers the frontend
            // 		 * holds to package objects. */
            // 		trans->unresolvable = unresolvable;
            //
            // 		alpm_list_free(trans->add);
            // 		trans->add = resolved;
            //
            // 		event.type = ALPM_EVENT_RESOLVEDEPS_DONE;
            // 		EVENT(handle, &event);
        }

        if !trans.flags.no_conflicts {
            unimplemented!();
            // 		/* check for inter-conflicts and whatnot */
            // 		event.type = ALPM_EVENT_INTERCONFLICTS_START;
            // 		EVENT(handle, &event);
            //
            // 		debug!("looking for conflicts\n");
            //
            // 		/* 1. check for conflicts in the target list */
            // 		debug!("check targets vs targets\n");
            // 		deps = _alpm_innerconflicts(handle, trans->add);
            //
            // 		for(i = deps; i; i = i->next) {
            // 			conflict_t *conflict = i->data;
            // 			Package *rsync, *sync, *sync1, *sync2;
            //
            // 			/* have we already removed one of the conflicting targets? */
            // 			sync1 = alpm_pkg_find(trans->add, conflict->package1);
            // 			sync2 = alpm_pkg_find(trans->add, conflict->package2);
            // 			if(!sync1 || !sync2) {
            // 				continue;
            // 			}
            //
            // 			debug!("conflicting packages in the sync list: '{}' <-> '{}'\n",
            // 					conflict->package1, conflict->package2);
            //
            // 			/* if sync1 provides sync2, we remove sync2 from the targets, and vice versa */
            // 			alpm_Dependency *dep1 = alpm_dep_from_string(conflict->package1);
            // 			alpm_Dependency *dep2 = alpm_dep_from_string(conflict->package2);
            // 			if(_alpm_depcmp(sync1, dep2)) {
            // 				rsync = sync2;
            // 				sync = sync1;
            // 			} else if(_alpm_depcmp(sync2, dep1)) {
            // 				rsync = sync1;
            // 				sync = sync2;
            // 			} else {
            // 				_alpm_log(handle, ALPM_LOG_ERROR, _("unresolvable package conflicts detected\n"));
            // 				handle->pm_errno = ALPM_ERR_CONFLICTING_DEPS;
            // 				ret = -1;
            // 				if(data) {
            // 					conflict_t *newconflict = _alpm_conflict_dup(conflict);
            // 					if(newconflict) {
            // 						*data = alpm_list_add(*data, newconflict);
            // 					}
            // 				}
            // 				alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
            // 				alpm_list_free(deps);
            // 				alpm_dep_free(dep1);
            // 				alpm_dep_free(dep2);
            // 				goto cleanup;
            // 			}
            // 			alpm_dep_free(dep1);
            // 			alpm_dep_free(dep2);
            //
            // 			/* Prints warning */
            // 			_alpm_log(handle, ALPM_LOG_WARNING,
            // 					_("removing '{}' from target list because it conflicts with '{}'\n"),
            // 					rsync->name, sync->name);
            // 			trans->add = alpm_list_remove(trans->add, rsync, _alpm_pkg_cmp, NULL);
            // 			/* rsync is not a transaction target anymore */
            // 			trans->unresolvable = alpm_list_add(trans->unresolvable, rsync);
            // 		}
            //
            // 		alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
            // 		alpm_list_free(deps);
            // 		deps = NULL;
            //
            // 		/* 2. we check for target vs db conflicts (and resolve)*/
            // 		debug!("check targets vs db and db vs targets\n");
            // 		deps = _alpm_outerconflicts(handle->db_local, trans->add);
            //
            // 		for(i = deps; i; i = i->next) {
            // 			alpm_question_conflict_t question = {
            // 				.type = ALPM_QUESTION_CONFLICT_PKG,
            // 				.remove = 0,
            // 				.conflict = i->data
            // 			};
            // 			conflict_t *conflict = i->data;
            // 			int found = 0;
            //
            // 			/* if conflict->package2 (the local package) is not elected for removal,
            // 			   we ask the user */
            // 			if(alpm_pkg_find(trans->remove, conflict->package2)) {
            // 				found = 1;
            // 			}
            // 			for(j = trans->add; j && !found; j = j->next) {
            // 				Package *spkg = j->data;
            // 				if(alpm_pkg_find(spkg->removes, conflict->package2)) {
            // 					found = 1;
            // 				}
            // 			}
            // 			if(found) {
            // 				continue;
            // 			}
            //
            // 			debug!("package '{}' conflicts with '{}'\n",
            // 					conflict->package1, conflict->package2);
            //
            // 			QUESTION(handle, &question);
            // 			if(question.remove) {
            // 				/* append to the removes list */
            // 				Package *sync = alpm_pkg_find(trans->add, conflict->package1);
            // 				Package *local = _alpm_db_get_pkgfromcache(handle->db_local, conflict->package2);
            // 				debug!("electing '{}' for removal\n", conflict->package2);
            // 				sync->removes = alpm_list_add(sync->removes, local);
            // 			} else { /* abort */
            // 				_alpm_log(handle, ALPM_LOG_ERROR, _("unresolvable package conflicts detected\n"));
            // 				handle->pm_errno = ALPM_ERR_CONFLICTING_DEPS;
            // 				ret = -1;
            // 				if(data) {
            // 					conflict_t *newconflict = _alpm_conflict_dup(conflict);
            // 					if(newconflict) {
            // 						*data = alpm_list_add(*data, newconflict);
            // 					}
            // 				}
            // 				alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
            // 				alpm_list_free(deps);
            // 				goto cleanup;
            // 			}
            // 		}
            // 		event.type = ALPM_EVENT_INTERCONFLICTS_DONE;
            // 		EVENT(handle, &event);
            // 		alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
            // 		alpm_list_free(deps);
        }

        /* Build trans->remove list */
        // 	for(i = trans->add; i; i = i->next) {
        // 		Package *spkg = i->data;
        // 		for(j = spkg->removes; j; j = j->next) {
        // 			Package *rpkg = j->data;
        // 			if(!alpm_pkg_find(trans->remove, rpkg->name)) {
        // 				Package *copy;
        // 				debug!("adding '{}' to remove list\n", rpkg->name);
        // 				if(_alpm_pkg_dup(rpkg, &copy) == -1) {
        // 					return -1;
        // 				}
        // 				trans->remove = alpm_list_add(trans->remove, copy);
        // 			}
        // 		}
        // 	}

        if !trans.flags.no_deps {
            debug!("checking dependencies");
            unimplemented!();
            // 		deps = alpm_checkdeps(handle, _alpm_db_get_pkgcache(handle->db_local),
            // 				trans->remove, trans->add, 1);
            // 		if(deps) {
            // 			handle->pm_errno = ALPM_ERR_UNSATISFIED_DEPS;
            // 			ret = -1;
            // 			if(data) {
            // 				*data = deps;
            // 			} else {
            // 				alpm_list_free_inner(deps,
            // 						(alpm_list_fn_free)alpm_depmissing_free);
            // 				alpm_list_free(deps);
            // 			}
            // 			goto cleanup;
            // 		}
        }

        for spkg in &trans.add {
            /* update download size field */
            let lpkg = self.db_local.alpm_db_get_pkg(&spkg.name);
            if spkg.compute_download_size() < 0 {
                return -1;
            }
            match lpkg {
                Some(lpkg) => {
                    unimplemented!();
                    // spkg.oldpkg = match lpkg._alpm_pkg_dup() {
                    //     Some(pkg) => pkg,
                    //     None => return -1,
                    // };
                }
                None => {}
            }
        }

        // cleanup:
        ret
    }
}

pub fn canonicalize_path(path: &String) -> String {
    let mut new_path = path.clone();
    /* verify path ends in a '/' */
    if !path.ends_with('/') {
        new_path.push('/');
    }
    return new_path;
}

pub fn _alpm_set_directory_option(
    value: &String,
    storage: &mut String,
    must_exist: bool,
) -> Result<()> {
    let mut path = value.clone();

    if must_exist {
        match std::fs::metadata(&path) {
            Ok(ref f) if f.is_dir() => {}
            _ => return Err(Error::ALPM_ERR_NOT_A_DIR),
        }
        match std::fs::canonicalize(&path) {
            Ok(p) => {
                *storage = p.into_os_string().into_string().unwrap();
            }
            Err(_) => return Err(Error::ALPM_ERR_NOT_A_DIR),
        }
    } else {
        *storage = canonicalize_path(&path);
    }
    return Ok(());
}

// #ifdef HAVE_LIBCURL
// #include <curl/curl.h>
// #endif

// #define EVENT(h, e) \
// do { \
// 	if((h)->eventcb) { \
// 		(h)->eventcb((alpm_event_t *) (e)); \
// 	} \
// } while(0)

// #define QUESTION(h, q) \
// do { \
// 	if((h)->questioncb) { \
// 		(h)->questioncb((alpm_question_t *) (q)); \
// 	} \
// } while(0)

// #define PROGRESS(h, e, p, per, n, r) \
// do { \
// 	if((h)->progresscb) { \
// 		(h)->progresscb(e, p, per, n, r); \
// 	} \
// } while(0)

#[derive(Default, Debug)]
pub struct Handle {
    // 	/* internal usage */
    pub db_local: Database,      //// local db pointer */
    pub dbs_sync: Vec<Database>, /* List of (Database *) */
    // 	FILE *logstream;        /* log file stream pointer */
    pub trans: Transaction,
    //
    // #ifdef HAVE_LIBCURL
    // 	/* libcurl handle */
    // 	CURL *curl;             /* reusable curl_easy handle */
    disable_dl_timeout: u16,
    // #endif
    //
    // #ifdef HAVE_LIBGPGME
    // 	alpm_list_t *known_keys;  /* keys verified to be in our keychain */
    // #endif
    //
    // 	/* callback functions */
    // 	alpm_cb_log logcb;          /* Log callback function */
    // 	alpm_cb_download dlcb;      /* Download callback function */
    // 	alpm_cb_totaldl totaldlcb;  /* Total download callback function */
    // fetchcb: alpm_cb_fetch, /* Download file callback function */
    // 	alpm_cb_event eventcb;
    // 	alpm_cb_question questioncb;
    // 	alpm_cb_progress progresscb;

    	/* filesystem paths */
    pub root: String,             /* Root path, default '/' */
    pub dbpath: String,           /* Base path to pacman's DBs */
    logfile: String,              /* Name of the log file */
    pub lockfile: String,         /* Name of the lock file */
    gpgdir: String,               /* Directory where GnuPG files are stored */
    cachedirs: Vec<String>,       /* Paths to pacman cache directories */
    pub hookdirs: Vec<String>,    /* Paths to hook directories */
    overwrite_files: Vec<String>, /* Paths that may be overwritten */

    /* package lists */
    /// List of packages NOT to be upgraded */
    noupgrade: Vec<String>,
    /// List of files NOT to extract */
    noextract: Vec<String>,
    /// List of packages to ignore */
    ignorepkg: Vec<String>,
    /// List of groups to ignore */
    ignoregroup: Vec<String>,
    ///List of virtual packages used to satisfy dependencies
    assumeinstalled: Vec<Dependency>,

    /* options */
    /// Architecture of packages we should allow */
    arch: String,
    deltaratio: f64,
    /// Download deltas if possible; a ratio value */
    usesyslog: i32, /* Use syslog instead of logfile? */
    /* TODO move to frontend */
    checkspace: i32,    /* Check disk space before installing */
    pub dbext: String,  /* Sync DB extension */
    siglevel: SigLevel, /* Default signature verification level */
    localfilesiglevel: SigLevel, /* Signature verification level for local file
                        // 	                                       upgrade operations */
    remotefilesiglevel: SigLevel, /* Signature verification level for remote file
                                  // 	                                       upgrade operations */
    //
    // 	/* error code */
    // pub pm_errno: Error,

    /* lock file descriptor */
    lockfd: Option<File>,
    //
    // 	/* for delta parsing efficiency */
    // 	int delta_regex_compiled;
    // 	regex_t delta_regex;
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        Handle {
            db_local: self.db_local.clone(),
            dbs_sync: self.dbs_sync.clone(),
            // 	FILE *logstream;
            trans: self.trans.clone(),
            // 	CURL *curl;             /* reusable curl_easy handle */
            disable_dl_timeout: self.disable_dl_timeout,
            // #endif
            //
            // #ifdef HAVE_LIBGPGME
            // 	alpm_list_t *known_keys;  /* keys verified to be in our keychain */
            // #endif
            //
            // 	/* callback functions */
            // 	alpm_cb_log logcb;          /* Log callback function */
            // 	alpm_cb_download dlcb;      /* Download callback function */
            // 	alpm_cb_totaldl totaldlcb;  /* Total download callback function */
            // fetchcb: alpm_cb_fetch, /* Download file callback function */
            // 	alpm_cb_event eventcb;
            // 	alpm_cb_question questioncb;
            // 	alpm_cb_progress progresscb;
            //
            // 	/* filesystem paths */
            root: self.root.clone(),
            dbpath: self.dbpath.clone(),
            logfile: self.logfile.clone(),
            lockfile: self.lockfile.clone(),
            gpgdir: self.gpgdir.clone(),
            cachedirs: self.cachedirs.clone(),
            hookdirs: self.hookdirs.clone(),
            overwrite_files: self.overwrite_files.clone(),
            noupgrade: self.noupgrade.clone(),
            noextract: self.noextract.clone(),
            ignorepkg: self.ignorepkg.clone(),
            ignoregroup: self.ignoregroup.clone(),
            assumeinstalled: self.assumeinstalled.clone(),
            arch: self.arch.clone(),
            deltaratio: self.deltaratio,
            usesyslog: self.usesyslog,
            checkspace: self.checkspace,
            dbext: self.dbext.clone(),
            siglevel: self.siglevel,
            localfilesiglevel: self.localfilesiglevel,
            remotefilesiglevel: self.remotefilesiglevel,
            // pub pm_errno: Error,
            lockfd: None,
            // 	int delta_regex_compiled;
            // 	regex_t delta_regex;
        }
    }
}
