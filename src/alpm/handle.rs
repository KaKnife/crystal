// #[macro_use]
// mod util;
use super::*;
use std;
// use std::error::Error;
use std::fs::File;
// use std::io::Result;
use std::ffi::OsString;
use self::alpm_errno_t::*;
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

// alpm_cb_log SYMEXPORT alpm_option_get_logcb(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->logcb;
// }
//
// alpm_cb_download SYMEXPORT alpm_option_get_dlcb(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->dlcb;
// }
//
// alpm_cb_fetch SYMEXPORT alpm_option_get_fetchcb(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->fetchcb;
// }
// alpm_cb_totaldl SYMEXPORT alpm_option_get_totaldlcb(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->totaldlcb;
// }
//
// alpm_cb_event SYMEXPORT alpm_option_get_eventcb(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->eventcb;
// }
//
// alpm_cb_question SYMEXPORT alpm_option_get_questioncb(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->questioncb;
// }
//
// alpm_cb_progress SYMEXPORT alpm_option_get_progresscb(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->progresscb;
// }

// #[derive(Default, Debug)]
///TODO: Implement this
pub type alpm_list_t<T> = Vec<T>;

impl alpm_handle_t {
    pub fn alpm_option_get_root(&self) -> String {
        return self.root.clone();
    }

    pub fn alpm_option_get_hookdirs(&self) -> Vec<String> {
        self.hookdirs.clone()
    }

    pub fn alpm_option_get_dbpath(&self) -> &String {
        // unimplemented!();
        // CHECK_HANDLE(handle, return NULL);
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

    // int SYMEXPORT alpm_option_get_usesyslog(alpm_handle_t *handle)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	return handle->usesyslog;
    // }
    //
    // alpm_list_t SYMEXPORT *alpm_option_get_noupgrades(alpm_handle_t *handle)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->noupgrade;
    // }
    //
    // alpm_list_t SYMEXPORT *alpm_option_get_noextracts(alpm_handle_t *handle)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->noextract;
    // }
    //
    // alpm_list_t SYMEXPORT *alpm_option_get_ignorepkgs(alpm_handle_t *handle)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->ignorepkg;
    // }
    //
    // alpm_list_t SYMEXPORT *alpm_option_get_ignoregroups(alpm_handle_t *handle)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->ignoregroup;
    // }
    //
    // alpm_list_t SYMEXPORT *alpm_option_get_overwrite_files(alpm_handle_t *handle)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->overwrite_files;
    // }
    //
    // alpm_list_t SYMEXPORT *alpm_option_get_assumeinstalled(alpm_handle_t *handle)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->assumeinstalled;
    // }
    //
    // const char SYMEXPORT *alpm_option_get_arch(alpm_handle_t *handle)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->arch;
    // }
    //
    // double SYMEXPORT alpm_option_get_deltaratio(alpm_handle_t *handle)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	return handle->deltaratio;
    // }

    // int SYMEXPORT alpm_option_get_checkspace(alpm_handle_t *handle)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	return handle->checkspace;
    // }
    //
    // const char SYMEXPORT *alpm_option_get_dbext(alpm_handle_t *handle)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->dbext;
    // }
    //
    // pub fn alpm_option_set_logcb(&mut self,  cb: alpm_cb_log)
    // {
    // 	self.logcb = cb;
    // }
    //
    // int SYMEXPORT alpm_option_set_dlcb(alpm_handle_t *handle, alpm_cb_download cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->dlcb = cb;
    // 	return 0;
    // }

    // fn alpm_option_set_fetchcb(&mut self, cb: alpm_cb_fetch) {
    //     self.fetchcb = cb;
    // }

    // int SYMEXPORT alpm_option_set_totaldlcb(alpm_handle_t *handle, alpm_cb_totaldl cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->totaldlcb = cb;
    // 	return 0;
    // }
    //
    // int SYMEXPORT alpm_option_set_eventcb(alpm_handle_t *handle, alpm_cb_event cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->eventcb = cb;
    // 	return 0;
    // }

    // int SYMEXPORT alpm_option_set_questioncb(alpm_handle_t *handle, alpm_cb_question cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->questioncb = cb;
    // 	return 0;
    // }

    // int SYMEXPORT alpm_option_set_progresscb(alpm_handle_t *handle, alpm_cb_progress cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->progresscb = cb;
    // 	return 0;
    // }

    pub fn alpm_option_add_hookdir(&mut self, hookdir: &String) -> Result<i32> {
        // 	char *newhookdir;
        let newhookdir = match std::fs::canonicalize(hookdir) {
            Err(_) => {
                return Err(ALPM_ERR_MEMORY);
            }
            Ok(h) => h,
        };
        self.hookdirs
            .push(newhookdir.into_os_string().into_string().unwrap());
        // 	_alpm_log(handle, ALPM_LOG_DEBUG, "option 'hookdir' = %s\n", newhookdir);
        return Ok(0);
    }

    // int SYMEXPORT alpm_option_set_hookdirs(alpm_handle_t *handle, alpm_list_t *hookdirs)
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
    // int SYMEXPORT alpm_option_remove_hookdir(alpm_handle_t *handle, const char *hookdir)
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
                return Err(ALPM_ERR_MEMORY);
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

    // int SYMEXPORT alpm_option_remove_cachedir(alpm_handle_t *handle, const char *cachedir)
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
            return Err(ALPM_ERR_WRONG_ARGS);
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

    // static int _alpm_option_strlist_add(alpm_handle_t *handle, alpm_list_t **list, const char *str)
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

    // static int _alpm_option_strlist_rem(alpm_handle_t *handle, alpm_list_t **list, const char *str)
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
    // int SYMEXPORT alpm_option_add_noupgrade(alpm_handle_t *handle, const char *pkg)
    // {
    // 	return _alpm_option_strlist_add(handle, &(handle->noupgrade), pkg);
    // }

    pub fn alpm_option_set_noupgrades(&mut self, noupgrade: &Vec<String>) {
        self.noupgrade = noupgrade.clone()
    }

    // int SYMEXPORT alpm_option_remove_noupgrade(alpm_handle_t *handle, const char *pkg)
    // {
    // 	return _alpm_option_strlist_rem(handle, &(handle->noupgrade), pkg);
    // }
    //
    // int SYMEXPORT alpm_option_match_noupgrade(alpm_handle_t *handle, const char *path)
    // {
    // 	return _alpm_fnmatch_patterns(handle->noupgrade, path);
    // }
    //
    // int SYMEXPORT alpm_option_add_noextract(alpm_handle_t *handle, const char *path)
    // {
    // 	return _alpm_option_strlist_add(handle, &(handle->noextract), path);
    // }

    pub fn alpm_option_set_noextracts(&mut self, noextract: &Vec<String>) {
        self.noextract = noextract.clone();
    }

    // int SYMEXPORT alpm_option_remove_noextract(alpm_handle_t *handle, const char *path)
    // {
    // 	return _alpm_option_strlist_rem(handle, &(handle->noextract), path);
    // }
    //
    // int SYMEXPORT alpm_option_match_noextract(alpm_handle_t *handle, const char *path)
    // {
    // 	return _alpm_fnmatch_patterns(handle->noextract, path);
    // }
    //
    // int SYMEXPORT alpm_option_add_ignorepkg(alpm_handle_t *handle, const char *pkg)
    // {
    // 	return _alpm_option_strlist_add(handle, &(handle->ignorepkg), pkg);
    // }

    pub fn alpm_option_set_ignorepkgs(&mut self, ignorepkgs: &Vec<String>) {
        self.ignorepkg = ignorepkgs.clone();
    }

    // int SYMEXPORT alpm_option_remove_ignorepkg(alpm_handle_t *handle, const char *pkg)
    // {
    // 	return _alpm_option_strlist_rem(handle, &(handle->ignorepkg), pkg);
    // }
    //
    // int SYMEXPORT alpm_option_add_ignoregroup(alpm_handle_t *handle, const char *grp)
    // {
    // 	return _alpm_option_strlist_add(handle, &(handle->ignoregroup), grp);
    // }

    pub fn alpm_option_set_ignoregroups(&mut self, ignoregrps: &Vec<String>) {
        self.ignoregroup = ignoregrps.clone();
    }

    // int SYMEXPORT alpm_option_remove_ignoregroup(alpm_handle_t *handle, const char *grp)
    // {
    // 	return _alpm_option_strlist_rem(handle, &(handle->ignoregroup), grp);
    // }
    //
    // int SYMEXPORT alpm_option_add_overwrite_file(alpm_handle_t *handle, const char *glob)
    // {
    // 	return _alpm_option_strlist_add(handle, &(handle->overwrite_files), glob);
    // }

    pub fn alpm_option_set_overwrite_files(&mut self, globs: &Vec<String>) {
        self.overwrite_files = globs.clone();
    }

    // int SYMEXPORT alpm_option_remove_overwrite_file(alpm_handle_t *handle, const char *glob)
    // {
    // 	return _alpm_option_strlist_rem(handle, &(handle->overwrite_files), glob);
    // }

    pub fn alpm_option_add_assumeinstalled(&mut self, dep: &alpm_depend_t) {
        use std::hash::{Hash, Hasher};
        let mut depcpy = alpm_depend_t::default();
        let mut hasher = sdbm_hasher::default();
        /* fill in name_hash in case dep was built by hand */
        dep.name.hash(&mut hasher);
        depcpy.name_hash = hasher.finish();
        self.assumeinstalled.push(depcpy);
    }

    // int SYMEXPORT alpm_option_set_assumeinstalled(alpm_handle_t *handle, alpm_list_t *deps)
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
    // 	const alpm_depend_t *dep1 = d1;
    // 	const alpm_depend_t *dep2 = d2;
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

    pub fn alpm_option_remove_assumeinstalled(&self, dep: &alpm_depend_t) -> i32 {
        unimplemented!();
        // alpm_depend_t *vdata = NULL;

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
            return Err(ALPM_ERR_WRONG_ARGS);
        }
        self.deltaratio = ratio;
        Ok(())
    }

    pub fn alpm_get_localdb(&self) -> &alpm_db_t {
        return &self.db_local;
    }

    pub fn alpm_get_localdb_mut(&mut self) -> &mut alpm_db_t {
        return &mut self.db_local;
    }

    pub fn alpm_get_syncdbs(&self) -> &Vec<alpm_db_t> {
        return &self.dbs_sync;
    }

    pub fn alpm_option_set_checkspace(&mut self, checkspace: i32) {
        self.checkspace = checkspace;
    }

    pub fn alpm_option_set_dbext(&mut self, dbext: &String) {
        self.dbext = dbext.clone();

        // _alpm_log(handle, ALPM_LOG_DEBUG, "option 'dbext' = %s\n", handle->dbext);
    }

    pub fn alpm_option_set_default_siglevel(&mut self, level: &siglevel) -> i32 {
        // #ifdef HAVE_LIBGPGME
        self.siglevel = level.clone();
        // #else
        // 	if(level != 0 && level != ALPM_SIG_USE_DEFAULT) {
        // 		RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1);
        // 	}
        // #endif
        return 0;
    }

    fn alpm_option_get_default_siglevel(&self) -> siglevel {
        // CHECK_HANDLE(handle, return -1);
        return self.siglevel;
    }

    pub fn alpm_option_set_local_file_siglevel(&mut self, level: siglevel) -> Result<i32> {
        // CHECK_HANDLE(handle, return -1);
        if cfg!(HAVE_LIBGPGME) {
            self.localfilesiglevel = level;
        } else if
        /*level != 0 &&*/
        level.ALPM_SIG_USE_DEFAULT {
            // RET_ERR!(self, ALPM_ERR_WRONG_ARGS, -1);
            return Err(ALPM_ERR_WRONG_ARGS);
        }

        return Ok(0);
    }

    pub fn alpm_option_get_local_file_siglevel(&self) -> siglevel {
        // CHECK_HANDLE(handle, return -1);
        if self.localfilesiglevel.ALPM_SIG_USE_DEFAULT {
            return self.siglevel;
        } else {
            return self.localfilesiglevel;
        }
    }

    pub fn alpm_option_set_remote_file_siglevel(&mut self, level: siglevel) {
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

    pub fn alpm_option_get_remote_file_siglevel(&self) -> siglevel {
        // CHECK_HANDLE(handle, return -1);
        if self.remotefilesiglevel.ALPM_SIG_USE_DEFAULT {
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

    pub fn _alpm_handle_new() -> alpm_handle_t {
        let mut handle = alpm_handle_t::default();
        handle.deltaratio = 0.0;
        handle.lockfd = None;

        return handle;
    }

    // void _alpm_handle_free(alpm_handle_t *handle)
    // {
    // 	if(handle == NULL) {
    // 		return;
    // 	}
    //
    // 	/* close logfile */
    // 	if(handle->logstream) {
    // 		fclose(handle->logstream);
    // 		handle->logstream = NULL;
    // 	}
    // 	if(handle->usesyslog) {
    // 		handle->usesyslog = 0;
    // 		closelog();
    // 	}
    //
    // #ifdef HAVE_LIBCURL
    // 	/* release curl handle */
    // 	curl_easy_cleanup(handle->curl);
    // #endif
    //
    // #ifdef HAVE_LIBGPGME
    // 	FREELIST(handle->known_keys);
    // #endif
    //
    // 	regfree(&handle->delta_regex);
    //
    // 	/* free memory */
    // 	_alpm_trans_free(handle->trans);
    // 	FREE(handle->root);
    // 	FREE(handle->dbpath);
    // 	FREE(handle->dbext);
    // 	FREELIST(handle->cachedirs);
    // 	FREELIST(handle->hookdirs);
    // 	FREE(handle->logfile);
    // 	FREE(handle->lockfile);
    // 	FREE(handle->arch);
    // 	FREE(handle->gpgdir);
    // 	FREELIST(handle->noupgrade);
    // 	FREELIST(handle->noextract);
    // 	FREELIST(handle->ignorepkg);
    // 	FREELIST(handle->ignoregroup);
    // 	FREELIST(handle->overwrite_files);
    //
    // 	alpm_list_free_inner(handle->assumeinstalled, (alpm_list_fn_free)alpm_dep_free);
    // 	alpm_list_free(handle->assumeinstalled);
    //
    // 	FREE(handle);
    // }

    /** Lock the database */
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

    /** Remove the database lock file
     * @param handle the context handle
     * @return 0 on success, -1 on error
     *
     * @note Safe to call from inside signal handlers.
     */
    fn alpm_unlock(&mut self) -> std::io::Result<()> {
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
            _ => return Err(ALPM_ERR_NOT_A_DIR),
        }
        match std::fs::canonicalize(&path) {
            Ok(p) => *storage = p.into_os_string().into_string().unwrap(),
            Err(_) => return Err(ALPM_ERR_NOT_A_DIR),
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
pub struct alpm_handle_t {
    // 	/* internal usage */
    pub db_local: alpm_db_t,      //// local db pointer */
    pub dbs_sync: Vec<alpm_db_t>, /* List of (alpm_db_t *) */
    // 	FILE *logstream;        /* log file stream pointer */
    pub trans: alpm_trans_t,
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
    //
    // 	/* filesystem paths */
    pub root: String,                 /* Root path, default '/' */
    pub dbpath: String,               /* Base path to pacman's DBs */
    pub logfile: String,              /* Name of the log file */
    pub lockfile: String,             /* Name of the lock file */
    pub gpgdir: String,               /* Directory where GnuPG files are stored */
    pub cachedirs: Vec<String>,       /* Paths to pacman cache directories */
    pub hookdirs: Vec<String>,        /* Paths to hook directories */
    pub overwrite_files: Vec<String>, /* Paths that may be overwritten */
    //
    // 	/* package lists */
    pub noupgrade: Vec<String>,   /* List of packages NOT to be upgraded */
    pub noextract: Vec<String>,   /* List of files NOT to extract */
    pub ignorepkg: Vec<String>,   /* List of packages to ignore */
    pub ignoregroup: Vec<String>, /* List of groups to ignore */
    ///List of virtual packages used to satisfy dependencies
    pub assumeinstalled: Vec<alpm_depend_t>,
    //
    // 	/* options */
    arch: String, /* Architecture of packages we should allow */
    deltaratio: f64,
    /// Download deltas if possible; a ratio value */
    pub usesyslog: i32, /* Use syslog instead of logfile? */
    /* TODO move to frontend */
    pub checkspace: i32, /* Check disk space before installing */
    pub dbext: String,   /* Sync DB extension */
    siglevel: siglevel,  /* Default signature verification level */
    localfilesiglevel: siglevel, /* Signature verification level for local file
                         // 	                                       upgrade operations */
    remotefilesiglevel: siglevel, /* Signature verification level for remote file
                                  // 	                                       upgrade operations */
    //
    // 	/* error code */
    // pub pm_errno: alpm_errno_t,

    /* lock file descriptor */
    lockfd: Option<File>,
    //
    // 	/* for delta parsing efficiency */
    // 	int delta_regex_compiled;
    // 	regex_t delta_regex;
}
