// #[macro_use]
// mod util;
use super::*;
use std;
// use std::error::Error;
use std::fs::File;
use std::io::Result;
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

// #include <errno.h>
// #include <stdlib.h>
// #include <string.h>
// #include <limits.h>
// #include <sys/types.h>
// #include <syslog.h>
// #include <sys/stat.h>
// #include <fcntl.h>
// /* libalpm */
// #include "handle.h"
// #include "alpm_list.h"
// #include "util.h"
// #include "log.h"
// #include "delta.h"
// #include "trans.h"
// #include "alpm.h"
// #include "deps.h"

fn _alpm_handle_new() -> alpm_handle_t {
    let mut handle = alpm_handle_t::default();

    // CALLOC(handle, 1, sizeof(alpm_handle_t), return NULL);
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
fn _alpm_handle_lock(handle: &mut alpm_handle_t) -> Result<()> {
    assert!(handle.lockfile != "");
    assert!(handle.lockfd.is_none());

    /* create the dir of the lockfile first */
    match File::create(&handle.lockfile) {
        Ok(f) => handle.lockfd = Some(f),
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
fn alpm_unlock(handle: &mut alpm_handle_t) -> Result<()> {
    // ASSERT(handle->lockfile != NULL, return 0);
    // ASSERT(handle->lockfd >= 0, return 0);

    // handle.lockfd.close();
    handle.lockfd = None;

    if std::fs::remove_file(&handle.lockfile).is_err() {
        unimplemented!();
        // RET_ERR_ASYNC_SAFE(handle, ALPM_ERR_SYSTEM, -1);
    }
    return Ok(());
}

fn _alpm_handle_unlock(handle: &mut alpm_handle_t) -> Result<()> {
    match alpm_unlock(handle) {
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

#[derive(Default, Debug)]
///TODO: Implement this
pub struct alpm_list_t {}

// const char SYMEXPORT *alpm_option_get_root(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->root;
// }
//
pub fn alpm_option_get_dbpath(handle: &alpm_handle_t) -> &String {
    // unimplemented!();
    // CHECK_HANDLE(handle, return NULL);
    return &handle.dbpath;
}
//
// alpm_list_t SYMEXPORT *alpm_option_get_hookdirs(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->hookdirs;
// }
// alpm_list_t SYMEXPORT *alpm_option_get_cachedirs(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->cachedirs;
// }
//
// const char SYMEXPORT *alpm_option_get_logfile(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->logfile;
// }
//
// const char SYMEXPORT *alpm_option_get_lockfile(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->lockfile;
// }
//
// const char SYMEXPORT *alpm_option_get_gpgdir(alpm_handle_t *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->gpgdir;
// }
//
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
//
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
// int SYMEXPORT alpm_option_set_logcb(alpm_handle_t *handle, alpm_cb_log cb)
// {
// 	CHECK_HANDLE(handle, return -1);
// 	handle->logcb = cb;
// 	return 0;
// }
//
// int SYMEXPORT alpm_option_set_dlcb(alpm_handle_t *handle, alpm_cb_download cb)
// {
// 	CHECK_HANDLE(handle, return -1);
// 	handle->dlcb = cb;
// 	return 0;
// }
//
// int SYMEXPORT alpm_option_set_fetchcb(alpm_handle_t *handle, alpm_cb_fetch cb)
// {
// 	CHECK_HANDLE(handle, return -1);
// 	handle->fetchcb = cb;
// 	return 0;
// }
//
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
//
// int SYMEXPORT alpm_option_set_questioncb(alpm_handle_t *handle, alpm_cb_question cb)
// {
// 	CHECK_HANDLE(handle, return -1);
// 	handle->questioncb = cb;
// 	return 0;
// }
//
// int SYMEXPORT alpm_option_set_progresscb(alpm_handle_t *handle, alpm_cb_progress cb)
// {
// 	CHECK_HANDLE(handle, return -1);
// 	handle->progresscb = cb;
// 	return 0;
// }
//
// static char *canonicalize_path(const char *path)
// {
// 	char *new_path;
// 	size_t len;
//
// 	/* verify path ends in a '/' */
// 	len = strlen(path);
// 	if(path[len - 1] != '/') {
// 		len += 1;
// 	}
// 	CALLOC(new_path, len + 1, sizeof(char), return NULL);
// 	strcpy(new_path, path);
// 	new_path[len - 1] = '/';
// 	return new_path;
// }
//
// alpm_errno_t _alpm_set_directory_option(const char *value,
// 		char **storage, int must_exist)
// {
// 	struct stat st;
// 	char real[PATH_MAX];
// 	const char *path;
//
// 	path = value;
// 	if(!path) {
// 		return ALPM_ERR_WRONG_ARGS;
// 	}
// 	if(must_exist) {
// 		if(stat(path, &st) == -1 || !S_ISDIR(st.st_mode)) {
// 			return ALPM_ERR_NOT_A_DIR;
// 		}
// 		if(!realpath(path, real)) {
// 			return ALPM_ERR_NOT_A_DIR;
// 		}
// 		path = real;
// 	}
//
// 	if(*storage) {
// 		FREE(*storage);
// 	}
// 	*storage = canonicalize_path(path);
// 	if(!*storage) {
// 		return ALPM_ERR_MEMORY;
// 	}
// 	return 0;
// }
//
// int SYMEXPORT alpm_option_add_hookdir(alpm_handle_t *handle, const char *hookdir)
// {
// 	char *newhookdir;
//
// 	CHECK_HANDLE(handle, return -1);
// 	ASSERT(hookdir != NULL, RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1));
//
// 	newhookdir = canonicalize_path(hookdir);
// 	if(!newhookdir) {
// 		RET_ERR(handle, ALPM_ERR_MEMORY, -1);
// 	}
// 	handle->hookdirs = alpm_list_add(handle->hookdirs, newhookdir);
// 	_alpm_log(handle, ALPM_LOG_DEBUG, "option 'hookdir' = %s\n", newhookdir);
// 	return 0;
// }
//
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
//
// int SYMEXPORT alpm_option_add_cachedir(alpm_handle_t *handle, const char *cachedir)
// {
// 	char *newcachedir;
//
// 	CHECK_HANDLE(handle, return -1);
// 	ASSERT(cachedir != NULL, RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1));
// 	/* don't stat the cachedir yet, as it may not even be needed. we can
// 	 * fail later if it is needed and the path is invalid. */
//
// 	newcachedir = canonicalize_path(cachedir);
// 	if(!newcachedir) {
// 		RET_ERR(handle, ALPM_ERR_MEMORY, -1);
// 	}
// 	handle->cachedirs = alpm_list_add(handle->cachedirs, newcachedir);
// 	_alpm_log(handle, ALPM_LOG_DEBUG, "option 'cachedir' = %s\n", newcachedir);
// 	return 0;
// }
//
// int SYMEXPORT alpm_option_set_cachedirs(alpm_handle_t *handle, alpm_list_t *cachedirs)
// {
// 	alpm_list_t *i;
// 	CHECK_HANDLE(handle, return -1);
// 	if(handle->cachedirs) {
// 		FREELIST(handle->cachedirs);
// 	}
// 	for(i = cachedirs; i; i = i->next) {
// 		int ret = alpm_option_add_cachedir(handle, i->data);
// 		if(ret) {
// 			return ret;
// 		}
// 	}
// 	return 0;
// }
//
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
//
// int SYMEXPORT alpm_option_set_logfile(alpm_handle_t *handle, const char *logfile)
// {
// 	char *oldlogfile = handle->logfile;
//
// 	CHECK_HANDLE(handle, return -1);
// 	if(!logfile) {
// 		handle->pm_errno = ALPM_ERR_WRONG_ARGS;
// 		return -1;
// 	}
//
// 	STRDUP(handle->logfile, logfile, RET_ERR(handle, ALPM_ERR_MEMORY, -1));
//
// 	/* free the old logfile path string, and close the stream so logaction
// 	 * will reopen a new stream on the new logfile */
// 	if(oldlogfile) {
// 		FREE(oldlogfile);
// 	}
// 	if(handle->logstream) {
// 		fclose(handle->logstream);
// 		handle->logstream = NULL;
// 	}
// 	_alpm_log(handle, ALPM_LOG_DEBUG, "option 'logfile' = %s\n", handle->logfile);
// 	return 0;
// }
//
// int SYMEXPORT alpm_option_set_gpgdir(alpm_handle_t *handle, const char *gpgdir)
// {
// 	int err;
// 	CHECK_HANDLE(handle, return -1);
// 	if((err = _alpm_set_directory_option(gpgdir, &(handle->gpgdir), 0))) {
// 		RET_ERR(handle, err, -1);
// 	}
// 	_alpm_log(handle, ALPM_LOG_DEBUG, "option 'gpgdir' = %s\n", handle->gpgdir);
// 	return 0;
// }
//
// int SYMEXPORT alpm_option_set_usesyslog(alpm_handle_t *handle, int usesyslog)
// {
// 	CHECK_HANDLE(handle, return -1);
// 	handle->usesyslog = usesyslog;
// 	return 0;
// }
//
// static int _alpm_option_strlist_add(alpm_handle_t *handle, alpm_list_t **list, const char *str)
// {
// 	char *dup;
// 	CHECK_HANDLE(handle, return -1);
// 	STRDUP(dup, str, RET_ERR(handle, ALPM_ERR_MEMORY, -1));
// 	*list = alpm_list_add(*list, dup);
// 	return 0;
// }
//
// static int _alpm_option_strlist_set(alpm_handle_t *handle, alpm_list_t **list,
// alpm_list_t *newlist)
// {
// 	CHECK_HANDLE(handle, return -1);
// 	FREELIST(*list);
// 	*list = alpm_list_strdup(newlist);
// 	return 0;
// }
//
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
//
// int SYMEXPORT alpm_option_set_noupgrades(alpm_handle_t *handle, alpm_list_t *noupgrade)
// {
// 	return _alpm_option_strlist_set(handle, &(handle->noupgrade), noupgrade);
// }
//
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
//
// int SYMEXPORT alpm_option_set_noextracts(alpm_handle_t *handle, alpm_list_t *noextract)
// {
// 	return _alpm_option_strlist_set(handle, &(handle->noextract), noextract);
// }
//
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
//
// int SYMEXPORT alpm_option_set_ignorepkgs(alpm_handle_t *handle, alpm_list_t *ignorepkgs)
// {
// 	return _alpm_option_strlist_set(handle, &(handle->ignorepkg), ignorepkgs);
// }
//
// int SYMEXPORT alpm_option_remove_ignorepkg(alpm_handle_t *handle, const char *pkg)
// {
// 	return _alpm_option_strlist_rem(handle, &(handle->ignorepkg), pkg);
// }
//
// int SYMEXPORT alpm_option_add_ignoregroup(alpm_handle_t *handle, const char *grp)
// {
// 	return _alpm_option_strlist_add(handle, &(handle->ignoregroup), grp);
// }
//
// int SYMEXPORT alpm_option_set_ignoregroups(alpm_handle_t *handle, alpm_list_t *ignoregrps)
// {
// 	return _alpm_option_strlist_set(handle, &(handle->ignoregroup), ignoregrps);
// }
//
// int SYMEXPORT alpm_option_remove_ignoregroup(alpm_handle_t *handle, const char *grp)
// {
// 	return _alpm_option_strlist_rem(handle, &(handle->ignoregroup), grp);
// }
//
// int SYMEXPORT alpm_option_add_overwrite_file(alpm_handle_t *handle, const char *glob)
// {
// 	return _alpm_option_strlist_add(handle, &(handle->overwrite_files), glob);
// }
//
// int SYMEXPORT alpm_option_set_overwrite_files(alpm_handle_t *handle, alpm_list_t *globs)
// {
// 	return _alpm_option_strlist_set(handle, &(handle->overwrite_files), globs);
// }
//
// int SYMEXPORT alpm_option_remove_overwrite_file(alpm_handle_t *handle, const char *glob)
// {
// 	return _alpm_option_strlist_rem(handle, &(handle->overwrite_files), glob);
// }
//
// int SYMEXPORT alpm_option_add_assumeinstalled(alpm_handle_t *handle, const alpm_depend_t *dep)
// {
// 	alpm_depend_t *depcpy;
// 	CHECK_HANDLE(handle, return -1);
// 	ASSERT(dep->mod == ALPM_DEP_MOD_EQ || dep->mod == ALPM_DEP_MOD_ANY,
// 			RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1));
// 	ASSERT((depcpy = _alpm_dep_dup(dep)), RET_ERR(handle, ALPM_ERR_MEMORY, -1));
//
// 	/* fill in name_hash in case dep was built by hand */
// 	depcpy->name_hash = _alpm_hash_sdbm(dep->name);
// 	handle->assumeinstalled = alpm_list_add(handle->assumeinstalled, depcpy);
// 	return 0;
// }
//
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
impl alpm_handle_t {
    pub fn alpm_option_remove_assumeinstalled(&self, dep: &alpm_depend_t) {
        // alpm_depend_t *vdata = NULL;
        // CHECK_HANDLE(handle, return -1);

        // 	self.assumeinstalled = alpm_list_remove(handle->assumeinstalled, dep,
        // &assumeinstalled_cmp, (void **)&vdata);
        // 	if(vdata != NULL) {
        // 		alpm_dep_free(vdata);
        // 		return 1;
        // 	}
        //
        // 	return 0;
    }

    pub fn alpm_option_set_arch(&mut self, arch: &String) -> i32 {
        self.arch = arch.clone();
        return 0;
    }

    pub fn alpm_option_set_deltaratio(&mut self, ratio: f64) -> i32 {
        if ratio < 0.0 || ratio > 2.0 {
            RET_ERR!(self, ALPM_ERR_WRONG_ARGS, -1);
        }
        self.deltaratio = ratio;
        return 0;
    }

    pub fn alpm_get_localdb(&self) -> &alpm_db_t {
        return &self.db_local;
    }

    // pub fn alpm_get_syncdbs(handle: &alpm_handle_t) -> &Vec<alpm_db_t> {
    //     // CHECK_HANDLE(handle, return NULL);
    //     return &handle.dbs_sync;
    // }

    // int SYMEXPORT alpm_option_set_checkspace(alpm_handle_t *handle, int checkspace)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->checkspace = checkspace;
    // 	return 0;
    // }
    //
    // int SYMEXPORT alpm_option_set_dbext(alpm_handle_t *handle, const char *dbext)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	ASSERT(dbext, RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1));
    //
    // 	if(handle->dbext) {
    // 		FREE(handle->dbext);
    // 	}
    //
    // 	STRDUP(handle->dbext, dbext, RET_ERR(handle, ALPM_ERR_MEMORY, -1));
    //
    // 	_alpm_log(handle, ALPM_LOG_DEBUG, "option 'dbext' = %s\n", handle->dbext);
    // 	return 0;
    // }

    // int SYMEXPORT alpm_option_set_default_siglevel(alpm_handle_t *handle,
    // 		int level)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // #ifdef HAVE_LIBGPGME
    // 	handle->siglevel = level;
    // #else
    // 	if(level != 0 && level != ALPM_SIG_USE_DEFAULT) {
    // 		RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1);
    // 	}
    // #endif
    // 	return 0;
    // }
    fn alpm_option_get_default_siglevel(&self) -> siglevel {
        // CHECK_HANDLE(handle, return -1);
        return self.siglevel;
    }

    pub fn alpm_option_set_local_file_siglevel(&mut self, level: siglevel) -> i32 {
        // CHECK_HANDLE(handle, return -1);
        if cfg!(HAVE_LIBGPGME) {
            self.localfilesiglevel = level;
        } else if
        /*level != 0 &&*/
        level.ALPM_SIG_USE_DEFAULT {
            RET_ERR!(self, ALPM_ERR_WRONG_ARGS, -1);
        }

        return 0;
    }

    pub fn alpm_option_get_local_file_siglevel(&self) -> siglevel {
        // CHECK_HANDLE(handle, return -1);
        if self.localfilesiglevel.ALPM_SIG_USE_DEFAULT {
            return self.siglevel;
        } else {
            return self.localfilesiglevel;
        }
    }

    pub fn alpm_option_set_remote_file_siglevel(&self, level: i32) -> i32 {
        unimplemented!();
        // 	CHECK_HANDLE(handle, return -1);
        // #ifdef HAVE_LIBGPGME
        // 	handle->remotefilesiglevel = level;
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
    pub db_local: alpm_db_t,              //// local db pointer */
    pub dbs_sync: Option<Vec<alpm_db_t>>, /* List of (alpm_db_t *) */
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
    // 	alpm_cb_fetch fetchcb;      /* Download file callback function */
    // 	alpm_cb_event eventcb;
    // 	alpm_cb_question questioncb;
    // 	alpm_cb_progress progresscb;
    //
    // 	/* filesystem paths */
    pub root: String,    /* Root path, default '/' */
    pub dbpath: String,  /* Base path to pacman's DBs */
    pub logfile: String, /* Name of the log file */
    lockfile: String,    /* Name of the lock file */
    // 	char *gpgdir;            /* Directory where GnuPG files are stored */
    // 	alpm_list_t *cachedirs;  /* Paths to pacman cache directories */
    // 	alpm_list_t *hookdirs;   /* Paths to hook directories */
    // 	alpm_list_t *overwrite_files; /* Paths that may be overwritten */
    //
    // 	/* package lists */
    // 	alpm_list_t *noupgrade;   /* List of packages NOT to be upgraded */
    // 	alpm_list_t *noextract;   /* List of files NOT to extract */
    // 	alpm_list_t *ignorepkg;   /* List of packages to ignore */
    // 	alpm_list_t *ignoregroup; /* List of groups to ignore */
    ///List of virtual packages used to satisfy dependencies
    pub assumeinstalled: Vec<alpm_depend_t>,
    //
    // 	/* options */
    arch: String, /* Architecture of packages we should allow */
    deltaratio: f64,
    /// Download deltas if possible; a ratio value */
    // 	int usesyslog;           /* Use syslog instead of logfile? */ /* TODO move to frontend */
    // 	int checkspace;          /* Check disk space before installing */
    // 	char *dbext;             /* Sync DB extension */
    siglevel: siglevel, /* Default signature verification level */
    localfilesiglevel: siglevel, /* Signature verification level for local file
                                 // 	                                       upgrade operations */
    remotefilesiglevel: siglevel, /* Signature verification level for remote file
                                  // 	                                       upgrade operations */
    //
    // 	/* error code */
    pub pm_errno: alpm_errno_t,

    /* lock file descriptor */
    lockfd: Option<File>,
    //
    // 	/* for delta parsing efficiency */
    // 	int delta_regex_compiled;
    // 	regex_t delta_regex;
}