use super::*;
// /*
//  *  sync.c
//  *
//  *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
//  *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
//  *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
//  *  Copyright (c) 2005 by Christian Hamar <krics@linuxforum.hu>
//  *  Copyright (c) 2005, 2006 by Miklos Vajna <vmiklos@frugalware.org>
//  *
//  *  This program is free software; you can redistribute it and/or modify
//  *  it under the terms of the GNU General Public License as published by
//  *  the Free Software Foundation; either version 2 of the License, or
//  *  (at your option) any later version.
//  *
//  *  This program is distributed in the hope that it will be useful,
//  *  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  *  GNU General Public License for more details.
//  *
//  *  You should have received a copy of the GNU General Public License
//  *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//  */
//
// #include <sys/types.h> /* off_t */
// #include <stdlib.h>
// #include <stdio.h>
// #include <string.h>
// #include <stdint.h> /* intmax_t */
// #include <unistd.h>
// #include <limits.h>
//
// /* libalpm */
// #include "sync.h"
// #include "alpm_list.h"
// #include "log.h"
// #include "package.h"
// #include "db.h"
// #include "deps.h"
// #include "conflict.h"
// #include "trans.h"
// #include "add.h"
// #include "util.h"
// #include "handle.h"
// #include "alpm.h"
// #include "dload.h"
// #include "delta.h"
// #include "remove.h"
// #include "diskspace.h"
// #include "signing.h"
//
// /** Check for new version of pkg in sync repos
//  * (only the first occurrence is considered in sync)
//  */
// alpm_pkg_t SYMEXPORT *alpm_sync_newversion(alpm_pkg_t *pkg, alpm_list_t *dbs_sync)
// {
// 	alpm_list_t *i;
// 	alpm_pkg_t *spkg = NULL;
//
// 	ASSERT(pkg != NULL, return NULL);
// 	pkg->handle->pm_errno = ALPM_ERR_OK;
//
// 	for(i = dbs_sync; !spkg && i; i = i->next) {
// 		alpm_db_t *db = i->data;
// 		if(!(db->usage & ALPM_DB_USAGE_SEARCH)) {
// 			continue;
// 		}
//
// 		spkg = _alpm_db_get_pkgfromcache(db, pkg->name);
// 	}
//
// 	if(spkg == NULL) {
// 		_alpm_log(pkg->handle, ALPM_LOG_DEBUG, "'{}' not found in sync db => no upgrade\n",
// 				pkg->name);
// 		return NULL;
// 	}
//
// 	/* compare versions and see if spkg is an upgrade */
// 	if(_alpm_pkg_compare_versions(spkg, pkg) > 0) {
// 		_alpm_log(pkg->handle, ALPM_LOG_DEBUG, "new version of '{}' found ({} => {})\n",
// 					pkg->name, pkg->version, spkg->version);
// 		return spkg;
// 	}
// 	/* spkg is not an upgrade */
// 	return NULL;
// }
//
// static int check_literal(alpm_handle_t *handle, alpm_pkg_t *lpkg,
// 		alpm_pkg_t *spkg, int enable_downgrade)
// {
// 	/* 1. literal was found in sdb */
// 	int cmp = _alpm_pkg_compare_versions(spkg, lpkg);
// 	if(cmp > 0) {
// 		debug!("new version of '{}' found ({} => {})\n",
// 				lpkg->name, lpkg->version, spkg->version);
// 		/* check IgnorePkg/IgnoreGroup */
// 		if(alpm_pkg_should_ignore(handle, spkg)
// 				|| alpm_pkg_should_ignore(handle, lpkg)) {
// 			_alpm_log(handle, ALPM_LOG_WARNING, _("{}: ignoring package upgrade ({} => {})\n"),
// 					lpkg->name, lpkg->version, spkg->version);
// 		} else {
// 			debug!("adding package {}-{} to the transaction targets\n",
// 					spkg->name, spkg->version);
// 			return 1;
// 		}
// 	} else if(cmp < 0) {
// 		if(enable_downgrade) {
// 			/* check IgnorePkg/IgnoreGroup */
// 			if(alpm_pkg_should_ignore(handle, spkg)
// 					|| alpm_pkg_should_ignore(handle, lpkg)) {
// 				_alpm_log(handle, ALPM_LOG_WARNING, _("{}: ignoring package downgrade ({} => {})\n"),
// 						lpkg->name, lpkg->version, spkg->version);
// 			} else {
// 				_alpm_log(handle, ALPM_LOG_WARNING, _("{}: downgrading from version {} to version {}\n"),
// 						lpkg->name, lpkg->version, spkg->version);
// 				return 1;
// 			}
// 		} else {
// 			alpm_db_t *sdb = alpm_pkg_get_db(spkg);
// 			_alpm_log(handle, ALPM_LOG_WARNING, _("{}: local ({}) is newer than {} ({})\n"),
// 					lpkg->name, lpkg->version, sdb->treename, spkg->version);
// 		}
// 	}
// 	return 0;
// }
//
// static alpm_list_t *check_replacers(alpm_handle_t *handle, alpm_pkg_t *lpkg,
// 		alpm_db_t *sdb)
// {
// 	/* 2. search for replacers in sdb */
// 	alpm_list_t *replacers = NULL;
// 	alpm_list_t *k;
// 	_alpm_log(handle, ALPM_LOG_DEBUG,
// 			"searching for replacements for {} in {}\n",
// 			lpkg->name, sdb->treename);
// 	for(k = _alpm_db_get_pkgcache(sdb); k; k = k->next) {
// 		int found = 0;
// 		alpm_pkg_t *spkg = k->data;
// 		alpm_list_t *l;
// 		for(l = alpm_pkg_get_replaces(spkg); l; l = l->next) {
// 			alpm_depend_t *replace = l->data;
// 			/* we only want to consider literal matches at this point. */
// 			if(_alpm_depcmp_literal(lpkg, replace)) {
// 				found = 1;
// 				break;
// 			}
// 		}
// 		if(found) {
// 			alpm_question_replace_t question = {
// 				.type = ALPM_QUESTION_REPLACE_PKG,
// 				.replace = 0,
// 				.oldpkg = lpkg,
// 				.newpkg = spkg,
// 				.newdb = sdb
// 			};
// 			alpm_pkg_t *tpkg;
// 			/* check IgnorePkg/IgnoreGroup */
// 			if(alpm_pkg_should_ignore(handle, spkg)
// 					|| alpm_pkg_should_ignore(handle, lpkg)) {
// 				_alpm_log(handle, ALPM_LOG_WARNING,
// 						_("ignoring package replacement ({}-{} => {}-{})\n"),
// 						lpkg->name, lpkg->version, spkg->name, spkg->version);
// 				continue;
// 			}
//
// 			QUESTION(handle, &question);
// 			if(!question.replace) {
// 				continue;
// 			}
//
// 			/* If spkg is already in the target list, we append lpkg to spkg's
// 			 * removes list */
// 			tpkg = alpm_pkg_find(handle->trans->add, spkg->name);
// 			if(tpkg) {
// 				/* sanity check, multiple repos can contain spkg->name */
// 				if(tpkg->origin_data.db != sdb) {
// 					_alpm_log(handle, ALPM_LOG_WARNING, _("cannot replace {} by {}\n"),
// 							lpkg->name, spkg->name);
// 					continue;
// 				}
// 				debug!("appending {} to the removes list of {}\n",
// 						lpkg->name, tpkg->name);
// 				tpkg->removes = alpm_list_add(tpkg->removes, lpkg);
// 				/* check the to-be-replaced package's reason field */
// 				if(alpm_pkg_get_reason(lpkg) == ALPM_PKG_REASON_EXPLICIT) {
// 					tpkg->reason = ALPM_PKG_REASON_EXPLICIT;
// 				}
// 			} else {
// 				/* add spkg to the target list */
// 				/* copy over reason */
// 				spkg->reason = alpm_pkg_get_reason(lpkg);
// 				spkg->removes = alpm_list_add(NULL, lpkg);
// 				_alpm_log(handle, ALPM_LOG_DEBUG,
// 						"adding package {}-{} to the transaction targets\n",
// 						spkg->name, spkg->version);
// 				replacers = alpm_list_add(replacers, spkg);
// 			}
// 		}
// 	}
// 	return replacers;
// }

/// Search for packages to upgrade and add them to the transaction.
pub fn alpm_sync_sysupgrade(handle: &alpm_handle_t, enable_downgrade: bool) -> Result<i32> {
	let trans = &handle.trans;
	//
	// 	CHECK_HANDLE(handle, return -1);
	// 	trans = handle->trans;
	// 	ASSERT(trans != NULL, RET_ERR(handle, ALPM_ERR_TRANS_NULL, -1));
	// 	ASSERT(trans->state == STATE_INITIALIZED, RET_ERR(handle, ALPM_ERR_TRANS_NOT_INITIALIZED, -1));
	//
	debug!("checking for package upgrades\n");
	for lpkg in handle.db_local._alpm_db_get_pkgcache() {
		if alpm_pkg_find(&trans.remove, &lpkg.name).is_some() {
			debug!("{} is marked for removal -- skipping", lpkg.name);
			continue;
		}

		if alpm_pkg_find(&trans.add, &lpkg.name).is_some() {
			debug!("{} is already in the target list -- skipping", lpkg.name);
			continue;
		}

		/* Search for replacers then literal (if no replacer) in each sync database. */
		for sdb in &handle.dbs_sync {
			// alpm_db_t *sdb = j.data;
			// alpm_list_t *replacers;

			if !sdb.usage.ALPM_DB_USAGE_UPGRADE {
				continue;
			}
			unimplemented!();
			/* Check sdb */
			// replacers = check_replacers(handle, lpkg, sdb);
			// if (replacers) {
			// 	// trans.add = alpm_list_join(trans.add, replacers);
			// 	/* jump to next local package */
			// 	// break;
			// } else {
			// 	// 				alpm_pkg_t *spkg = _alpm_db_get_pkgfromcache(sdb, lpkg.name);
			// 	// 				if(spkg) {
			// 	// 					if(check_literal(handle, lpkg, spkg, enable_downgrade)) {
			// 	// 						trans.add = alpm_list_add(trans.add, spkg);
			// 	// 					}
			// 	// 					/* jump to next local package */
			// 	// 					break;
			// 	// 				}
			// }
		}
	}

	Ok(0)
}

/** Find group members across a list of databases.
 * If a member exists in several databases, only the first database is used.
 * IgnorePkg is also handled.
 * @param dbs the list of alpm_db_t *
 * @param name the name of the group
 * @return the list of alpm_pkg_t * (caller is responsible for alpm_list_free)
 */
pub fn alpm_find_group_pkgs(dbs: Vec<alpm_db_t>, name: &String) -> Vec<alpm_pkg_t> {
	unimplemented!();
	// 	alpm_list_t *i, *j, *pkgs = NULL, *ignorelist = NULL;
	//
	// 	for(i = dbs; i; i = i.next) {
	// 		alpm_db_t *db = i.data;
	// 		alpm_group_t *grp = alpm_db_get_group(db, name);
	//
	// 		if(!grp) {
	// 			continue;
	// 		}
	//
	// 		for(j = grp.packages; j; j = j.next) {
	// 			alpm_pkg_t *pkg = j.data;
	//
	// 			if(alpm_pkg_find(ignorelist, pkg.name)) {
	// 				continue;
	// 			}
	// 			if(alpm_pkg_should_ignore(db.handle, pkg)) {
	// 				alpm_question_install_ignorepkg_t question = {
	// 					.type = ALPM_QUESTION_INSTALL_IGNOREPKG,
	// 					.install = 0,
	// 					.pkg = pkg
	// 				};
	// 				ignorelist = alpm_list_add(ignorelist, pkg);
	// 				QUESTION(db.handle, &question);
	// 				if(!question.install) {
	// 					continue;
	// 				}
	// 			}
	// 			if(!alpm_pkg_find(pkgs, pkg.name)) {
	// 				pkgs = alpm_list_add(pkgs, pkg);
	// 			}
	// 		}
	// 	}
	// 	alpm_list_free(ignorelist);
	// 	return pkgs;
}

// /** Compute the size of the files that will be downloaded to install a
//  * package.
//  * @param newpkg the new package to upgrade to
//  */
// static int compute_download_size(alpm_pkg_t *newpkg)
// {
// 	const char *fname;
// 	char *fpath, *fnamepart = NULL;
// 	off_t size = 0;
// 	alpm_handle_t *handle = newpkg.handle;
// 	int ret = 0;
//
// 	if(newpkg.origin != ALPM_PKG_FROM_SYNCDB) {
// 		newpkg.infolevel |= INFRQ_DSIZE;
// 		newpkg.download_size = 0;
// 		return 0;
// 	}
//
// 	ASSERT(newpkg.filename != NULL, RET_ERR(handle, ALPM_ERR_PKG_INVALID_NAME, -1));
// 	fname = newpkg.filename;
// 	fpath = _alpm_filecache_find(handle, fname);
//
// 	/* downloaded file exists, so there's nothing to grab */
// 	if(fpath) {
// 		size = 0;
// 		goto finish;
// 	}
//
// 	CALLOC(fnamepart, strlen(fname) + 6, sizeof(char), return -1);
// 	sprintf(fnamepart, "{}.part", fname);
// 	fpath = _alpm_filecache_find(handle, fnamepart);
// 	if(fpath) {
// 		struct stat st;
// 		if(stat(fpath, &st) == 0) {
// 			/* subtract the size of the .part file */
// 			debug!("using (package - .part) size\n");
// 			size = newpkg.size - st.st_size;
// 			size = size < 0 ? 0 : size;
// 		}
//
// 		/* tell the caller that we have a partial */
// 		ret = 1;
// 	} else if(handle.deltaratio > 0.0) {
// 		off_t dltsize;
//
// 		dltsize = _alpm_shortest_delta_path(handle, newpkg.deltas,
// 				newpkg.filename, &newpkg.delta_path);
//
// 		if(newpkg.delta_path && (dltsize < newpkg.size * handle.deltaratio)) {
// 			debug!("using delta size\n");
// 			size = dltsize;
// 		} else {
// 			debug!("using package size\n");
// 			size = newpkg.size;
// 			alpm_list_free(newpkg.delta_path);
// 			newpkg.delta_path = NULL;
// 		}
// 	} else {
// 		size = newpkg.size;
// 	}
//
// finish:
// 	debug!("setting download size %jd for pkg {}\n",
// 			(intmax_t)size, newpkg.name);
//
// 	newpkg.infolevel |= INFRQ_DSIZE;
// 	newpkg.download_size = size;
//
// 	FREE(fpath);
// 	FREE(fnamepart);
//
// 	return ret;
// }
//
// int _alpm_sync_prepare(alpm_handle_t *handle, alpm_list_t **data)
// {
// 	alpm_list_t *i, *j;
// 	alpm_list_t *deps = NULL;
// 	alpm_list_t *unresolvable = NULL;
// 	int from_sync = 0;
// 	int ret = 0;
// 	alpm_trans_t *trans = handle.trans;
// 	alpm_event_t event;
//
// 	if(data) {
// 		*data = NULL;
// 	}
//
// 	for(i = trans.add; i; i = i.next) {
// 		alpm_pkg_t *spkg = i.data;
// 		if (spkg.origin == ALPM_PKG_FROM_SYNCDB){
// 			from_sync = 1;
// 			break;
// 		}
// 	}
//
// 	/* ensure all sync database are valid if we will be using them */
// 	for(i = handle.dbs_sync; i; i = i.next) {
// 		const alpm_db_t *db = i.data;
// 		if(db.status & DB_STATUS_INVALID) {
// 			RET_ERR(handle, ALPM_ERR_DB_INVALID, -1);
// 		}
// 		/* missing databases are not allowed if we have sync targets */
// 		if(from_sync && db.status & DB_STATUS_MISSING) {
// 			RET_ERR(handle, ALPM_ERR_DB_NOT_FOUND, -1);
// 		}
// 	}
//
// 	if(!(trans.flags & ALPM_TRANS_FLAG_NODEPS)) {
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
// 			alpm_pkg_t *spkg = i.data;
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
// 			alpm_pkg_t *pkg = i->data;
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
// 			alpm_pkg_t *pkg = i->data;
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
// 	}
//
// 	if(!(trans->flags & ALPM_TRANS_FLAG_NOCONFLICTS)) {
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
// 			alpm_conflict_t *conflict = i->data;
// 			alpm_pkg_t *rsync, *sync, *sync1, *sync2;
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
// 			alpm_depend_t *dep1 = alpm_dep_from_string(conflict->package1);
// 			alpm_depend_t *dep2 = alpm_dep_from_string(conflict->package2);
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
// 					alpm_conflict_t *newconflict = _alpm_conflict_dup(conflict);
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
// 			alpm_conflict_t *conflict = i->data;
// 			int found = 0;
//
// 			/* if conflict->package2 (the local package) is not elected for removal,
// 			   we ask the user */
// 			if(alpm_pkg_find(trans->remove, conflict->package2)) {
// 				found = 1;
// 			}
// 			for(j = trans->add; j && !found; j = j->next) {
// 				alpm_pkg_t *spkg = j->data;
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
// 				alpm_pkg_t *sync = alpm_pkg_find(trans->add, conflict->package1);
// 				alpm_pkg_t *local = _alpm_db_get_pkgfromcache(handle->db_local, conflict->package2);
// 				debug!("electing '{}' for removal\n", conflict->package2);
// 				sync->removes = alpm_list_add(sync->removes, local);
// 			} else { /* abort */
// 				_alpm_log(handle, ALPM_LOG_ERROR, _("unresolvable package conflicts detected\n"));
// 				handle->pm_errno = ALPM_ERR_CONFLICTING_DEPS;
// 				ret = -1;
// 				if(data) {
// 					alpm_conflict_t *newconflict = _alpm_conflict_dup(conflict);
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
// 	}
//
// 	/* Build trans->remove list */
// 	for(i = trans->add; i; i = i->next) {
// 		alpm_pkg_t *spkg = i->data;
// 		for(j = spkg->removes; j; j = j->next) {
// 			alpm_pkg_t *rpkg = j->data;
// 			if(!alpm_pkg_find(trans->remove, rpkg->name)) {
// 				alpm_pkg_t *copy;
// 				debug!("adding '{}' to remove list\n", rpkg->name);
// 				if(_alpm_pkg_dup(rpkg, &copy) == -1) {
// 					return -1;
// 				}
// 				trans->remove = alpm_list_add(trans->remove, copy);
// 			}
// 		}
// 	}
//
// 	if(!(trans->flags & ALPM_TRANS_FLAG_NODEPS)) {
// 		debug!("checking dependencies\n");
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
// 	}
// 	for(i = trans->add; i; i = i->next) {
// 		/* update download size field */
// 		alpm_pkg_t *spkg = i->data;
// 		alpm_pkg_t *lpkg = alpm_db_get_pkg(handle->db_local, spkg->name);
// 		if(compute_download_size(spkg) < 0) {
// 			ret = -1;
// 			goto cleanup;
// 		}
// 		if(lpkg && _alpm_pkg_dup(lpkg, &spkg->oldpkg) != 0) {
// 			ret = -1;
// 			goto cleanup;
// 		}
// 	}
//
// cleanup:
// 	return ret;
// }
//
impl alpm_pkg_t {
	/// Returns the size of the files that will be downloaded to install a
	/// package. returns the size of the download
	pub fn alpm_pkg_download_size(&self) -> i64 {
		unimplemented!();
		// if !(self.infolevel & INFRQ_DSIZE) {
		// 	compute_download_size(newpkg);
		// }
		// return self.download_size;
	}
}
//
// static int endswith(const char *filename, const char *extension)
// {
// 	const char *s = filename + strlen(filename) - strlen(extension);
// 	return strcmp(s, extension) == 0;
// }
//
// /** Applies delta files to create an upgraded package file.
//  *
//  * All intermediate files are deleted, leaving only the starting and
//  * ending package files.
//  *
//  * @param handle the context handle
//  *
//  * @return 0 if all delta files were able to be applied, 1 otherwise.
//  */
// static int apply_deltas(alpm_handle_t *handle)
// {
// 	alpm_list_t *i;
// 	size_t deltas_found = 0;
// 	int ret = 0;
// 	const char *cachedir = _alpm_filecache_setup(handle);
// 	alpm_trans_t *trans = handle->trans;
// 	alpm_event_delta_patch_t event;
//
// 	for(i = trans->add; i; i = i->next) {
// 		alpm_pkg_t *spkg = i->data;
// 		alpm_list_t *delta_path = spkg->delta_path;
// 		alpm_list_t *dlts = NULL;
//
// 		if(!delta_path) {
// 			continue;
// 		}
//
// 		if(!deltas_found) {
// 			/* only show this if we actually have deltas to apply, and it is before
// 			 * the very first one */
// 			event.type = ALPM_EVENT_DELTA_PATCHES_START;
// 			EVENT(handle, &event);
// 			deltas_found = 1;
// 		}
//
// 		for(dlts = delta_path; dlts; dlts = dlts->next) {
// 			alpm_delta_t *d = dlts->data;
// 			char *delta, *from, *to;
// 			char command[PATH_MAX];
// 			size_t len = 0;
//
// 			delta = _alpm_filecache_find(handle, d->delta);
// 			/* the initial package might be in a different cachedir */
// 			if(dlts == delta_path) {
// 				from = _alpm_filecache_find(handle, d->from);
// 			} else {
// 				/* len = cachedir len + from len + '/' + null */
// 				len = strlen(cachedir) + strlen(d->from) + 2;
// 				MALLOC(from, len, free(delta); RET_ERR(handle, ALPM_ERR_MEMORY, 1));
// 				snprintf(from, len, "{}/{}", cachedir, d->from);
// 			}
// 			len = strlen(cachedir) + strlen(d->to) + 2;
// 			MALLOC(to, len, free(delta); free(from); RET_ERR(handle, ALPM_ERR_MEMORY, 1));
// 			snprintf(to, len, "{}/{}", cachedir, d->to);
//
// 			/* build the patch command */
// 			if(endswith(to, ".gz")) {
// 				/* special handling for gzip : we disable timestamp with -n option */
// 				snprintf(command, PATH_MAX, "xdelta3 -d -q -R -c -s {} {} | gzip -n > {}", from, delta, to);
// 			} else {
// 				snprintf(command, PATH_MAX, "xdelta3 -d -q -s {} {} {}", from, delta, to);
// 			}
//
// 			debug!("command: {}\n", command);
//
// 			event.type = ALPM_EVENT_DELTA_PATCH_START;
// 			event.delta = d;
// 			EVENT(handle, &event);
//
// 			int retval = system(command);
// 			if(retval == 0) {
// 				event.type = ALPM_EVENT_DELTA_PATCH_DONE;
// 				EVENT(handle, &event);
//
// 				/* delete the delta file */
// 				unlink(delta);
//
// 				/* Delete the 'from' package but only if it is an intermediate
// 				 * package. The starting 'from' package should be kept, just
// 				 * as if deltas were not used. */
// 				if(dlts != delta_path) {
// 					unlink(from);
// 				}
// 			}
// 			FREE(from);
// 			FREE(to);
// 			FREE(delta);
//
// 			if(retval != 0) {
// 				/* one delta failed for this package, cancel the remaining ones */
// 				event.type = ALPM_EVENT_DELTA_PATCH_FAILED;
// 				EVENT(handle, &event);
// 				handle->pm_errno = ALPM_ERR_DLT_PATCHFAILED;
// 				ret = 1;
// 				break;
// 			}
// 		}
// 	}
// 	if(deltas_found) {
// 		event.type = ALPM_EVENT_DELTA_PATCHES_DONE;
// 		EVENT(handle, &event);
// 	}
//
// 	return ret;
// }
//
// /**
//  * Prompts to delete the file now that we know it is invalid.
//  * @param handle the context handle
//  * @param filename the absolute path of the file to test
//  * @param reason an error code indicating the reason for package invalidity
//  *
//  * @return 1 if file was removed, 0 otherwise
//  */
// static int prompt_to_delete(alpm_handle_t *handle, const char *filepath,
// 		alpm_errno_t reason)
// {
// 	alpm_question_corrupted_t question = {
// 		.type = ALPM_QUESTION_CORRUPTED_PKG,
// 		.remove = 0,
// 		.filepath = filepath,
// 		.reason = reason
// 	};
// 	QUESTION(handle, &question);
// 	if(question.remove) {
// 		unlink(filepath);
// 	}
// 	return question.remove;
// }
//
// static int validate_deltas(alpm_handle_t *handle, alpm_list_t *deltas)
// {
// 	alpm_list_t *i, *errors = NULL;
// 	alpm_event_t event;
//
// 	if(!deltas) {
// 		return 0;
// 	}
//
// 	/* Check integrity of deltas */
// 	event.type = ALPM_EVENT_DELTA_INTEGRITY_START;
// 	EVENT(handle, &event);
// 	for(i = deltas; i; i = i->next) {
// 		alpm_delta_t *d = i->data;
// 		char *filepath = _alpm_filecache_find(handle, d->delta);
//
// 		if(_alpm_test_checksum(filepath, d->delta_md5, ALPM_PKG_VALIDATION_MD5SUM)) {
// 			errors = alpm_list_add(errors, filepath);
// 		} else {
// 			FREE(filepath);
// 		}
// 	}
// 	event.type = ALPM_EVENT_DELTA_INTEGRITY_DONE;
// 	EVENT(handle, &event);
//
// 	if(errors) {
// 		for(i = errors; i; i = i->next) {
// 			char *filepath = i->data;
// 			prompt_to_delete(handle, filepath, ALPM_ERR_DLT_INVALID);
// 			FREE(filepath);
// 		}
// 		alpm_list_free(errors);
// 		handle->pm_errno = ALPM_ERR_DLT_INVALID;
// 		return -1;
// 	}
// 	return 0;
// }
//
// static struct dload_payload *build_payload(alpm_handle_t *handle,
// 		const char *filename, size_t size, alpm_list_t *servers)
// {
// 		struct dload_payload *payload;
//
// 		CALLOC(payload, 1, sizeof(*payload), RET_ERR(handle, ALPM_ERR_MEMORY, NULL));
// 		STRDUP(payload->remote_name, filename, FREE(payload); RET_ERR(handle, ALPM_ERR_MEMORY, NULL));
// 		payload->max_size = size;
// 		payload->servers = servers;
// 		return payload;
// }
//
// static int find_dl_candidates(alpm_db_t *repo, alpm_list_t **files, alpm_list_t **deltas)
// {
// 	alpm_list_t *i;
// 	alpm_handle_t *handle = repo->handle;
//
// 	for(i = handle->trans->add; i; i = i->next) {
// 		alpm_pkg_t *spkg = i->data;
//
// 		if(spkg->origin != ALPM_PKG_FROM_FILE && repo == spkg->origin_data.db) {
// 			alpm_list_t *delta_path = spkg->delta_path;
//
// 			if(!repo->servers) {
// 				handle->pm_errno = ALPM_ERR_SERVER_NONE;
// 				_alpm_log(handle, ALPM_LOG_ERROR, "{}: {}\n",
// 						alpm_strerror(handle->pm_errno), repo->treename);
// 				return 1;
// 			}
//
// 			if(delta_path) {
// 				/* using deltas */
// 				alpm_list_t *dlts;
// 				for(dlts = delta_path; dlts; dlts = dlts->next) {
// 					alpm_delta_t *delta = dlts->data;
// 					if(delta->download_size != 0) {
// 						struct dload_payload *payload = build_payload(
// 								handle, delta->delta, delta->delta_size, repo->servers);
// 						ASSERT(payload, return -1);
// 						*files = alpm_list_add(*files, payload);
// 					}
// 					/* keep a list of all the delta files for md5sums */
// 					*deltas = alpm_list_add(*deltas, delta);
// 				}
//
// 			} else if(spkg->download_size != 0) {
// 				struct dload_payload *payload;
// 				ASSERT(spkg->filename != NULL, RET_ERR(handle, ALPM_ERR_PKG_INVALID_NAME, -1));
// 				payload = build_payload(handle, spkg->filename, spkg->size, repo->servers);
// 				ASSERT(payload, return -1);
// 				*files = alpm_list_add(*files, payload);
// 			}
// 		}
// 	}
//
// 	return 0;
// }
//
// static int download_single_file(alpm_handle_t *handle, struct dload_payload *payload,
// 		const char *cachedir)
// {
// 	alpm_event_pkgdownload_t event = {
// 		.type = ALPM_EVENT_PKGDOWNLOAD_START,
// 		.file = payload->remote_name
// 	};
// 	const alpm_list_t *server;
//
// 	payload->handle = handle;
// 	payload->allow_resume = 1;
//
// 	EVENT(handle, &event);
// 	for(server = payload->servers; server; server = server->next) {
// 		const char *server_url = server->data;
// 		size_t len;
//
// 		/* print server + filename into a buffer */
// 		len = strlen(server_url) + strlen(payload->remote_name) + 2;
// 		MALLOC(payload->fileurl, len, RET_ERR(handle, ALPM_ERR_MEMORY, -1));
// 		snprintf(payload->fileurl, len, "{}/{}", server_url, payload->remote_name);
//
// 		if(_alpm_download(payload, cachedir, NULL, NULL) != -1) {
// 			event.type = ALPM_EVENT_PKGDOWNLOAD_DONE;
// 			EVENT(handle, &event);
// 			return 0;
// 		}
// 		_alpm_dload_payload_reset_for_retry(payload);
// 	}
//
// 	event.type = ALPM_EVENT_PKGDOWNLOAD_FAILED;
// 	EVENT(handle, &event);
// 	return -1;
// }
//
// static int download_files(alpm_handle_t *handle, alpm_list_t **deltas)
// {
// 	const char *cachedir;
// 	alpm_list_t *i, *files = NULL;
// 	int errors = 0;
// 	alpm_event_t event;
//
// 	cachedir = _alpm_filecache_setup(handle);
// 	handle->trans->state = STATE_DOWNLOADING;
//
// 	/* Total progress - figure out the total download size if required to
// 	 * pass to the callback. This function is called once, and it is up to the
// 	 * frontend to compute incremental progress. */
// 	if(handle->totaldlcb) {
// 		off_t total_size = (off_t)0;
// 		/* sum up the download size for each package and store total */
// 		for(i = handle->trans->add; i; i = i->next) {
// 			alpm_pkg_t *spkg = i->data;
// 			total_size += spkg->download_size;
// 		}
// 		handle->totaldlcb(total_size);
// 	}
//
// 	for(i = handle->dbs_sync; i; i = i->next) {
// 		errors += find_dl_candidates(i->data, &files, deltas);
// 	}
//
// 	if(files) {
// 		/* check for necessary disk space for download */
// 		if(handle->checkspace) {
// 			off_t *file_sizes;
// 			size_t idx, num_files;
// 			int ret;
//
// 			debug!("checking available disk space for download\n");
//
// 			num_files = alpm_list_count(files);
// 			CALLOC(file_sizes, num_files, sizeof(off_t), goto finish);
//
// 			for(i = files, idx = 0; i; i = i->next, idx++) {
// 				const struct dload_payload *payload = i->data;
// 				file_sizes[idx] = payload->max_size;
// 			}
//
// 			ret = _alpm_check_downloadspace(handle, cachedir, num_files, file_sizes);
// 			free(file_sizes);
//
// 			if(ret != 0) {
// 				errors++;
// 				goto finish;
// 			}
// 		}
//
// 		event.type = ALPM_EVENT_RETRIEVE_START;
// 		EVENT(handle, &event);
// 		event.type = ALPM_EVENT_RETRIEVE_DONE;
// 		for(i = files; i; i = i->next) {
// 			if(download_single_file(handle, i->data, cachedir) == -1) {
// 				errors++;
// 				event.type = ALPM_EVENT_RETRIEVE_FAILED;
// 				_alpm_log(handle, ALPM_LOG_WARNING, _("failed to retrieve some files\n"));
// 			}
// 		}
// 		EVENT(handle, &event);
// 	}
//
// finish:
// 	if(files) {
// 		alpm_list_free_inner(files, (alpm_list_fn_free)_alpm_dload_payload_reset);
// 		FREELIST(files);
// 	}
//
// 	for(i = handle->trans->add; i; i = i->next) {
// 		alpm_pkg_t *pkg = i->data;
// 		pkg->infolevel &= ~INFRQ_DSIZE;
// 		pkg->download_size = 0;
// 	}
//
// 	/* clear out value to let callback know we are done */
// 	if(handle->totaldlcb) {
// 		handle->totaldlcb(0);
// 	}
//
// 	return errors;
// }
//
// #ifdef HAVE_LIBGPGME
// static int check_keyring(alpm_handle_t *handle)
// {
// 	size_t current = 0, numtargs;
// 	alpm_list_t *i, *errors = NULL;
// 	alpm_event_t event;
//
// 	event.type = ALPM_EVENT_KEYRING_START;
// 	EVENT(handle, &event);
//
// 	numtargs = alpm_list_count(handle->trans->add);
//
// 	for(i = handle->trans->add; i; i = i->next, current++) {
// 		alpm_pkg_t *pkg = i->data;
// 		int level;
//
// 		int percent = (current * 100) / numtargs;
// 		PROGRESS(handle, ALPM_PROGRESS_KEYRING_START, "", percent,
// 				numtargs, current);
//
// 		if(pkg->origin == ALPM_PKG_FROM_FILE) {
// 			continue; /* pkg_load() has been already called, this package is valid */
// 		}
//
// 		level = alpm_db_get_siglevel(alpm_pkg_get_db(pkg));
// 		if((level & ALPM_SIG_PACKAGE) && pkg->base64_sig) {
// 			unsigned char *decoded_sigdata = NULL;
// 			size_t data_len;
// 			int decode_ret = alpm_decode_signature(pkg->base64_sig,
// 					&decoded_sigdata, &data_len);
// 			if(decode_ret == 0) {
// 				alpm_list_t *keys = NULL;
// 				if(alpm_extract_keyid(handle, pkg->name, decoded_sigdata,
// 							data_len, &keys) == 0) {
// 					alpm_list_t *k;
// 					for(k = keys; k; k = k->next) {
// 						char *key = k->data;
// 						if(!alpm_list_find_str(errors, key) &&
// 								_alpm_key_in_keychain(handle, key) == 0) {
// 							errors = alpm_list_add(errors, strdup(key));
// 						}
// 					}
// 					FREELIST(keys);
// 				}
// 				free(decoded_sigdata);
// 			}
// 		}
// 	}
//
// 	PROGRESS(handle, ALPM_PROGRESS_KEYRING_START, "", 100,
// 			numtargs, current);
// 	event.type = ALPM_EVENT_KEYRING_DONE;
// 	EVENT(handle, &event);
//
// 	if(errors) {
// 		event.type = ALPM_EVENT_KEY_DOWNLOAD_START;
// 		EVENT(handle, &event);
// 		int fail = 0;
// 		alpm_list_t *k;
// 		for(k = errors; k; k = k->next) {
// 			char *key = k->data;
// 			if(_alpm_key_import(handle, key) == -1) {
// 				fail = 1;
// 			}
// 		}
// 		event.type = ALPM_EVENT_KEY_DOWNLOAD_DONE;
// 		EVENT(handle, &event);
// 		if(fail) {
// 			_alpm_log(handle, ALPM_LOG_ERROR, _("required key missing from keyring\n"));
// 			return -1;
// 		}
// 	}
//
// 	return 0;
// }
// #endif /* HAVE_LIBGPGME */
//
// static int check_validity(alpm_handle_t *handle,
// 		size_t total, uint64_t total_bytes)
// {
// 	struct validity {
// 		alpm_pkg_t *pkg;
// 		char *path;
// 		alpm_siglist_t *siglist;
// 		int siglevel;
// 		int validation;
// 		alpm_errno_t error;
// 	};
// 	size_t current = 0;
// 	uint64_t current_bytes = 0;
// 	alpm_list_t *i, *errors = NULL;
// 	alpm_event_t event;
//
// 	/* Check integrity of packages */
// 	event.type = ALPM_EVENT_INTEGRITY_START;
// 	EVENT(handle, &event);
//
// 	for(i = handle->trans->add; i; i = i->next, current++) {
// 		struct validity v = { i->data, NULL, NULL, 0, 0, 0 };
// 		int percent = (int)(((double)current_bytes / total_bytes) * 100);
//
// 		PROGRESS(handle, ALPM_PROGRESS_INTEGRITY_START, "", percent,
// 				total, current);
// 		if(v.pkg->origin == ALPM_PKG_FROM_FILE) {
// 			continue; /* pkg_load() has been already called, this package is valid */
// 		}
//
// 		current_bytes += v.pkg->size;
// 		v.path = _alpm_filecache_find(handle, v.pkg->filename);
// 		v.siglevel = alpm_db_get_siglevel(alpm_pkg_get_db(v.pkg));
//
// 		if(_alpm_pkg_validate_internal(handle, v.path, v.pkg,
// 					v.siglevel, &v.siglist, &v.validation) == -1) {
// 			struct validity *invalid;
// 			v.error = handle->pm_errno;
// 			MALLOC(invalid, sizeof(struct validity), return -1);
// 			memcpy(invalid, &v, sizeof(struct validity));
// 			errors = alpm_list_add(errors, invalid);
// 		} else {
// 			alpm_siglist_cleanup(v.siglist);
// 			free(v.siglist);
// 			free(v.path);
// 			v.pkg->validation = v.validation;
// 		}
// 	}
//
// 	PROGRESS(handle, ALPM_PROGRESS_INTEGRITY_START, "", 100,
// 			total, current);
// 	event.type = ALPM_EVENT_INTEGRITY_DONE;
// 	EVENT(handle, &event);
//
// 	if(errors) {
// 		for(i = errors; i; i = i->next) {
// 			struct validity *v = i->data;
// 			if(v->error == ALPM_ERR_PKG_MISSING_SIG) {
// 				_alpm_log(handle, ALPM_LOG_ERROR,
// 						_("{}: missing required signature\n"), v->pkg->name);
// 			} else if(v->error == ALPM_ERR_PKG_INVALID_SIG) {
// 				_alpm_process_siglist(handle, v->pkg->name, v->siglist,
// 						v->siglevel & ALPM_SIG_PACKAGE_OPTIONAL,
// 						v->siglevel & ALPM_SIG_PACKAGE_MARGINAL_OK,
// 						v->siglevel & ALPM_SIG_PACKAGE_UNKNOWN_OK);
// 				prompt_to_delete(handle, v->path, v->error);
// 			} else if(v->error == ALPM_ERR_PKG_INVALID_CHECKSUM) {
// 				prompt_to_delete(handle, v->path, v->error);
// 			}
// 			alpm_siglist_cleanup(v->siglist);
// 			free(v->siglist);
// 			free(v->path);
// 			free(v);
// 		}
// 		alpm_list_free(errors);
//
// 		if(handle->pm_errno == ALPM_ERR_OK) {
// 			RET_ERR(handle, ALPM_ERR_PKG_INVALID, -1);
// 		}
// 		return -1;
// 	}
//
// 	return 0;
// }
//
// static int load_packages(alpm_handle_t *handle, alpm_list_t **data,
// 		size_t total, size_t total_bytes)
// {
// 	size_t current = 0, current_bytes = 0;
// 	int errors = 0;
// 	alpm_list_t *i;
// 	alpm_event_t event;
//
// 	/* load packages from disk now that they are known-valid */
// 	event.type = ALPM_EVENT_LOAD_START;
// 	EVENT(handle, &event);
//
// 	for(i = handle->trans->add; i; i = i->next, current++) {
// 		int error = 0;
// 		alpm_pkg_t *spkg = i->data;
// 		char *filepath;
// 		int percent = (int)(((double)current_bytes / total_bytes) * 100);
//
// 		PROGRESS(handle, ALPM_PROGRESS_LOAD_START, "", percent,
// 				total, current);
// 		if(spkg->origin == ALPM_PKG_FROM_FILE) {
// 			continue; /* pkg_load() has been already called, this package is valid */
// 		}
//
// 		current_bytes += spkg->size;
// 		filepath = _alpm_filecache_find(handle, spkg->filename);
//
// 		/* load the package file and replace pkgcache entry with it in the target list */
// 		/* TODO: alpm_pkg_get_db() will not work on this target anymore */
// 		_alpm_log(handle, ALPM_LOG_DEBUG,
// 				"replacing pkgcache entry with package file for target {}\n",
// 				spkg->name);
// 		alpm_pkg_t *pkgfile =_alpm_pkg_load_internal(handle, filepath, 1);
// 		if(!pkgfile) {
// 			debug!("failed to load pkgfile internal\n");
// 			error = 1;
// 		} else {
// 			if(strcmp(spkg->name, pkgfile->name) != 0) {
// 				_alpm_log(handle, ALPM_LOG_DEBUG,
// 						"internal package name mismatch, expected: '{}', actual: '{}'\n",
// 						spkg->name, pkgfile->name);
// 				error = 1;
// 			}
// 			if(strcmp(spkg->version, pkgfile->version) != 0) {
// 				_alpm_log(handle, ALPM_LOG_DEBUG,
// 						"internal package version mismatch, expected: '{}', actual: '{}'\n",
// 						spkg->version, pkgfile->version);
// 				error = 1;
// 			}
// 		}
// 		if(error != 0) {
// 			errors++;
// 			*data = alpm_list_add(*data, strdup(spkg->filename));
// 			free(filepath);
// 			continue;
// 		}
// 		free(filepath);
// 		/* copy over the install reason */
// 		pkgfile->reason = spkg->reason;
// 		/* copy over validation method */
// 		pkgfile->validation = spkg->validation;
// 		/* transfer oldpkg */
// 		pkgfile->oldpkg = spkg->oldpkg;
// 		spkg->oldpkg = NULL;
// 		i->data = pkgfile;
// 		/* spkg has been removed from the target list, so we can free the
// 		 * sync-specific fields */
// 		_alpm_pkg_free_trans(spkg);
// 	}
//
// 	PROGRESS(handle, ALPM_PROGRESS_LOAD_START, "", 100,
// 			total, current);
// 	event.type = ALPM_EVENT_LOAD_DONE;
// 	EVENT(handle, &event);
//
// 	if(errors) {
// 		if(handle->pm_errno == ALPM_ERR_OK) {
// 			RET_ERR(handle, ALPM_ERR_PKG_INVALID, -1);
// 		}
// 		return -1;
// 	}
//
// 	return 0;
// }
//
// int _alpm_sync_load(alpm_handle_t *handle, alpm_list_t **data)
// {
// 	alpm_list_t *i, *deltas = NULL;
// 	size_t total = 0;
// 	uint64_t total_bytes = 0;
// 	alpm_trans_t *trans = handle->trans;
//
// 	if(download_files(handle, &deltas)) {
// 		alpm_list_free(deltas);
// 		return -1;
// 	}
//
// 	if(validate_deltas(handle, deltas)) {
// 		alpm_list_free(deltas);
// 		return -1;
// 	}
// 	alpm_list_free(deltas);
//
// 	/* Use the deltas to generate the packages */
// 	if(apply_deltas(handle)) {
// 		return -1;
// 	}
//
// #ifdef HAVE_LIBGPGME
// 	/* make sure all required signatures are in keyring */
// 	if(check_keyring(handle)) {
// 		return -1;
// 	}
// #endif
//
// 	/* get the total size of all packages so we can adjust the progress bar more
// 	 * realistically if there are small and huge packages involved */
// 	for(i = trans->add; i; i = i->next) {
// 		alpm_pkg_t *spkg = i->data;
// 		if(spkg->origin != ALPM_PKG_FROM_FILE) {
// 			total_bytes += spkg->size;
// 		}
// 		total++;
// 	}
// 	/* this can only happen maliciously */
// 	total_bytes = total_bytes ? total_bytes : 1;
//
// 	if(check_validity(handle, total, total_bytes) != 0) {
// 		return -1;
// 	}
//
// 	if(trans->flags & ALPM_TRANS_FLAG_DOWNLOADONLY) {
// 		return 0;
// 	}
//
// 	if(load_packages(handle, data, total, total_bytes)) {
// 		return -1;
// 	}
//
// 	return 0;
// }
//
// int _alpm_sync_check(alpm_handle_t *handle, alpm_list_t **data)
// {
// 	alpm_trans_t *trans = handle->trans;
// 	alpm_event_t event;
//
// 	/* fileconflict check */
// 	if(!(trans->flags & ALPM_TRANS_FLAG_DBONLY)) {
// 		event.type = ALPM_EVENT_FILECONFLICTS_START;
// 		EVENT(handle, &event);
//
// 		debug!("looking for file conflicts\n");
// 		alpm_list_t *conflict = _alpm_db_find_fileconflicts(handle,
// 				trans->add, trans->remove);
// 		if(conflict) {
// 			if(data) {
// 				*data = conflict;
// 			} else {
// 				alpm_list_free_inner(conflict,
// 						(alpm_list_fn_free)alpm_fileconflict_free);
// 				alpm_list_free(conflict);
// 			}
// 			RET_ERR(handle, ALPM_ERR_FILE_CONFLICTS, -1);
// 		}
//
// 		event.type = ALPM_EVENT_FILECONFLICTS_DONE;
// 		EVENT(handle, &event);
// 	}
//
// 	/* check available disk space */
// 	if(handle->checkspace && !(trans->flags & ALPM_TRANS_FLAG_DBONLY)) {
// 		event.type = ALPM_EVENT_DISKSPACE_START;
// 		EVENT(handle, &event);
//
// 		debug!("checking available disk space\n");
// 		if(_alpm_check_diskspace(handle) == -1) {
// 			_alpm_log(handle, ALPM_LOG_ERROR, _("not enough free disk space\n"));
// 			return -1;
// 		}
//
// 		event.type = ALPM_EVENT_DISKSPACE_DONE;
// 		EVENT(handle, &event);
// 	}
//
// 	return 0;
// }
//
// int _alpm_sync_commit(alpm_handle_t *handle)
// {
// 	alpm_trans_t *trans = handle->trans;
//
// 	/* remove conflicting and to-be-replaced packages */
// 	if(trans->remove) {
// 		_alpm_log(handle, ALPM_LOG_DEBUG,
// 				"removing conflicting and to-be-replaced packages\n");
// 		/* we want the frontend to be aware of commit details */
// 		if(_alpm_remove_packages(handle, 0) == -1) {
// 			_alpm_log(handle, ALPM_LOG_ERROR,
// 					_("could not commit removal transaction\n"));
// 			return -1;
// 		}
// 	}
//
// 	/* install targets */
// 	debug!("installing packages\n");
// 	if(_alpm_upgrade_packages(handle) == -1) {
// 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not commit transaction\n"));
// 		return -1;
// 	}
//
// 	return 0;
// }
//
// /* vim: set noet: */
