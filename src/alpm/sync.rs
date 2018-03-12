/*
 *  sync.c
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
 *  Copyright (c) 2005 by Christian Hamar <krics@linuxforum.hu>
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
use {Database, Error, Handle, Package};

/// Find group members across a list of databases.
/// If a member exists in several databases, only the first database is used.
/// IgnorePkg is also handled.
/// @param dbs the list of Database
/// @param name the name of the group
/// @return the list of Package * (caller is responsible for list_free)
pub fn find_group_pkgs<'a>(dbs: Vec<Database>, name: &String) -> Vec<Package> {
    unimplemented!();
    // 	list_t *i, *j, *pkgs = NULL, *ignorelist = NULL;
    //
    // 	for(i = dbs; i; i = i.next) {
    // 		Database *db = i.data;
    // 		group_t *grp = db_get_group(db, name);
    //
    // 		if(!grp) {
    // 			continue;
    // 		}
    //
    // 		for(j = grp.packages; j; j = j.next) {
    // 			Package *pkg = j.data;
    //
    // 			if(pkg_find(ignorelist, pkg.name)) {
    // 				continue;
    // 			}
    // 			if(pkg_should_ignore(db.handle, pkg)) {
    // 				question_install_ignorePackage question = {
    // 					.type = ALPM_QUESTION_INSTALL_IGNOREPKG,
    // 					.install = 0,
    // 					.pkg = pkg
    // 				};
    // 				ignorelist = list_add(ignorelist, pkg);
    // 				QUESTION(db.handle, &question);
    // 				if(!question.install) {
    // 					continue;
    // 				}
    // 			}
    // 			if(!pkg_find(pkgs, pkg.name)) {
    // 				pkgs = list_add(pkgs, pkg);
    // 			}
    // 		}
    // 	}
    // 	list_free(ignorelist);
    // 	return pkgs;
}

// fn endswith(filename: &String, extension: &String) -> bool
// {
// 	const char *s = filename + strlen(filename) - strlen(extension);
// 	return strcmp(s, extension) == 0;
// }

/// Applies delta files to create an upgraded package file.
///
/// All intermediate files are deleted, leaving only the starting and
/// ending package files.
///
/// returns 0 if all delta files were able to be applied, 1 otherwise.
fn apply_deltas(handle: &Handle) -> i32 {
    unimplemented!();
    // 	list_t *i;
    // 	size_t deltas_found = 0;
    // 	int ret = 0;
    // 	const char *cachedir = _filecache_setup(handle);
    // 	trans_t *trans = handle->trans;
    // 	event_delta_patch_t event;
    //
    // 	for(i = trans->add; i; i = i->next) {
    // 		Package *spkg = i->data;
    // 		list_t *delta_path = spkg->delta_path;
    // 		list_t *dlts = NULL;
    //
    // 		if(!delta_path) {
    // 			continue;
    // 		}
    //
    // 		if(!deltas_found) {
    // 			/* only show this if we actually have deltas to apply, and it is before
    // 			 * the very first one */
    // 			info!("applying deltas...");
    // 			deltas_found = 1;
    // 		}
    //
    // 		for(dlts = delta_path; dlts; dlts = dlts->next) {
    // 			delta_t *d = dlts->data;
    // 			char *delta, *from, *to;
    // 			char command[PATH_MAX];
    // 			size_t len = 0;
    //
    // 			delta = _filecache_find(handle, d->delta);
    // 			/* the initial package might be in a different cachedir */
    // 			if(dlts == delta_path) {
    // 				from = _filecache_find(handle, d->from);
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
    //
    // 			if(retval != 0) {
    // 				/* one delta failed for this package, cancel the remaining ones */
    // 				info!("failed.");
    // 				handle->pm_errno = ALPM_ERR_DLT_PATCHFAILED;
    // 				ret = 1;
    // 				break;
    // 			}
    // 		}
    // 	}
    //
    // 	return ret;
}

/**
 * Prompts to delete the file now that we know it is invalid.
 * @param handle the context handle
 * @param filename the absolute path of the file to test
 * @param reason an error code indicating the reason for package invalidity
 *
 * @return 1 if file was removed, 0 otherwise
 */
fn prompt_to_delete(handle: &Handle, filepath: &String, reason: Error) -> i32 {
    unimplemented!();
    // 	question_corrupted_t question = {
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
}

// static int validate_deltas(Handle *handle, list_t *deltas)
// {
// 	list_t *i, *errors = NULL;
// 	event_t event;
//
// 	if(!deltas) {
// 		return 0;
// 	}
//
// 	/* Check integrity of deltas */
// 	info!("checking delta integrity...");
// 	for(i = deltas; i; i = i->next) {
// 		delta_t *d = i->data;
// 		char *filepath = _filecache_find(handle, d->delta);
//
// 		if(_test_checksum(filepath, d->delta_md5, ALPM_PKG_VALIDATION_MD5SUM)) {
// 			errors = list_add(errors, filepath);
// 		} else {
// 			FREE(filepath);
// 		}
// 	}
//
// 	if(errors) {
// 		for(i = errors; i; i = i->next) {
// 			char *filepath = i->data;
// 			prompt_to_delete(handle, filepath, ALPM_ERR_DLT_INVALID);
// 			FREE(filepath);
// 		}
// 		list_free(errors);
// 		handle->pm_errno = ALPM_ERR_DLT_INVALID;
// 		return -1;
// 	}
// 	return 0;
// }

// static struct dload_payload *build_payload(Handle *handle,
// 		const char *filename, size_t size, list_t *servers)
// {
// 		struct dload_payload *payload;
//
// 		CALLOC(payload, 1, sizeof(*payload), RET_ERR(handle, ALPM_ERR_MEMORY, NULL));
// 		STRDUP(payload->remote_name, filename, FREE(payload); RET_ERR(handle, ALPM_ERR_MEMORY, NULL));
// 		payload->max_size = size;
// 		payload->servers = servers;
// 		return payload;
// }

// static int find_dl_candidates(Database *repo, list_t **files, list_t **deltas)
// {
// 	list_t *i;
// 	Handle *handle = repo->handle;
//
// 	for(i = handle->trans->add; i; i = i->next) {
// 		Package *spkg = i->data;
//
// 		if(spkg->origin != ALPM_PKG_FROM_FILE && repo == spkg->origin_data.db) {
// 			list_t *delta_path = spkg->delta_path;
//
// 			if(!repo->servers) {
// 				handle->pm_errno = ALPM_ERR_SERVER_NONE;
// 				_log(handle, ALPM_LOG_ERROR, "{}: {}\n",
// 						strerror(handle->pm_errno), repo->treename);
// 				return 1;
// 			}
//
// 			if(delta_path) {
// 				/* using deltas */
// 				list_t *dlts;
// 				for(dlts = delta_path; dlts; dlts = dlts->next) {
// 					delta_t *delta = dlts->data;
// 					if(delta->download_size != 0) {
// 						struct dload_payload *payload = build_payload(
// 								handle, delta->delta, delta->delta_size, repo->servers);
// 						ASSERT(payload, return -1);
// 						*files = list_add(*files, payload);
// 					}
// 					/* keep a list of all the delta files for md5sums */
// 					*deltas = list_add(*deltas, delta);
// 				}
//
// 			} else if(spkg->download_size != 0) {
// 				struct dload_payload *payload;
// 				ASSERT(spkg->filename != NULL, RET_ERR(handle, ALPM_ERR_PKG_INVALID_NAME, -1));
// 				payload = build_payload(handle, spkg->filename, spkg->size, repo->servers);
// 				ASSERT(payload, return -1);
// 				*files = list_add(*files, payload);
// 			}
// 		}
// 	}
//
// 	return 0;
// }

// static int download_single_file(Handle *handle, struct dload_payload *payload,
// 		const char *cachedir)
// {
// 	event_pkgdownload_t event = {
// 		.type = ALPM_EVENT_PKGDOWNLOAD_START,
// 		.file = payload->remote_name
// 	};
// 	const list_t *server;
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
// 		if(_download(payload, cachedir, NULL, NULL) != -1) {
// 			return 0;
// 		}
// 		_dload_payload_reset_for_retry(payload);
// 	}
//
// 	return -1;
// }

// static int download_files(Handle *handle, list_t **deltas)
// {
// 	const char *cachedir;
// 	list_t *i, *files = NULL;
// 	int errors = 0;
// 	event_t event;
//
// 	cachedir = _filecache_setup(handle);
// 	handle->trans->state = STATE_DOWNLOADING;
//
// 	/* Total progress - figure out the total download size if required to
// 	 * pass to the callback. This function is called once, and it is up to the
// 	 * frontend to compute incremental progress. */
// 	if(handle->totaldlcb) {
// 		off_t total_size = (off_t)0;
// 		/* sum up the download size for each package and store total */
// 		for(i = handle->trans->add; i; i = i->next) {
// 			Package *spkg = i->data;
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
// 			num_files = list_count(files);
// 			CALLOC(file_sizes, num_files, sizeof(off_t), goto finish);
//
// 			for(i = files, idx = 0; i; i = i->next, idx++) {
// 				const struct dload_payload *payload = i->data;
// 				file_sizes[idx] = payload->max_size;
// 			}
//
// 			ret = _check_downloadspace(handle, cachedir, num_files, file_sizes);
// 			free(file_sizes);
//
// 			if(ret != 0) {
// 				errors++;
// 				goto finish;
// 			}
// 		}
//
//      info!("Retrieving packages...");
// 		for(i = files; i; i = i->next) {
// 			if(download_single_file(handle, i->data, cachedir) == -1) {
// 				errors++;
// 				_log(handle, ALPM_LOG_WARNING, _("failed to retrieve some files\n"));
// 			}
// 		}
// 	}
//
// finish:
// 	if(files) {
// 		list_free_inner(files, (list_fn_free)_dload_payload_reset);
// 		FREELIST(files);
// 	}
//
// 	for(i = handle->trans->add; i; i = i->next) {
// 		Package *pkg = i->data;
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

// #ifdef HAVE_LIBGPGME
// static int check_keyring(Handle *handle)
// {
// 	size_t current = 0, numtargs;
// 	list_t *i, *errors = NULL;
// 	event_t event;
//
// 	event.type = ALPM_EVENT_KEYRING_START;
// 	EVENT(handle, &event);
//
// 	numtargs = list_count(handle->trans->add);
//
// 	for(i = handle->trans->add; i; i = i->next, current++) {
// 		Package *pkg = i->data;
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
// 		level = db_get_siglevel(pkg_get_db(pkg));
// 		if((level & ALPM_SIG_PACKAGE) && pkg->base64_sig) {
// 			unsigned char *decoded_sigdata = NULL;
// 			size_t data_len;
// 			int decode_ret = decode_signature(pkg->base64_sig,
// 					&decoded_sigdata, &data_len);
// 			if(decode_ret == 0) {
// 				list_t *keys = NULL;
// 				if(extract_keyid(handle, pkg->name, decoded_sigdata,
// 							data_len, &keys) == 0) {
// 					list_t *k;
// 					for(k = keys; k; k = k->next) {
// 						char *key = k->data;
// 						if(!list_find_str(errors, key) &&
// 								_key_in_keychain(handle, key) == 0) {
// 							errors = list_add(errors, strdup(key));
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
// 		list_t *k;
// 		for(k = errors; k; k = k->next) {
// 			char *key = k->data;
// 			if(_key_import(handle, key) == -1) {
// 				fail = 1;
// 			}
// 		}
// 		event.type = ALPM_EVENT_KEY_DOWNLOAD_DONE;
// 		EVENT(handle, &event);
// 		if(fail) {
// 			_log(handle, ALPM_LOG_ERROR, _("required key missing from keyring\n"));
// 			return -1;
// 		}
// 	}
//
// 	return 0;
// }
// #endif /* HAVE_LIBGPGME */

// static int check_validity(Handle *handle,
// 		size_t total, uint64_t total_bytes)
// {
// 	struct validity {
// 		Package *pkg;
// 		char *path;
// 		siglist_t *siglist;
// 		int siglevel;
// 		int validation;
// 		errno_t error;
// 	};
// 	size_t current = 0;
// 	uint64_t current_bytes = 0;
// 	list_t *i, *errors = NULL;
// 	event_t event;
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
// 		v.path = _filecache_find(handle, v.pkg->filename);
// 		v.siglevel = db_get_siglevel(pkg_get_db(v.pkg));
//
// 		if(_pkg_validate_internal(handle, v.path, v.pkg,
// 					v.siglevel, &v.siglist, &v.validation) == -1) {
// 			struct validity *invalid;
// 			v.error = handle->pm_errno;
// 			MALLOC(invalid, sizeof(struct validity), return -1);
// 			memcpy(invalid, &v, sizeof(struct validity));
// 			errors = list_add(errors, invalid);
// 		} else {
// 			siglist_cleanup(v.siglist);
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
// 				_log(handle, ALPM_LOG_ERROR,
// 						_("{}: missing required signature\n"), v->pkg->name);
// 			} else if(v->error == ALPM_ERR_PKG_INVALID_SIG) {
// 				_process_siglist(handle, v->pkg->name, v->siglist,
// 						v->siglevel & ALPM_SIG_PACKAGE_OPTIONAL,
// 						v->siglevel & ALPM_SIG_PACKAGE_MARGINAL_OK,
// 						v->siglevel & ALPM_SIG_PACKAGE_UNKNOWN_OK);
// 				prompt_to_delete(handle, v->path, v->error);
// 			} else if(v->error == ALPM_ERR_PKG_INVALID_CHECKSUM) {
// 				prompt_to_delete(handle, v->path, v->error);
// 			}
// 			siglist_cleanup(v->siglist);
// 			free(v->siglist);
// 			free(v->path);
// 			free(v);
// 		}
// 		list_free(errors);
//
// 		if(handle->pm_errno == ALPM_ERR_OK) {
// 			RET_ERR(handle, ALPM_ERR_PKG_INVALID, -1);
// 		}
// 		return -1;
// 	}
//
// 	return 0;
// }

// static int load_packages(Handle *handle, list_t **data,
// 		size_t total, size_t total_bytes)
// {
// 	size_t current = 0, current_bytes = 0;
// 	int errors = 0;
// 	list_t *i;
// 	event_t event;
//
// 	/* load packages from disk now that they are known-valid */
// 	event.type = ALPM_EVENT_LOAD_START;
// 	EVENT(handle, &event);
//
// 	for(i = handle->trans->add; i; i = i->next, current++) {
// 		int error = 0;
// 		Package *spkg = i->data;
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
// 		filepath = _filecache_find(handle, spkg->filename);
//
// 		/* load the package file and replace pkgcache entry with it in the target list */
// 		/* TODO: pkg_get_db() will not work on this target anymore */
// 		_log(handle, ALPM_LOG_DEBUG,
// 				"replacing pkgcache entry with package file for target {}\n",
// 				spkg->name);
// 		Package *pkgfile =_pkg_load_internal(handle, filepath, 1);
// 		if(!pkgfile) {
// 			debug!("failed to load pkgfile internal\n");
// 			error = 1;
// 		} else {
// 			if(strcmp(spkg->name, pkgfile->name) != 0) {
// 				_log(handle, ALPM_LOG_DEBUG,
// 						"internal package name mismatch, expected: '{}', actual: '{}'\n",
// 						spkg->name, pkgfile->name);
// 				error = 1;
// 			}
// 			if(strcmp(spkg->version, pkgfile->version) != 0) {
// 				_log(handle, ALPM_LOG_DEBUG,
// 						"internal package version mismatch, expected: '{}', actual: '{}'\n",
// 						spkg->version, pkgfile->version);
// 				error = 1;
// 			}
// 		}
// 		if(error != 0) {
// 			errors++;
// 			*data = list_add(*data, strdup(spkg->filename));
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
// 		_pkg_free_trans(spkg);
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

// int _sync_load(Handle *handle, list_t **data)
// {
// 	list_t *i, *deltas = NULL;
// 	size_t total = 0;
// 	uint64_t total_bytes = 0;
// 	trans_t *trans = handle->trans;
//
// 	if(download_files(handle, &deltas)) {
// 		list_free(deltas);
// 		return -1;
// 	}
//
// 	if(validate_deltas(handle, deltas)) {
// 		list_free(deltas);
// 		return -1;
// 	}
// 	list_free(deltas);
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
// 		Package *spkg = i->data;
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

// int _sync_check(Handle *handle, list_t **data)
// {
// 	trans_t *trans = handle->trans;
// 	event_t event;
//
// 	/* fileconflict check */
// 	if(!(trans->flags & ALPM_TRANS_FLAG_DBONLY)) {
// 		event.type = ALPM_EVENT_FILECONFLICTS_START;
// 		EVENT(handle, &event);
//
// 		debug!("looking for file conflicts\n");
// 		list_t *conflict = _db_find_fileconflicts(handle,
// 				trans->add, trans->remove);
// 		if(conflict) {
// 			if(data) {
// 				*data = conflict;
// 			} else {
// 				list_free_inner(conflict,
// 						(list_fn_free)fileconflict_free);
// 				list_free(conflict);
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
// 		if(_check_diskspace(handle) == -1) {
// 			_log(handle, ALPM_LOG_ERROR, _("not enough free disk space\n"));
// 			return -1;
// 		}
//
// 		event.type = ALPM_EVENT_DISKSPACE_DONE;
// 		EVENT(handle, &event);
// 	}
//
// 	return 0;
// }

fn _sync_commit(handle: &mut Handle) -> i32 {
    /* remove conflicting and to-be-replaced packages */
    if !handle.trans.remove.is_empty() {
        debug!("removing conflicting and to-be-replaced packages");
        /* we want the frontend to be aware of commit details */
        if handle.remove_packages(0) == -1 {
            error!("could not commit removal transaction");
            return -1;
        }
    }

    /* install targets */
    debug!("installing packages");
    if handle.upgrade_packages().is_err() {
        error!("could not commit transaction");
        return -1;
    }

    return 0;
}
