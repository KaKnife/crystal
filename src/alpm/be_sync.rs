/*
 *  be_sync.c : backend for sync databases
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

// /* libarchive */
// #include <archive.h>
// #include <archive_entry.h>

use super::{Database, DownloadPayload, Error, Handle};
use std::fs;
use Result;

/** Update a package database
 *
 * An update of the package database \a db will be attempted. Unless
 * \a force is true, the update will only be performed if the remote
 * database was modified since the last update.
 *
 * This operation requires a database lock, and will return an applicable error
 * if the lock could not be obtained.
 *
 * Example:
 * @code
 * list_t *syncs = get_syncdbs();
 * for(i = syncs; i; i = list_next(i)) {
 *     Database *db = list_getdata(i);
 *     result = db_update(0, db);
 *
 *     if(result < 0) {
 *	       printf("Unable to update database: %s\n", strerrorlast());
 *     } else if(result == 1) {
 *         printf("Database already up to date\n");
 *     } else {
 *         printf("Database updated\n");
 *     }
 * }
 * @endcode
 *
 * @ingroup databases
 * @note After a successful update, the \link db_get_pkgcache()
 * package cache \endlink will be invalidated
 * @param force if true, then forces the update, otherwise update only in case
 * the database isn't up to date
 * @param db pointer to the package database to update
 * @return 0 on success, -1 on error (pm_errno is set accordingly), 1 if up to
 * to date
 */
pub fn db_update<'a>(mut force: bool, db: &mut Database, handle: &'a mut Handle) -> Result<i8> {
    let syncpath;
    let mut updated = false;
    let mut ret = -1;
    // 	mode_t oldmask;
    let siglevel;

    if !db.get_usage().sync {
        return Ok(0);
    }

    syncpath = handle.get_sync_dir()?;

    /* force update of invalid databases to fix potential mismatched database/signature */
    if db.status.invalid {
        force = true;
    }

    /* make sure we have a sane umask */
    // 	oldmask = umask(0022);

    siglevel = db.get_siglevel();

    /* attempt to grab a lock */
    if handle.handle_lock().is_err() {
        return Err(Error::HandleLock);
    }
    {
        let dbext = handle.get_dbext();
        for server in db.get_servers() {
            let tmp;
            let mut final_db_url: String = String::new();
            let mut payload: DownloadPayload = DownloadPayload::new(handle.disable_dl_timeout());
            let mut sig_ret = 0;

            /* set hard upper limit of 25MiB */
            payload.max_size = 25 * 1024 * 1024;

            /* print server + filename into a buffer */
            payload.fileurl = format!("{}/{}{}", server, db.get_name(), dbext);
            payload.force = force;
            payload.unlink_on_fail = true;

            tmp = payload.download(&syncpath)?;
            ret = tmp.2;
            final_db_url = tmp.1;
            payload.reset();
            updated = updated || ret == 0;

            if ret != -1 && updated && siglevel.database {
                /* an existing sig file is no good at this point */

                let dbpath = &db.path().ok();
                let sigpath = match handle.sigpath(dbpath) {
                    Some(s) => s,
                    None => {
                        ret = -1;
                        break;
                    }
                };
                fs::remove_file(sigpath)?;

                /* check if the final URL from internal downloader looks reasonable */
                if final_db_url != "" {
                    if final_db_url.len() < 3 || !final_db_url.ends_with(dbext) {
                        final_db_url = String::new();
                    }
                }

                /* if we downloaded a DB, we want the .sig from the same server */
                if final_db_url != "" {
                    payload.fileurl = format!("{}.sig", final_db_url);
                } else {
                    payload.fileurl = format!("{}/{}{}.sig", server, db.get_name(), dbext);
                }

                payload.force = true;
                payload.errors_ok = siglevel.database_optional;

                /* set hard upper limit of 16KiB */
                payload.max_size = 16 * 1024;

                let tmp = payload.download(&syncpath)?;
                sig_ret = tmp.2;
                /* errors_ok suppresses error messages, but not the return code */
                sig_ret = if payload.errors_ok { 0 } else { sig_ret };
                payload.reset();
            }
            if ret != -1 && sig_ret != -1 {
                debug!("TMP: {}", ret);
                break;
            }
        }
    }
    if updated {
        /* Cache needs to be rebuilt */
        db.free_pkgcache();

        /* clear all status flags regarding validity/existence */
        db.status.valid = false;
        db.status.invalid = false;
        db.status.exists = false;
        db.status.missing = false;

        /* if the download failed skip validation to preserve the download error */
        if ret != -1 {
            db.sync_db_validate(handle)?;
        }
    }

    if ret == -1 {
        /* pm_errno was set by the download code */
        // _debug!("failed to sync db: {}",
        // 		strerror(handle->pm_errno));
    }

    handle.handle_unlock()?;
    // umask(oldmask);
    if ret == 1 || ret == 0 {
        Ok(ret as i8)
    } else {
        unimplemented!();
    }
    // return ret as i8;
}

// /* Forward decl so I don't reorganize the whole file right now */
// static int sync_db_read(Database *db, struct archive *archive,
// 		struct archive_entry *entry, pkg_t **likely_pkg);

// /* This function doesn't work as well as one might think, as size of database
//  * entries varies considerably. Adding signatures nearly doubles the size of a
//  * single entry; deltas also can make for large variations in size. These
//  * current values are heavily influenced by Arch Linux; databases with no
//  * deltas and a single signature per package. */
// static size_t estimate_package_count(struct stat *st, struct archive *archive)
// {
// 	int per_package;
//
// 	switch(_archive_filter_code(archive)) {
// 		case ARCHIVE_COMPRESSION_NONE:
// 			per_package = 3015;
// 			break;
// 		case ARCHIVE_COMPRESSION_GZIP:
// 		case ARCHIVE_COMPRESSION_COMPRESS:
// 			per_package = 464;
// 			break;
// 		case ARCHIVE_COMPRESSION_BZIP2:
// 			per_package = 394;
// 			break;
// 		case ARCHIVE_COMPRESSION_LZMA:
// 		case ARCHIVE_COMPRESSION_XZ:
// 			per_package = 400;
// 			break;
// #ifdef ARCHIVE_COMPRESSION_UU
// 		case ARCHIVE_COMPRESSION_UU:
// 			per_package = 3015 * 4 / 3;
// 			break;
// #endif
// 		default:
// 			/* assume it is at least somewhat compressed */
// 			per_package = 500;
// 	}
//
// 	return (size_t)((st->st_size / per_package) + 1);
// }

// /* This function validates %FILENAME%. filename must be between 3 and
//  * PATH_MAX characters and cannot be contain a path */
// static int _validate_filename(Database *db, const char *pkgname,
// 		const char *filename)
// {
// 	size_t len = strlen(filename);
//
// 	if(filename[0] == '.') {
// 		errno = EINVAL;
// 		_log(db->handle, ALPM_LOG_ERROR, _("%s database is inconsistent: filename "
// 					"of package %s is illegal\n"), db->treename, pkgname);
// 		return -1;
// 	} else if(memchr(filename, '/', len) != NULL) {
// 		errno = EINVAL;
// 		_log(db->handle, ALPM_LOG_ERROR, _("%s database is inconsistent: filename "
// 					"of package %s is illegal\n"), db->treename, pkgname);
// 		return -1;
// 	} else if(len > PATH_MAX) {
// 		errno = EINVAL;
// 		_log(db->handle, ALPM_LOG_ERROR, _("%s database is inconsistent: filename "
// 					"of package %s is too long\n"), db->treename, pkgname);
// 		return -1;
// 	}
//
// 	return 0;
// }

// #define READ_NEXT() do { \
// 	if(_archive_fgets(archive, &buf) != ARCHIVE_OK) goto error; \
// 	line = buf.line; \
// 	_strip_newline(line, buf.real_line_size); \
// } while(0)

// #define READ_AND_STORE(f) do { \
// 	READ_NEXT(); \
// 	STRDUP(f, line, goto error); \
// } while(0)

// #define READ_AND_STORE_ALL(f) do { \
// 	char *linedup; \
// 	if(_archive_fgets(archive, &buf) != ARCHIVE_OK) goto error; \
// 	if(_strip_newline(buf.line, buf.real_line_size) == 0) break; \
// 	STRDUP(linedup, buf.line, goto error); \
// 	f = list_add(f, linedup); \
// } while(1) /* note the while(1) and not (0) */

// #define READ_AND_SPLITDEP(f) do { \
// 	if(_archive_fgets(archive, &buf) != ARCHIVE_OK) goto error; \
// 	if(_strip_newline(buf.line, buf.real_line_size) == 0) break; \
// 	f = list_add(f, dep_from_string(line)); \
// } while(1) /* note the while(1) and not (0) */

// struct db_operations sync_db_ops = {
// 	.validate         = sync_db_validate,
// 	.populate         = sync_db_populate,
// 	.unregister       = _db_unregister,
// };
