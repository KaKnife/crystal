use super::*;
/*
 *  add.c
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

// #include <stdlib.h>
// #include <errno.h>
// #include <string.h>
// #include <limits.h>
// #include <fcntl.h>
// #include <sys/types.h>
// #include <sys/stat.h>
// #include <unistd.h>
// #include <stdint.h> /* int64_t */
//
// /* libarchive */
// #include <archive.h>
// #include <archive_entry.h>
//
// /* libalpm */
// #include "add.h"
// #include "alpm.h"
// #include "alpm_list.h"
// #include "handle.h"
// #include "libarchive-compat.h"
// #include "trans.h"
// #include "util.h"
// #include "log.h"
// #include "backup.h"
// #include "package.h"
// #include "db.h"
// #include "remove.h"
// #include "handle.h"

pub struct archive {}
pub struct archive_entry {}

impl alpm_handle_t {
    /// Add a package to the transaction.
    pub fn alpm_add_pkg(&mut self, pkg: &mut alpm_pkg_t) -> Result<()> {
        let trans: &mut alpm_trans_t = &mut self.trans;
        let pkgname: &String = &pkg.name;
        let pkgver: String = pkg.version.clone();

        debug!("adding package '{}'", pkgname);

        if alpm_pkg_find(&trans.add, &pkgname).is_some() {
            return Err(alpm_errno_t::ALPM_ERR_TRANS_DUP_TARGET);
        }

        match self.db_local._alpm_db_get_pkgfromcache(pkgname) {
            Some(local) => {
                let localpkgname: &String = &local.name;
                let localpkgver: &String = &local.version;
                let cmp: i8 = pkg._alpm_pkg_compare_versions(&local);

                if cmp == 0 {
                    if trans.flags.NEEDED {
                        /* with the NEEDED flag, packages up to date are not reinstalled */
                        warn!(
                            "{}-{} is up to date -- skipping\n",
                            localpkgname, localpkgver
                        );
                        return Ok(());
                    } else if !trans.flags.DOWNLOADONLY {
                        warn!(
                            "{}-{} is up to date -- reinstalling\n",
                            localpkgname, localpkgver
                        );
                    }
                } else if cmp < 0 && !trans.flags.DOWNLOADONLY {
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
        pkg.reason = alpm_pkgreason_t::ALPM_PKG_REASON_EXPLICIT;
        debug!(
            "adding package {}-{} to the transaction add list\n",
            pkgname, pkgver
        );
        trans.add.push(pkg.clone());
        Ok(())
    }

    pub fn perform_extraction(
        &self,
        archive: &archive,
        entry: &archive_entry,
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
                &alpm_transstate_t::STATE_INTERRUPTED => {
                    return ret;
                }
                _ => {}
            }

            if self.commit_single_pkg(&newpkg, pkg_current, pkg_count) != 0 {
                /* something screwed up on the commit, abort the trans */
                self.trans.state = alpm_transstate_t::STATE_INTERRUPTED;
                /* running ldconfig at this point could possibly screw system */
                skip_ldconfig = true;
                ret = Err(alpm_errno_t::ALPM_ERR_TRANS_ABORT);
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
                // alpm_logaction(handle, ALPM_CALLER_PREFIX,
                // "error: could not rename {} to {} ({})\n", src, dest, strerror(errno));
                return 1;
            }
            Ok(()) => {}
        }
        return 0;
    }

    pub fn extract_db_file(
        &self,
        archive: &archive,
        entry: &archive_entry,
        newpkg: &alpm_pkg_t,
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
        archive: &archive,
        entry: &archive_entry,
        newpkg: &alpm_pkg_t,
        oldpkg: &alpm_pkg_t,
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

    pub fn commit_single_pkg(
        &self,
        newpkg: &alpm_pkg_t,
        pkg_current: usize,
        pkg_count: usize,
    ) -> i32 {
        unimplemented!();
        // 	int i, ret = 0, errors = 0;
        // 	int is_upgrade = 0;
        let oldpkg: &Option<alpm_pkg_t>;
        // 	alpm_pkg_t *oldpkg = NULL;
        // 	alpm_db_t *db = handle->db_local;
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
        // 		newpkg->reason = ALPM_PKG_REASON_DEPEND;
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
}
