use super::*;
/*
 *  be_local.c : backend for the local database
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

// #include <unistd.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <errno.h>
// #include <string.h>
// #include <stdint.h> /* intmax_t */
// #include <sys/stat.h>
// #include <dirent.h>
// #include <limits.h> /* PATH_MAX */
//
// /* libarchive */
// #include <archive.h>
// #include <archive_entry.h>
//
// /* libalpm */
// #include "db.h"
// #include "alpm_list.h"
// #include "libarchive-compat.h"
// #include "log.h"
// #include "util.h"
// #include "alpm.h"
// #include "handle.h"
// #include "package.h"
// #include "deps.h"
// #include "filelist.h"

// /* local database format version */
const ALPM_LOCAL_DB_VERSION: usize = 9;
//
// static int local_db_read(alpm_pkg_t *info, int inforeq);
//
// #define LAZY_LOAD(info) \
// 	do { \
// 		if(!(pkg->infolevel & info)) { \
// 			local_db_read(pkg, info); \
// 		} \
// 	} while(0)

// /* Cache-specific accessor functions. These implementations allow for lazy
//  * loading by the files backend when a data member is actually needed
//  * rather than loading all pieces of information when the package is first
//  * initialized.
//  */
impl alpm_pkg_t {
    // static const char *_cache_get_base(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->base;
    // }

    // static const char *_cache_get_desc(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->desc;
    // }

    // static const char *_cache_get_url(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->url;
    // }

    // static alpm_time_t _cache_get_builddate(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->builddate;
    // }

    // static alpm_time_t _cache_get_installdate(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->installdate;
    // }

    // static const char *_cache_get_packager(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->packager;
    // }

    // static const char *_cache_get_arch(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->arch;
    // }

    // static off_t _cache_get_isize(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->isize;
    // }

    pub fn _cache_get_reason(&self) -> &alpm_pkgreason_t
    {
    	// LAZY_LOAD(INFRQ_DESC);
    	return &self.reason;
    }

    // static int _cache_get_validation(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->validation;
    // }

    // static alpm_list_t *_cache_get_licenses(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->licenses;
    // }

    // static alpm_list_t *_cache_get_groups(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->groups;
    // }

    // static int _cache_has_scriptlet(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_SCRIPTLET);
    // 	return pkg->scriptlet;
    // }

    // static alpm_list_t *_cache_get_depends(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->depends;
    // }

    // static alpm_list_t *_cache_get_optdepends(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->optdepends;
    // }

    // static alpm_list_t *_cache_get_conflicts(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->conflicts;
    // }

    // static alpm_list_t *_cache_get_provides(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->provides;
    // }

    // static alpm_list_t *_cache_get_replaces(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_DESC);
    // 	return pkg->replaces;
    // }

    // static alpm_filelist_t *_cache_get_files(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_FILES);
    // 	return &(pkg->files);
    // }

    // static alpm_list_t *_cache_get_backup(alpm_pkg_t *pkg)
    // {
    // 	LAZY_LOAD(INFRQ_FILES);
    // 	return pkg->backup;
    // }

    // /**
    //  * Open a package changelog for reading. Similar to fopen in functionality,
    //  * except that the returned 'file stream' is from the database.
    //  * @param pkg the package (from db) to read the changelog
    //  * @return a 'file stream' to the package changelog
    //  */
    // static void *_cache_changelog_open(alpm_pkg_t *pkg)
    // {
    // 	alpm_db_t *db = alpm_pkg_get_db(pkg);
    // 	char *clfile = _alpm_local_db_pkgpath(db, pkg, "changelog");
    // 	FILE *f = fopen(clfile, "r");
    // 	free(clfile);
    // 	return f;
    // }

    // /**
    //  * Read data from an open changelog 'file stream'. Similar to fread in
    //  * functionality, this function takes a buffer and amount of data to read.
    //  * @param ptr a buffer to fill with raw changelog data
    //  * @param size the size of the buffer
    //  * @param pkg the package that the changelog is being read from
    //  * @param fp a 'file stream' to the package changelog
    //  * @return the number of characters read, or 0 if there is no more data
    //  */
    // static size_t _cache_changelog_read(void *ptr, size_t size,
    // 		const alpm_pkg_t UNUSED *pkg, void *fp)
    // {
    // 	return fread(ptr, 1, size, (FILE *)fp);
    // }

    // /**
    //  * Close a package changelog for reading. Similar to fclose in functionality,
    //  * except that the 'file stream' is from the database.
    //  * @param pkg the package that the changelog was read from
    //  * @param fp a 'file stream' to the package changelog
    //  * @return whether closing the package changelog stream was successful
    //  */
    // static int _cache_changelog_close(const alpm_pkg_t UNUSED *pkg, void *fp)
    // {
    // 	return fclose((FILE *)fp);
    // }

    // /**
    //  * Open a package mtree file for reading.
    //  * @param pkg the local package to read the changelog of
    //  * @return a archive structure for the package mtree file
    //  */
    // static struct archive *_cache_mtree_open(alpm_pkg_t *pkg)
    // {
    // 	int r;
    // 	struct archive *mtree;
    //
    // 	alpm_db_t *db = alpm_pkg_get_db(pkg);
    // 	char *mtfile = _alpm_local_db_pkgpath(db, pkg, "mtree");
    //
    // 	if(access(mtfile, F_OK) != 0) {
    // 		/* there is no mtree file for this package */
    // 		goto error;
    // 	}
    //
    // 	if((mtree = archive_read_new()) == NULL) {
    // 		pkg->handle->pm_errno = ALPM_ERR_LIBARCHIVE;
    // 		goto error;
    // 	}
    //
    // 	_alpm_archive_read_support_filter_all(mtree);
    // 	archive_read_support_format_mtree(mtree);
    //
    // 	if((r = _alpm_archive_read_open_file(mtree, mtfile, ALPM_BUFFER_SIZE))) {
    // 		_alpm_log(pkg->handle, ALPM_LOG_ERROR, _("error while reading file {}: {}\n"),
    // 					mtfile, archive_error_string(mtree));
    // 		pkg->handle->pm_errno = ALPM_ERR_LIBARCHIVE;
    // 		_alpm_archive_read_free(mtree);
    // 		goto error;
    // 	}
    //
    // 	free(mtfile);
    // 	return mtree;
    //
    // error:
    // 	free(mtfile);
    // 	return NULL;
    // }

    // /**
    //  * Read next entry from a package mtree file.
    //  * @param pkg the package that the mtree file is being read from
    //  * @param archive the archive structure reading from the mtree file
    //  * @param entry an archive_entry to store the entry header information
    //  * @return 0 if end of archive is reached, non-zero otherwise.
    //  */
    // static int _cache_mtree_next(const alpm_pkg_t UNUSED *pkg,
    // 		struct archive *mtree, struct archive_entry **entry)
    // {
    // 	return archive_read_next_header(mtree, entry);
    // }

    // /**
    //  * Close a package mtree file for reading.
    //  * @param pkg the package that the mtree file was read from
    //  * @param mtree the archive structure use for reading from the mtree file
    //  * @return whether closing the package changelog stream was successful
    //  */
    // static int _cache_mtree_close(const alpm_pkg_t UNUSED *pkg,
    // 		struct archive *mtree)
    // {
    // 	return _alpm_archive_read_free(mtree);
    // }

    // static int _cache_force_load(alpm_pkg_t *pkg)
    // {
    // 	return local_db_read(pkg, INFRQ_ALL);
    // }

    // /** The local database operations struct. Get package fields through
    //  * lazy accessor methods that handle any backend loading and caching
    //  * logic.
    //  */
    // static struct pkg_operations local_pkg_ops = {
    // 	.get_base        = _cache_get_base,
    // 	.get_desc        = _cache_get_desc,
    // 	.get_url         = _cache_get_url,
    // 	.get_builddate   = _cache_get_builddate,
    // 	.get_installdate = _cache_get_installdate,
    // 	.get_packager    = _cache_get_packager,
    // 	.get_arch        = _cache_get_arch,
    // 	.get_isize       = _cache_get_isize,
    // 	.get_reason      = _cache_get_reason,
    // 	.get_validation  = _cache_get_validation,
    // 	.has_scriptlet   = _cache_has_scriptlet,
    // 	.get_licenses    = _cache_get_licenses,
    // 	.get_groups      = _cache_get_groups,
    // 	.get_depends     = _cache_get_depends,
    // 	.get_optdepends  = _cache_get_optdepends,
    // 	.get_conflicts   = _cache_get_conflicts,
    // 	.get_provides    = _cache_get_provides,
    // 	.get_replaces    = _cache_get_replaces,
    // 	.get_files       = _cache_get_files,
    // 	.get_backup      = _cache_get_backup,
    //
    // 	.changelog_open  = _cache_changelog_open,
    // 	.changelog_read  = _cache_changelog_read,
    // 	.changelog_close = _cache_changelog_close,
    //
    // 	.mtree_open      = _cache_mtree_open,
    // 	.mtree_next      = _cache_mtree_next,
    // 	.mtree_close     = _cache_mtree_close,
    //
    // 	.force_load      = _cache_force_load,
    // };

    // static int checkdbdir(alpm_db_t *db)
    // {
    // 	struct stat buf;
    // 	const char *path = _alpm_db_path(db);
    //
    // 	if(stat(path, &buf) != 0) {
    // 		_alpm_log(db->handle, ALPM_LOG_DEBUG, "database dir '{}' does not exist, creating it\n",
    // 				path);
    // 		if(_alpm_makepath(path) != 0) {
    // 			RET_ERR(db->handle, ALPM_ERR_SYSTEM, -1);
    // 		}
    // 	} else if(!S_ISDIR(buf.st_mode)) {
    // 		_alpm_log(db->handle, ALPM_LOG_WARNING, _("removing invalid database: {}\n"), path);
    // 		if(unlink(path) != 0 || _alpm_makepath(path) != 0) {
    // 			RET_ERR(db->handle, ALPM_ERR_SYSTEM, -1);
    // 		}
    // 	}
    // 	return 0;
    // }

    // static int is_dir(const char *path, struct dirent *entry)
    // {
    // #ifdef HAVE_STRUCT_DIRENT_D_TYPE
    // 	if(entry->d_type != DT_UNKNOWN) {
    // 		return (entry->d_type == DT_DIR);
    // 	}
    // #endif
    // 	{
    // 		char buffer[PATH_MAX];
    // 		struct stat sbuf;
    //
    // 		snprintf(buffer, PATH_MAX, "{}/{}", path, entry->d_name);
    //
    // 		if(!stat(buffer, &sbuf)) {
    // 			return S_ISDIR(sbuf.st_mode);
    // 		}
    // 	}
    //
    // 	return 0;
    // }

    // /* Note: the return value must be freed by the caller */
    // char *_alpm_local_db_pkgpath(alpm_db_t *db, alpm_pkg_t *info,
    // 		const char *filename)
    // {
    // 	size_t len;
    // 	char *pkgpath;
    // 	const char *dbpath;
    //
    // 	dbpath = _alpm_db_path(db);
    // 	len = strlen(dbpath) + strlen(info->name) + strlen(info->version) + 3;
    // 	len += filename ? strlen(filename) : 0;
    // 	MALLOC(pkgpath, len, RET_ERR(db->handle, ALPM_ERR_MEMORY, NULL));
    // 	sprintf(pkgpath, "{}{}-{}/{}", dbpath, info->name, info->version,
    // 			filename ? filename : "");
    // 	return pkgpath;
    // }

    // #define READ_NEXT() do { \
    // 	if(safe_fgets(line, sizeof(line), fp) == NULL && !feof(fp)) goto error; \
    // 	_alpm_strip_newline(line, 0); \
    // } while(0)

    // #define READ_AND_STORE(f) do { \
    // 	READ_NEXT(); \
    // 	STRDUP(f, line, goto error); \
    // } while(0)

    // #define READ_AND_STORE_ALL(f) do { \
    // 	char *linedup; \
    // 	if(safe_fgets(line, sizeof(line), fp) == NULL) {\
    // 		if(!feof(fp)) goto error; else break; \
    // 	} \
    // 	if(_alpm_strip_newline(line, 0) == 0) break; \
    // 	STRDUP(linedup, line, goto error); \
    // 	f = alpm_list_add(f, linedup); \
    // } while(1) /* note the while(1) and not (0) */

    // #define READ_AND_SPLITDEP(f) do { \
    // 	if(safe_fgets(line, sizeof(line), fp) == NULL) {\
    // 		if(!feof(fp)) goto error; else break; \
    // 	} \
    // 	if(_alpm_strip_newline(line, 0) == 0) break; \
    // 	f = alpm_list_add(f, alpm_dep_from_string(line)); \
    // } while(1) /* note the while(1) and not (0) */

    // int _alpm_local_db_prepare(alpm_db_t *db, alpm_pkg_t *info)
    // {
    // 	mode_t oldmask;
    // 	int retval = 0;
    // 	char *pkgpath;
    //
    // 	if(checkdbdir(db) != 0) {
    // 		return -1;
    // 	}
    //
    // 	oldmask = umask(0000);
    // 	pkgpath = _alpm_local_db_pkgpath(db, info, NULL);
    //
    // 	if((retval = mkdir(pkgpath, 0755)) != 0) {
    // 		_alpm_log(db->handle, ALPM_LOG_ERROR, _("could not create directory {}: {}\n"),
    // 				pkgpath, strerror(errno));
    // 	}
    //
    // 	free(pkgpath);
    // 	umask(oldmask);
    //
    // 	return retval;
    // }

    // static void write_deps(FILE *fp, const char *header, alpm_list_t *deplist)
    // {
    // 	alpm_list_t *lp;
    // 	if(!deplist) {
    // 		return;
    // 	}
    // 	fputs(header, fp);
    // 	fputc('\n', fp);
    // 	for(lp = deplist; lp; lp = lp->next) {
    // 		char *depstring = alpm_dep_compute_string(lp->data);
    // 		fputs(depstring, fp);
    // 		fputc('\n', fp);
    // 		free(depstring);
    // 	}
    // 	fputc('\n', fp);
    // }

    // int _alpm_local_db_write(alpm_db_t *db, alpm_pkg_t *info, int inforeq)
    // {
    // 	FILE *fp = NULL;
    // 	mode_t oldmask;
    // 	alpm_list_t *lp;
    // 	int retval = 0;
    //
    // 	if(db == NULL || info == NULL || !(db->status & DB_STATUS_LOCAL)) {
    // 		return -1;
    // 	}
    //
    // 	/* make sure we have a sane umask */
    // 	oldmask = umask(0022);
    //
    // 	/* DESC */
    // 	if(inforeq & INFRQ_DESC) {
    // 		char *path;
    // 		_alpm_log(db->handle, ALPM_LOG_DEBUG,
    // 				"writing {}-{} DESC information back to db\n",
    // 				info->name, info->version);
    // 		path = _alpm_local_db_pkgpath(db, info, "desc");
    // 		if(!path || (fp = fopen(path, "w")) == NULL) {
    // 			_alpm_log(db->handle, ALPM_LOG_ERROR, _("could not open file {}: {}\n"),
    // 					path, strerror(errno));
    // 			retval = -1;
    // 			free(path);
    // 			goto cleanup;
    // 		}
    // 		free(path);
    // 		fprintf(fp, "%%NAME%%\n{}\n\n"
    // 						"%%VERSION%%\n{}\n\n", info->name, info->version);
    // 		if(info->base) {
    // 			fprintf(fp, "%%BASE%%\n"
    // 							"{}\n\n", info->base);
    // 		}
    // 		if(info->desc) {
    // 			fprintf(fp, "%%DESC%%\n"
    // 							"{}\n\n", info->desc);
    // 		}
    // 		if(info->url) {
    // 			fprintf(fp, "%%URL%%\n"
    // 							"{}\n\n", info->url);
    // 		}
    // 		if(info->arch) {
    // 			fprintf(fp, "%%ARCH%%\n"
    // 							"{}\n\n", info->arch);
    // 		}
    // 		if(info->builddate) {
    // 			fprintf(fp, "%%BUILDDATE%%\n"
    // 							"%jd\n\n", (intmax_t)info->builddate);
    // 		}
    // 		if(info->installdate) {
    // 			fprintf(fp, "%%INSTALLDATE%%\n"
    // 							"%jd\n\n", (intmax_t)info->installdate);
    // 		}
    // 		if(info->packager) {
    // 			fprintf(fp, "%%PACKAGER%%\n"
    // 							"{}\n\n", info->packager);
    // 		}
    // 		if(info->isize) {
    // 			/* only write installed size, csize is irrelevant once installed */
    // 			fprintf(fp, "%%SIZE%%\n"
    // 							"%jd\n\n", (intmax_t)info->isize);
    // 		}
    // 		if(info->reason) {
    // 			fprintf(fp, "%%REASON%%\n"
    // 							"%u\n\n", info->reason);
    // 		}
    // 		if(info->groups) {
    // 			fputs("%GROUPS%\n", fp);
    // 			for(lp = info->groups; lp; lp = lp->next) {
    // 				fputs(lp->data, fp);
    // 				fputc('\n', fp);
    // 			}
    // 			fputc('\n', fp);
    // 		}
    // 		if(info->licenses) {
    // 			fputs("%LICENSE%\n", fp);
    // 			for(lp = info->licenses; lp; lp = lp->next) {
    // 				fputs(lp->data, fp);
    // 				fputc('\n', fp);
    // 			}
    // 			fputc('\n', fp);
    // 		}
    // 		if(info->validation) {
    // 			fputs("%VALIDATION%\n", fp);
    // 			if(info->validation & ALPM_PKG_VALIDATION_NONE) {
    // 				fputs("none\n", fp);
    // 			}
    // 			if(info->validation & ALPM_PKG_VALIDATION_MD5SUM) {
    // 				fputs("md5\n", fp);
    // 			}
    // 			if(info->validation & ALPM_PKG_VALIDATION_SHA256SUM) {
    // 				fputs("sha256\n", fp);
    // 			}
    // 			if(info->validation & ALPM_PKG_VALIDATION_SIGNATURE) {
    // 				fputs("pgp\n", fp);
    // 			}
    // 			fputc('\n', fp);
    // 		}
    //
    // 		write_deps(fp, "%REPLACES%", info->replaces);
    // 		write_deps(fp, "%DEPENDS%", info->depends);
    // 		write_deps(fp, "%OPTDEPENDS%", info->optdepends);
    // 		write_deps(fp, "%CONFLICTS%", info->conflicts);
    // 		write_deps(fp, "%PROVIDES%", info->provides);
    //
    // 		fclose(fp);
    // 		fp = NULL;
    // 	}
    //
    // 	/* FILES */
    // 	if(inforeq & INFRQ_FILES) {
    // 		char *path;
    // 		_alpm_log(db->handle, ALPM_LOG_DEBUG,
    // 				"writing {}-{} FILES information back to db\n",
    // 				info->name, info->version);
    // 		path = _alpm_local_db_pkgpath(db, info, "files");
    // 		if(!path || (fp = fopen(path, "w")) == NULL) {
    // 			_alpm_log(db->handle, ALPM_LOG_ERROR, _("could not open file {}: {}\n"),
    // 					path, strerror(errno));
    // 			retval = -1;
    // 			free(path);
    // 			goto cleanup;
    // 		}
    // 		free(path);
    // 		if(info->files.count) {
    // 			size_t i;
    // 			fputs("%FILES%\n", fp);
    // 			for(i = 0; i < info->files.count; i++) {
    // 				const alpm_file_t *file = info->files.files + i;
    // 				fputs(file->name, fp);
    // 				fputc('\n', fp);
    // 			}
    // 			fputc('\n', fp);
    // 		}
    // 		if(info->backup) {
    // 			fputs("%BACKUP%\n", fp);
    // 			for(lp = info->backup; lp; lp = lp->next) {
    // 				const alpm_backup_t *backup = lp->data;
    // 				fprintf(fp, "{}\t{}\n", backup->name, backup->hash);
    // 			}
    // 			fputc('\n', fp);
    // 		}
    // 		fclose(fp);
    // 		fp = NULL;
    // 	}
    //
    // 	/* INSTALL and MTREE */
    // 	/* nothing needed here (automatically extracted) */
    //
    // cleanup:
    // 	umask(oldmask);
    // 	return retval;
    // }

    // int _alpm_local_db_remove(alpm_db_t *db, alpm_pkg_t *info)
    // {
    // 	int ret = 0;
    // 	DIR *dirp;
    // 	struct dirent *dp;
    // 	char *pkgpath;
    // 	size_t pkgpath_len;
    //
    // 	pkgpath = _alpm_local_db_pkgpath(db, info, NULL);
    // 	if(!pkgpath) {
    // 		return -1;
    // 	}
    // 	pkgpath_len = strlen(pkgpath);
    //
    // 	dirp = opendir(pkgpath);
    // 	if(!dirp) {
    // 		free(pkgpath);
    // 		return -1;
    // 	}
    // 	/* go through the local DB entry, removing the files within, which we know
    // 	 * are not nested directories of any kind. */
    // 	for(dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
    // 		if(strcmp(dp->d_name, "..") != 0 && strcmp(dp->d_name, ".") != 0) {
    // 			char name[PATH_MAX];
    // 			if(pkgpath_len + strlen(dp->d_name) + 2 > PATH_MAX) {
    // 				/* file path is too long to remove, hmm. */
    // 				ret = -1;
    // 			} else {
    // 				sprintf(name, "{}/{}", pkgpath, dp->d_name);
    // 				if(unlink(name)) {
    // 					ret = -1;
    // 				}
    // 			}
    // 		}
    // 	}
    // 	closedir(dirp);
    //
    // 	/* after removing all enclosed files, we can remove the directory itself. */
    // 	if(rmdir(pkgpath)) {
    // 		ret = -1;
    // 	}
    // 	free(pkgpath);
    // 	return ret;
    // }

    pub fn alpm_pkg_set_reason(&self, reason: &alpm_pkgreason_t) -> i32 {
        unimplemented!();
        // 	ASSERT(pkg != NULL, return -1);
        // 	ASSERT(pkg->origin == ALPM_PKG_FROM_LOCALDB,
        // 			RET_ERR(pkg->handle, ALPM_ERR_WRONG_ARGS, -1));
        // 	ASSERT(pkg->origin_data.db == pkg->handle->db_local,
        // 			RET_ERR(pkg->handle, ALPM_ERR_WRONG_ARGS, -1));
        //
        // 	_alpm_log(pkg->handle, ALPM_LOG_DEBUG,
        // 			"setting install reason %u for {}\n", reason, pkg->name);
        // 	if(alpm_pkg_get_reason(pkg) == reason) {
        // 		/* we are done */
        // 		return 0;
        // 	}
        // 	/* set reason (in pkgcache) */
        // 	pkg->reason = reason;
        // 	/* write DESC */
        // 	if(_alpm_local_db_write(pkg->handle->db_local, pkg, INFRQ_DESC)) {
        // 		RET_ERR(pkg->handle, ALPM_ERR_DB_WRITE, -1);
        // 	}
        //
        // 	return 0;
    }

    // struct db_operations local_db_ops = {
    // 	.validate         = local_db_validate,
    // 	.populate         = local_db_populate,
    // 	.unregister       = _alpm_db_unregister,
    // };
}

impl alpm_db_t {
    pub fn local_db_populate(&mut self) -> Result<()> {
        use std::fs;
        use self::alpm_errno_t::*;
        // 	size_t est_count;
        // 	size_t count = 0;
        let mut count = 0;
        // 	struct stat buf;
        // 	struct dirent *ent = NULL;
        // 	const char *dbpath;
        let dbdir;
        let dbpath;
        // 	DIR *dbdir;
        //
        if self.status.DB_STATUS_INVALID {
            return Err(ALPM_ERR_DB_INVALID);
        }
        if self.status.DB_STATUS_MISSING {
            return Err(ALPM_ERR_DB_NOT_FOUND);
        }

        dbpath = self._alpm_db_path()?;

        dbdir = match fs::read_dir(dbpath) {
            Err(_e) => return Err(ALPM_ERR_DB_OPEN),
            Ok(d) => d,
        };
        self.status.DB_STATUS_EXISTS = true;
        self.status.DB_STATUS_MISSING = false;
        // if dbdir.len() >= 2 {
        // 		est_count = buf.st_nlink;
        // } else {
        // 		/* Some filesystems don't subscribe to the two-implicit links school of
        // 		 * thought, e.g. BTRFS, HFS+. See
        // 		 * http://kerneltrap.org/mailarchive/linux-btrfs/2010/1/23/6723483/thread
        // 		 */
        // 		est_count = 0;
        // 		while(readdir(dbdir) != NULL) {
        // 			est_count++;
        // 		}
        // 		rewinddir(dbdir);
        // }
        // 	if(est_count >= 2) {
        // 		/* subtract the '.' and '..' pointers to get # of children */
        // 		est_count -= 2;
        // 	}
        self.pkgcache = _alpm_pkghash_create();
        // 	if(db->pkgcache == NULL){
        // 		closedir(dbdir);
        // 		RET_ERR(db->handle, ALPM_ERR_MEMORY, -1);
        // 	}

        for ent in dbdir {
            match ent {
                Ok(ent) => {
                    let mut pkg;
                    let name = ent.file_name().into_string().unwrap();
                    // 		alpm_pkg_t *pkg;
                    debug!("TEMP 1: {:?}",ent);

                    if name == "." || name == ".." {
                        continue;
                    }
                    match fs::metadata(ent.path()) {
                        Ok(m) => if !m.is_dir() {
                            continue;
                        },
                        Err(_e) => {}
                    }
                    debug!("TEMP 2: {:?}",ent);

                    pkg = alpm_pkg_t::default();
                    /* split the db entry name */
                    {
                        let (name, version, name_hash) = match _alpm_splitname(&name) {
                            Err(_) => {
                                error!("invalid name for database entry '{}'", name);
                                // _alpm_pkg_free(pkg);
                                continue;
                            }
                            Ok(d) => d,
                        };
                        pkg.name = name;
                        pkg.version = version;
                        pkg.name_hash = name_hash;
                    }
                    debug!("TEMP 3: {:?}",ent);

                    /* duplicated database entries are not allowed */
                    // 		if(_alpm_pkghash_find(db->pkgcache, pkg->name)) {
                    // 			_alpm_log(db->handle, ALPM_LOG_ERROR, _("duplicated database entry '{}'\n"), pkg->name);
                    // 			_alpm_pkg_free(pkg);
                    // 			continue;
                    // 		}

                    pkg.origin = alpm_pkgfrom_t::ALPM_PKG_FROM_LOCALDB;
                    // pkg.db = self.clone();
                    // pkg.ops = &local_pkg_ops;
                    // pkg.handle = db->handle;
                    debug!("TEMP 4: {:?}",ent);

                    /* explicitly read with only 'BASE' data, accessors will handle the rest */
                    if local_db_read(&pkg, INFRQ_BASE) == -1 {
                        debug!("corrupted database entry '{}'", name);
                        continue;
                    }

                    /* add to the collection */
                    // 		_alpm_log(db->handle, ALPM_LOG_FUNCTION, "adding '{}' to package cache for db '{}'\n",
                    // 				pkg->name, db->treename);
                    self.pkgcache._alpm_pkghash_add(pkg);
                    count += 1;
                }
                Err(_e) => unimplemented!(),
            }
        }

        if count > 0 {
            self.pkgcache.list.sort_by(_alpm_pkg_cmp);
        }
        debug!(
            "added {} packages to package cache for db '{}'",
            count, self.treename
        );
        Ok(())
    }

    pub fn local_db_validate(&mut self, handle: &alpm_handle_t) -> Result<bool> {
        let dbpath;
        let dbdir;
        let dbverpath;
        let version: usize;
        let mut dbverfile;

        if self.status.DB_STATUS_VALID {
            return Ok(true);
        }
        if self.status.DB_STATUS_INVALID {
            return Ok(false);
            // return -1;
        }

        dbpath = match self._alpm_db_path() {
            Ok(d) => d,
            Err(e) => {
                return Err(e);
            }
        };

        dbdir = match std::fs::read_dir(&dbpath) {
            Ok(d) => d,
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        /* local database dir doesn't exist yet - create it */
                        match self.local_db_create(&dbpath) {
                            Ok(_) => {
                                self.status.DB_STATUS_VALID = true;
                                self.status.DB_STATUS_INVALID = false;
                                self.status.DB_STATUS_EXISTS = true;
                                self.status.DB_STATUS_MISSING = false;
                                return Ok(true);
                            }
                            Err(e) => {
                                self.status.DB_STATUS_EXISTS = false;
                                self.status.DB_STATUS_MISSING = true;
                                return Err(e);
                            }
                        }
                    }
                    _ => {
                        return Err(alpm_errno_t::ALPM_ERR_DB_OPEN);
                    }
                }
            }
        };
        self.status.DB_STATUS_EXISTS = true;
        self.status.DB_STATUS_MISSING = false;

        dbverpath = format!("{}ALPM_DB_VERSION", dbpath);

        dbverfile = match std::fs::File::open(&dbverpath) {
            Err(_e) => {
                /* create dbverfile if local database is empty - otherwise version error */
                for ent in dbdir {
                    match ent {
                        Ok(ent) => {
                            let name = &ent.file_name();
                            if name == "." || name == ".." {
                                continue;
                            } else {
                                self.status.DB_STATUS_VALID = false;
                                self.status.DB_STATUS_INVALID = true;
                                return Err(alpm_errno_t::ALPM_ERR_DB_VERSION);
                            }
                        }
                        Err(_e) => panic!(),
                    }
                }

                if self.local_db_add_version(&dbpath).is_err() {
                    self.status.DB_STATUS_VALID = false;
                    self.status.DB_STATUS_INVALID = true;
                    return Err(alpm_errno_t::ALPM_ERR_DB_VERSION);
                }

                self.status.DB_STATUS_VALID = true;
                self.status.DB_STATUS_INVALID = false;
                return Ok(true);
            }
            Ok(f) => f,
        };

        use std::io::Read;
        let mut dbverfilestr = String::new();
        dbverfile.read_to_string(&mut dbverfilestr).unwrap();
        dbverfilestr = String::from(dbverfilestr.trim());
        version = match dbverfilestr.parse() {
            Err(e) => {
                self.status.DB_STATUS_VALID = false;
                self.status.DB_STATUS_INVALID = true;
                debug!("TEMP, {}", e);
                return Err(alpm_errno_t::ALPM_ERR_DB_VERSION);
            }
            Ok(v) => v,
        };

        if version != ALPM_LOCAL_DB_VERSION {
            self.status.DB_STATUS_VALID = false;
            self.status.DB_STATUS_INVALID = true;
            return Err(alpm_errno_t::ALPM_ERR_DB_VERSION);
        }

        self.status.DB_STATUS_VALID = true;
        self.status.DB_STATUS_INVALID = false;
        return Ok(true);
    }

    fn local_db_create(&mut self, dbpath: &String) -> Result<i32> {
        // if (std::fs::create_dir(dbpath, 0755) != 0) {
        match std::fs::create_dir(dbpath) {
            Err(e) => {
                eprintln!("could not create directory {}: {}", dbpath, e);
                return Err(alpm_errno_t::ALPM_ERR_DB_CREATE);
            }
            _ => {}
        }
        if self.local_db_add_version(dbpath).is_err() {
            // return 1;
            unimplemented!();
        }

        return Ok(0);
    }

    fn local_db_add_version(&self, dbpath: &String) -> std::io::Result<usize> {
        let dbverpath = format!("{}ALPM_DB_VERSION", dbpath);
        use std::io::Write;
        match std::fs::File::create(dbverpath) {
            Ok(mut dbverfile) => {
                let data = format!("{}", ALPM_LOCAL_DB_VERSION);
                dbverfile.write(data.as_bytes())
            }
            Err(e) => Err(e),
        }
    }
}

impl alpm_handle_t {
    pub fn _alpm_db_register_local(&mut self) -> Result<&alpm_db_t> {
        let mut db;
        // 	_alpm_log(handle, ALPM_LOG_DEBUG, "registering local database\n");

        db = alpm_db_t::_alpm_db_new(&String::from("local"), true);
        // 	if(db == NULL) {
        // 		handle->pm_errno = ALPM_ERR_DB_CREATE;
        // 		return NULL;
        // 	}
        // db.ops = &local_db_ops;
        db.ops_type = db_ops_type::local;
        // db->handle = handle;
        db.usage.ALPM_DB_USAGE_ALL = true;
        db.create_path(&self.dbpath, &self.dbext)?;
        db.local_db_validate(self)?;

        self.db_local = db;
        return Ok(&self.db_local);
    }
}

pub fn local_db_read(info: &alpm_pkg_t, inforeq: i32) -> i32 {
    // 	FILE *fp = NULL;
    // 	char line[1024];
    // 	alpm_db_t *db = info->origin_data.db;

    /* bitmask logic here:
     * infolevel: 00001111
     * inforeq:   00010100
     * & result:  00000100
     * == to inforeq? nope, we need to load more info. */
    if (info.infolevel & inforeq) == inforeq {
        /* already loaded all of this info, do nothing */
        return 0;
    }

    if info.infolevel & INFRQ_ERROR != 0 {
        /* We've encountered an error loading this package before. Don't attempt
         * repeated reloads, just give up. */
        return -1;
    }

    // 	_alpm_log(db->handle, ALPM_LOG_FUNCTION,
    // 			"loading package data for {} : level=0x%x\n",
    // 			info->name, inforeq);
    //
    // 	/* clear out 'line', to be certain - and to make valgrind happy */
    // 	memset(line, 0, sizeof(line));

    /* DESC */
    if inforeq & INFRQ_DESC != 0 && (info.infolevel & INFRQ_DESC) == 0 {
        unimplemented!();
        // 		char *path = _alpm_local_db_pkgpath(db, info, "desc");
        // 		if(!path || (fp = fopen(path, "r")) == NULL) {
        // 			_alpm_log(db->handle, ALPM_LOG_ERROR, _("could not open file {}: {}\n"), path, strerror(errno));
        // 			free(path);
        // 			goto error;
        // 		}
        // 		free(path);
        // 		while(!feof(fp)) {
        // 			if(safe_fgets(line, sizeof(line), fp) == NULL && !feof(fp)) {
        // 				goto error;
        // 			}
        // 			if(_alpm_strip_newline(line, 0) == 0) {
        // 				/* length of stripped line was zero */
        // 				continue;
        // 			}
        // 			if(strcmp(line, "%NAME%") == 0) {
        // 				READ_NEXT();
        // 				if(strcmp(line, info->name) != 0) {
        // 					_alpm_log(db->handle, ALPM_LOG_ERROR, _("{} database is inconsistent: name "
        // 								"mismatch on package {}\n"), db->treename, info->name);
        // 				}
        // 			} else if(strcmp(line, "%VERSION%") == 0) {
        // 				READ_NEXT();
        // 				if(strcmp(line, info->version) != 0) {
        // 					_alpm_log(db->handle, ALPM_LOG_ERROR, _("{} database is inconsistent: version "
        // 								"mismatch on package {}\n"), db->treename, info->name);
        // 				}
        // 			} else if(strcmp(line, "%BASE%") == 0) {
        // 				READ_AND_STORE(info->base);
        // 			} else if(strcmp(line, "%DESC%") == 0) {
        // 				READ_AND_STORE(info->desc);
        // 			} else if(strcmp(line, "%GROUPS%") == 0) {
        // 				READ_AND_STORE_ALL(info->groups);
        // 			} else if(strcmp(line, "%URL%") == 0) {
        // 				READ_AND_STORE(info->url);
        // 			} else if(strcmp(line, "%LICENSE%") == 0) {
        // 				READ_AND_STORE_ALL(info->licenses);
        // 			} else if(strcmp(line, "%ARCH%") == 0) {
        // 				READ_AND_STORE(info->arch);
        // 			} else if(strcmp(line, "%BUILDDATE%") == 0) {
        // 				READ_NEXT();
        // 				info->builddate = _alpm_parsedate(line);
        // 			} else if(strcmp(line, "%INSTALLDATE%") == 0) {
        // 				READ_NEXT();
        // 				info->installdate = _alpm_parsedate(line);
        // 			} else if(strcmp(line, "%PACKAGER%") == 0) {
        // 				READ_AND_STORE(info->packager);
        // 			} else if(strcmp(line, "%REASON%") == 0) {
        // 				READ_NEXT();
        // 				info->reason = (alpm_pkgreason_t)atoi(line);
        // 			} else if(strcmp(line, "%VALIDATION%") == 0) {
        // 				alpm_list_t *i, *v = NULL;
        // 				READ_AND_STORE_ALL(v);
        // 				for(i = v; i; i = alpm_list_next(i))
        // 				{
        // 					if(strcmp(i->data, "none") == 0) {
        // 						info->validation |= ALPM_PKG_VALIDATION_NONE;
        // 					} else if(strcmp(i->data, "md5") == 0) {
        // 						info->validation |= ALPM_PKG_VALIDATION_MD5SUM;
        // 					} else if(strcmp(i->data, "sha256") == 0) {
        // 						info->validation |= ALPM_PKG_VALIDATION_SHA256SUM;
        // 					} else if(strcmp(i->data, "pgp") == 0) {
        // 						info->validation |= ALPM_PKG_VALIDATION_SIGNATURE;
        // 					} else {
        // 						_alpm_log(db->handle, ALPM_LOG_WARNING,
        // 								_("unknown validation type for package {}: {}\n"),
        // 								info->name, (const char *)i->data);
        // 					}
        // 				}
        // 				FREELIST(v);
        // 			} else if(strcmp(line, "%SIZE%") == 0) {
        // 				READ_NEXT();
        // 				info->isize = _alpm_strtoofft(line);
        // 			} else if(strcmp(line, "%REPLACES%") == 0) {
        // 				READ_AND_SPLITDEP(info->replaces);
        // 			} else if(strcmp(line, "%DEPENDS%") == 0) {
        // 				READ_AND_SPLITDEP(info->depends);
        // 			} else if(strcmp(line, "%OPTDEPENDS%") == 0) {
        // 				READ_AND_SPLITDEP(info->optdepends);
        // 			} else if(strcmp(line, "%CONFLICTS%") == 0) {
        // 				READ_AND_SPLITDEP(info->conflicts);
        // 			} else if(strcmp(line, "%PROVIDES%") == 0) {
        // 				READ_AND_SPLITDEP(info->provides);
        // 			}
        // 		}
        // 		fclose(fp);
        // 		fp = NULL;
        // 		info->infolevel |= INFRQ_DESC;
    }

    /* FILES */
    if inforeq & INFRQ_FILES != 0 && (info.infolevel & INFRQ_FILES) == 0 {
        unimplemented!();
        // 		char *path = _alpm_local_db_pkgpath(db, info, "files");
        // 		if(!path || (fp = fopen(path, "r")) == NULL) {
        // 			_alpm_log(db->handle, ALPM_LOG_ERROR, _("could not open file {}: {}\n"), path, strerror(errno));
        // 			free(path);
        // 			goto error;
        // 		}
        // 		free(path);
        // 		while(safe_fgets(line, sizeof(line), fp)) {
        // 			_alpm_strip_newline(line, 0);
        // 			if(strcmp(line, "%FILES%") == 0) {
        // 				size_t files_count = 0, files_size = 0, len;
        // 				alpm_file_t *files = NULL;
        //
        // 				while(safe_fgets(line, sizeof(line), fp) &&
        // 						(len = _alpm_strip_newline(line, 0))) {
        // 					if(!_alpm_greedy_grow((void **)&files, &files_size,
        // 								(files_count ? (files_count + 1) * sizeof(alpm_file_t) : 8 * sizeof(alpm_file_t)))) {
        // 						goto nomem;
        // 					}
        // 					/* since we know the length of the file string already,
        // 					 * we can do malloc + memcpy rather than strdup */
        // 					len += 1;
        // 					MALLOC(files[files_count].name, len, goto nomem);
        // 					memcpy(files[files_count].name, line, len);
        // 					files_count++;
        // 				}
        // 				/* attempt to hand back any memory we don't need */
        // 				if(files_count > 0) {
        // 					alpm_file_t *newfiles;
        //
        // 					newfiles = realloc(files, sizeof(alpm_file_t) * files_count);
        // 					if(newfiles != NULL) {
        // 						files = newfiles;
        // 					}
        // 				} else {
        // 					FREE(files);
        // 				}
        // 				info->files.count = files_count;
        // 				info->files.files = files;
        // 				_alpm_filelist_sort(&info->files);
        // 				continue;
        // nomem:
        // 				while(files_count > 0) {
        // 					FREE(files[--files_count].name);
        // 				}
        // 				FREE(files);
        // 				goto error;
        // 			} else if(strcmp(line, "%BACKUP%") == 0) {
        // 				while(safe_fgets(line, sizeof(line), fp) && _alpm_strip_newline(line, 0)) {
        // 					alpm_backup_t *backup;
        // 					CALLOC(backup, 1, sizeof(alpm_backup_t), goto error);
        // 					if(_alpm_split_backup(line, &backup)) {
        // 						FREE(backup);
        // 						goto error;
        // 					}
        // 					info->backup = alpm_list_add(info->backup, backup);
        // 				}
        // 			}
        // 		}
        // 		fclose(fp);
        // 		fp = NULL;
        // 		info->infolevel |= INFRQ_FILES;
    }

    /* INSTALL */
    if inforeq & INFRQ_SCRIPTLET != 0 && (info.infolevel & INFRQ_SCRIPTLET) == 0 {
        unimplemented!();
        // 		char *path = _alpm_local_db_pkgpath(db, info, "install");
        // 		if(access(path, F_OK) == 0) {
        // 			info->scriptlet = 1;
        // 		}
        // 		free(path);
        // 		info->infolevel |= INFRQ_SCRIPTLET;
    }

    return 0;

    // error:
    // 	info->infolevel |= INFRQ_ERROR;
    // 	if(fp) {
    // 		fclose(fp);
    // 	}
    // 	return -1;
}
