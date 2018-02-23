use super::*;
use std::fs::File;
use super::deps::dep_vercmp;
/*
 *  package.h
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
 *  Copyright (c) 2006 by David Kimpe <dnaku@frugalware.org>
 *  Copyright (c) 2005, 2006 by Christian Hamar <krics@linuxforum.hu>
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
 *  package.c
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
 *  Copyright (c) 2005, 2006 by Christian Hamar <krics@linuxforum.hu>
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

// #include <stdlib.h>
// #include <string.h>
// #include <sys/types.h>
//
// /* libalpm */
// #include "package.h"
// #include "alpm_list.h"
// #include "log.h"
// #include "util.h"
// #include "db.h"
// #include "delta.h"
// #include "handle.h"
// #include "deps.h"

// /** Package operations struct. This struct contains function pointers to
//  * all methods used to access data in a package to allow for things such
//  * as lazy package initialization (such as used by the file backend). Each
//  * backend is free to define a stuct containing pointers to a specific
//  * implementation of these methods. Some backends may find using the
//  * defined default_pkg_ops struct to work just fine for their needs.
//  */
// #[derive(Clone)]
// struct pkg_operations {
//     get_base: fn(&Package) -> String,
//     get_desc: fn(&Package) -> String,
//     get_url: fn(&Package) -> String,
//     get_builddate: fn(&Package) -> alpm_time_t,
//     get_installdate: fn(&Package) -> alpm_time_t,
//     // const char *(*get_packager) (Package *);
//     // const char *(*get_arch) (Package *);
//     // off_t (*get_isize) (Package *);
//     // PackageReason (*get_reason) (Package *);
//     // int (*get_validation) (Package *);
//     // int (*has_scriptlet) (Package *);
//
//     // alpm_list_t *(*get_licenses) (Package *);
//     // alpm_list_t *(*get_groups) (Package *);
//     // alpm_list_t *(*get_depends) (Package *);
//     // alpm_list_t *(*get_optdepends) (Package *);
//     // alpm_list_t *(*get_checkdepends) (Package *);
//     // alpm_list_t *(*get_makedepends) (Package *);
//     // alpm_list_t *(*get_conflicts) (Package *);
//     // alpm_list_t *(*get_provides) (Package *);
//     // alpm_list_t *(*get_replaces) (Package *);
//     // alpm_filelist_t *(*get_files) (Package *);
//     // alpm_list_t *(*get_backup) (Package *);
//
//     // void *(*changelog_open) (Package *);
//     // size_t (*changelog_read) (void *, size_t, const Package *, void *);
//     // int (*changelog_close) (const Package *, void *);
//
//     // struct archive *(*mtree_open) (Package *);
//     // int (*mtree_next) (const Package *, struct archive *, struct archive_entry **);
//     // int (*mtree_close) (const Package *, struct archive *);
//
//     // int (*force_load) (Package *);
// }

// /** The standard package operations struct. get fields directly from the
//  * struct itself with no abstraction layer or any type of lazy loading.
//  * The actual definition is in package.c so it can have access to the
//  * default accessor functions which are defined there.
//  */
// extern struct pkg_operations default_pkg_ops;
// type off_t = i64;
#[derive(Default, Debug, Clone)]
pub struct Package {
    name_hash: u64,
    filename: String,
    base: String,
    name: String,
    version: String,
    desc: String,
    url: String,
    packager: String,
    md5sum: String,
    sha256sum: String,
    base64_sig: String,
    arch: String,

    builddate: Time,
    installdate: Time,

    size: i64,
    isize: i64,
    download_size: i64,

    // pub handle: alpm_handle_t,
    licenses: Vec<String>,
    replaces: Vec<Dependency>,
    groups: Vec<String>,
    backup: Vec<String>,
    depends: Vec<Dependency>,
    optdepends: Vec<Dependency>,
    checkdepends: Vec<Dependency>,
    makedepends: Vec<Dependency>,
    conflicts: Vec<Dependency>,
    provides: Vec<Dependency>,
    deltas: Vec<Dependency>,
    delta_path: Vec<Dependency>,
    removes: Vec<Dependency>,
    /* in transaction targets only */
    // pub oldpkg: Option<Package>, /* in transaction targets only */

    // pub ops: pkg_operations,

    // alpm_filelist_t files;

    /* origin == PKG_FROM_FILE, use pkg->origin_data.file
     * origin == PKG_FROM_*DB, use pkg->origin_data.db */
    // union {
    // pub db: Database,
    file: String,
    // } origin_data;
    origin: PackageFrom,
    reason: PackageReason,
    scriptlet: i32,

    /* Bitfield from alpm_dbinfrq_t */
    infolevel: i32,
    /* Bitfield from alpm_pkgvalidation_t */
    validation: i32,
}

// /* Default package accessor functions. These will get overridden by any
//  * backend logic that needs lazy access, such as the local database through
//  * a lazy-load cache. However, the defaults will work just fine for fully-
//  * populated package structures. */
// static const char *_pkg_get_base(Package *pkg)        { return pkg->base; }
// static const char *_pkg_get_desc(Package *pkg)        { return pkg->desc; }
// static const char *_pkg_get_url(Package *pkg)         { return pkg->url; }
// static alpm_time_t _pkg_get_builddate(Package *pkg)   { return pkg->builddate; }
// static alpm_time_t _pkg_get_installdate(Package *pkg) { return pkg->installdate; }
// static const char *_pkg_get_packager(Package *pkg)    { return pkg->packager; }
// static const char *_pkg_get_arch(Package *pkg)        { return pkg->arch; }
// static off_t _pkg_get_isize(Package *pkg)             { return pkg->isize; }
// static PackageReason _pkg_get_reason(Package *pkg) { return pkg->reason; }
// static int _pkg_get_validation(Package *pkg) { return pkg->validation; }
// static int _pkg_has_scriptlet(Package *pkg)           { return pkg->scriptlet; }
//
// static alpm_list_t *_pkg_get_licenses(Package *pkg)   { return pkg->licenses; }
// static alpm_list_t *_pkg_get_groups(Package *pkg)     { return pkg->groups; }
// static alpm_list_t *_pkg_get_depends(Package *pkg)    { return pkg->depends; }
// static alpm_list_t *_pkg_get_optdepends(Package *pkg) { return pkg->optdepends; }
// static alpm_list_t *_pkg_get_checkdepends(Package *pkg) { return pkg->checkdepends; }
// static alpm_list_t *_pkg_get_makedepends(Package *pkg) { return pkg->makedepends; }
// static alpm_list_t *_pkg_get_conflicts(Package *pkg)  { return pkg->conflicts; }
// static alpm_list_t *_pkg_get_provides(Package *pkg)   { return pkg->provides; }
// static alpm_list_t *_pkg_get_replaces(Package *pkg)   { return pkg->replaces; }
// static alpm_filelist_t *_pkg_get_files(Package *pkg)  { return &(pkg->files); }
// static alpm_list_t *_pkg_get_backup(Package *pkg)     { return pkg->backup; }

// static void *_pkg_changelog_open(Package UNUSED *pkg)
// {
// 	return NULL;
// }

// static size_t _pkg_changelog_read(void UNUSED *ptr, size_t UNUSED size,
// 		const Package UNUSED *pkg, UNUSED void *fp)
// {
// 	return 0;
// }

// static int _pkg_changelog_close(const Package UNUSED *pkg,
// 		void UNUSED *fp)
// {
// 	return EOF;
// }

// static struct archive *_pkg_mtree_open(Package UNUSED *pkg)
// {
// 	return NULL;
// }

// static int _pkg_mtree_next(const Package UNUSED *pkg,
// 		struct archive UNUSED *archive, struct archive_entry UNUSED **entry)
// {
// 	return -1;
// }

// static int _pkg_mtree_close(const Package UNUSED *pkg,
// 		struct archive UNUSED *archive)
// {
// 	return -1;
// }

// static int _pkg_force_load(Package UNUSED *pkg) { return 0; }

impl Package {
    /// Check the integrity (with md5) of a package from the sync cache.
    fn checkmd5sum(&self) -> i64 {
        let fpath: String;
        let retval = 0;

        /* We only inspect packages from sync repositories */
        match self.origin {
            PackageFrom::SyncDatabase => {}
            _ => { /*RET_ERR(pkg->handle, ALPM_ERR_WRONG_ARGS, -1))*/ }
        }
        unimplemented!();
        // fpath = _alpm_filecache_find(pkg.handle, pkg.filename);
        //
        // retval = _alpm_test_checksum(fpath, pkg.md5sum, ALPM_PKG_VALIDATION_MD5SUM);
        //
        // if (retval == 1) {
        //     retval = -1;
        // }

        return retval;
    }

    /// Check for new version of pkg in sync repos
    /// (only the first occurrence is considered in sync)
    pub fn newversion(&self, dbs_sync: &Vec<Database>) -> Option<Package> {
        unimplemented!();
        // 	alpm_list_t *i;
        // 	Package *spkg = NULL;
        //
        // 	ASSERT(pkg != NULL, return NULL);
        // 	pkg->handle->pm_errno = ALPM_ERR_OK;
        //
        // 	for(i = dbs_sync; !spkg && i; i = i->next) {
        // 		Database *db = i->data;
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
        // static int check_literal(alpm_handle_t *handle, Package *lpkg,
        // 		Package *spkg, int enable_downgrade)
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
        // 			Database *sdb = alpm_pkg_get_db(spkg);
        // 			_alpm_log(handle, ALPM_LOG_WARNING, _("{}: local ({}) is newer than {} ({})\n"),
        // 					lpkg->name, lpkg->version, sdb->treename, spkg->version);
        // 		}
        // 	}
        // 	return 0;
    }

    /// Returns the size of the files that will be downloaded to install a
    /// package. returns the size of the download
    pub fn download_size(&self) -> i64 {
        unimplemented!();
        // if !(self.infolevel & INFRQ_DSIZE) {
        // 	compute_download_size(newpkg);
        // }
        // return self.download_size;
    }

    fn depcmp_literal(&self, dep: &Dependency) -> bool {
        if self.name_hash != dep.name_hash || self.name != dep.name {
            /* skip more expensive checks */
            return false;
        }
        return dep_vercmp(&self.version, &dep.depmod, &dep.version);
    }

    pub fn depcmp(&self, dep: &Dependency) -> bool {
        return self.depcmp_literal(dep) || dep._alpm_depcmp_provides(&self.provides);
    }

    pub fn get_filename(&self) -> String {
        return self.filename.clone();
    }

    pub fn get_base(&self) -> String {
        unimplemented!();
        // return self.ops.get_base(self);
    }

    pub fn set_base(&mut self, base: &str) {
        self.name = String::from(base);
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn set_name(&mut self, name: &String) {
        self.name = name.clone();
    }

    pub fn set_name_hash(&mut self, name_hash: u64) {
        self.name_hash = name_hash;
    }

    pub fn get_version(&self) -> &String {
        return &self.version;
    }

    pub fn set_version(&mut self, ver: String) {
        self.version = ver.clone();
    }

    pub fn get_origin(&self) -> PackageFrom {
        return self.origin;
    }

    // Sets the origin of the package
    pub fn set_origin(&mut self, origin: PackageFrom) {
        self.origin = origin;
    }

    pub fn get_desc(&self) -> Result<&String> {
        match self.get_origin() {
            PackageFrom::LocalDatabase => self._cache_get_desc(),
            _ => unimplemented!(),
        }
        // return self.ops.get_desc(self);
    }

    /// Sets the Description of the Package
    pub fn set_desc(&mut self, desc: String) {
        self.desc = desc
    }

    /// Gets the URL of the Package
    pub fn get_url(&self) -> Result<&String> {
        match self.get_origin() {
            PackageFrom::LocalDatabase => self._cache_get_url(),
            _ => unimplemented!(),
        }
        // return self.ops.get_url(self);
    }

    /// Set the URL of the Package
    pub fn set_url(&mut self, url: String) {
        self.url = url;
    }

    pub fn get_builddate(&self) -> Result<Time> {
        match self.get_origin() {
            PackageFrom::LocalDatabase => self._cache_get_builddate(),
            _ => unimplemented!(),
        }
    }

    pub fn get_installdate(&self) -> Result<Time> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_installdate(),
            _ => unimplemented!(),
        }
    }

    pub fn get_packager(&mut self) -> Result<&String> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_packager(),
            _ => unimplemented!(),
        }
        // 	return pkg->ops->get_packager(pkg);
    }

    pub fn md5sum(&self) -> &String {
        return &self.md5sum;
    }

    pub fn sha256sum(&self) -> &String {
        return &self.sha256sum;
    }

    pub fn base64_sig(&self) -> &String {
        return &self.base64_sig;
    }

    pub fn get_arch(&self) -> Result<&String> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_arch(),
            _ => unimplemented!(),
        }
        // return self.ops.get_arch(self);
    }

    pub fn get_size(&self) -> i64 {
        return self.size;
    }

    pub fn get_isize(&mut self, db: &mut Database) -> Result<i64> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_isize(db),
            _ => unimplemented!(),
        }
        // return self.ops.get_isize(pkg);
    }

    pub fn get_reason(&mut self, db: &mut Database) -> Result<&PackageReason> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_reason(db),
            _ => unimplemented!(),
        }
        //return pkg.ops.get_reason(pkg);
    }

    pub fn get_validation(&mut self, db: &mut Database) -> Result<i32> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_validation(db),
            _ => unimplemented!(),
        }
    }

    pub fn get_licenses(&mut self, db: &mut Database) -> &Vec<String> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_licenses(db),
            _ => unimplemented!(),
        }
        // 	return pkg->ops->get_licenses(pkg);
    }

    pub fn get_groups(&mut self, db: &mut Database) -> &Vec<String> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_groups(db),
            _ => unimplemented!(),
        }
        // 	return pkg->ops->get_groups(pkg);
    }

    pub fn get_depends(&self) -> &Vec<Dependency> {
        return &self.depends;
    }

    pub fn get_optdepends(&mut self, db: &mut Database) -> &Vec<Dependency> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_optdepends(db),
            _ => unimplemented!(),
        }
        // return pkg->ops->get_optdepends(pkg);
    }

    pub fn get_checkdepends(&self) -> Vec<Dependency> {
        unimplemented!();
        // return pkg->ops->get_checkdepends(pkg);
    }

    pub fn get_makedepends(&self) -> Vec<Dependency> {
        unimplemented!();
        // return pkg->ops->get_makedepends(pkg);
    }

    pub fn get_conflicts(&mut self, db: &mut Database) -> &Vec<Dependency> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_conflicts(db),
            _ => unimplemented!(),
        }
        // return pkg->ops->get_conflicts(pkg);
    }

    pub fn get_provides(&mut self, db: &mut Database) -> &Vec<Dependency> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_provides(db),
            _ => unimplemented!(),
        }
        // return pkg->ops->get_provides(pkg);
    }

    pub fn get_replaces(&mut self, db: &mut Database) -> &Vec<Dependency> {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_get_replaces(db),
            _ => unimplemented!(),
        }
        // return pkg->ops->get_replaces(pkg);
    }

    pub fn get_deltas(&self) -> &Vec<String> {
        unimplemented!();
        // return pkg->deltas;
    }

    pub fn get_files(&self) -> Vec<String> {
        unimplemented!();
        // return pkg->ops->get_files(pkg);
    }

    pub fn get_backup(&self) -> Vec<String> {
        unimplemented!();
        // return pkg->ops->get_backup(pkg);
    }

    // pub fn alpm_pkg_get_db(&self) -> &Database {
    //     unimplemented!();
    //     // return &self.db;
    // }

    /** Open a package changelog for reading. */
    pub fn changelog_open(&self) {
        unimplemented!();
        // return pkg->ops->changelog_open(pkg);
    }

    // /// Read data from an open changelog 'file stream'.
    // pub fn changelog_read(void *ptr, size_t size,
    // 		const &self, void *fp) -> usize
    // {
    //     unimplemented!();
    // 	// return pkg->ops->changelog_read(ptr, size, pkg, fp);
    // }

    /// Close a package changelog for reading.
    // pub fn changelog_close(const &self, void *fp) -> i64
    // {
    //     unimplemented!();
    // 	// return pkg->ops->changelog_close(pkg, fp);
    // }

    /// Open a package mtree file for reading.
    // pub fn mtree_open(&self) -> archive {
    //     unimplemented!();
    //     // return pkg->ops->mtree_open(pkg);
    // }

    /// Read entry from an open mtree file.
    // int SYMEXPORT _mtree_next(const Package * pkg, struct archive *archive,
    // 	struct archive_entry **entry)
    // {
    // 	ASSERT(pkg != NULL, return -1);
    // 	pkg->handle->pm_errno = ALPM_ERR_OK;
    // 	return pkg->ops->mtree_next(pkg, archive, entry);
    // }

    /// Close a package mtree file for reading.
    // pub fn mtree_close(&self, archive: &archive) -> i64 {
    //     unimplemented!();
    //     // 	return pkg->ops->mtree_close(pkg, archive);
    // }

    pub fn has_scriptlet(&mut self, db: &mut Database) -> i32 {
        match self.origin {
            PackageFrom::LocalDatabase => self._cache_has_scriptlet(db),
            _ => unimplemented!(),
        }
        // 	return pkg->ops->has_scriptlet(pkg);
    }

    fn find_requiredby(&self, db: &mut Database, reqs: &mut Vec<String>, optional: i8) {
        let mut db_clone = db.clone();
        for cachepkg in db.get_pkgcache_mut().unwrap() {
            let j;
            let cachepkgname = cachepkg.name.clone();

            if optional == 0 {
                j = cachepkg.get_depends();
            } else {
                j = cachepkg.get_optdepends(&mut db_clone);
            }
            for data in j {
                if self.depcmp(data) {
                    if !reqs.contains(&cachepkgname) {
                        reqs.push(cachepkgname.clone());
                    }
                }
            }
        }
    }

    /** Compute the packages requiring a given package. */
    pub fn compute_requiredby(
        &self,
        optional: i8,
        db_local: &mut Database,
        dbs_sync: &mut Vec<Database>,
    ) -> Vec<String> {
        // 	const alpm_list_t *i;
        // 	alpm_list_t *reqs = NULL;
        // 	Database *db;
        let db: Database;
        let mut reqs = Vec::new();
        //
        // 	ASSERT(pkg != NULL, return NULL);
        // 	pkg->handle->pm_errno = ALPM_ERR_OK;
        match self.origin {
            PackageFrom::File => {
                /* The sane option; search locally for things that require this. */
                self.find_requiredby(db_local, &mut reqs, optional);
            }
            PackageFrom::LocalDatabase => {
                self.find_requiredby(db_local, &mut reqs, optional);
            }
            PackageFrom::SyncDatabase => {
                for db in dbs_sync {
                    // db = i->data;
                    self.find_requiredby(db, &mut reqs, optional);
                }
                unimplemented!();
                // reqs = alpm_list_msort(reqs, alpm_list_count(reqs), _alpm_str_cmp);
            }
        }

        return reqs;
    }

    /** Compute the packages optionally requiring a given package. */
    pub fn compute_optionalfor(
        &self,
        db_local: &mut Database,
        dbs_sync: &mut Vec<Database>,
    ) -> Vec<String> {
        self.compute_requiredby(1, db_local, dbs_sync)
    }

    // alpm_file_t *_alpm_file_copy(alpm_file_t *dest,
    // 		const alpm_file_t *src)
    // {
    // 	STRDUP(dest->name, src->name, return NULL);
    // 	dest->size = src->size;
    // 	dest->mode = src->mode;
    //
    // 	return dest;
    // }

    // static alpm_list_t *list_depdup(alpm_list_t *old)
    // {
    // 	alpm_list_t *i, *new = NULL;
    // 	for(i = old; i; i = i->next) {
    // 		new = alpm_list_add(new, _alpm_dep_dup(i->data));
    // 	}
    // 	return new;
    // }
    //

    /// Duplicate a package data struct.
    /// * `pkg` - the package to duplicate
    /// * `new_ptr` - location to store duplicated package pointer
    /// * returns 0 on success, -1 on fatal error, 1 on non-fatal error
    pub fn dup(&self) -> Result<Package> {
        unimplemented!();
        // 	Package *newpkg;
        // 	alpm_list_t *i;
        // 	int ret = 0;
        //
        // 	if(!pkg || !pkg->handle) {
        // 		return -1;
        // 	}
        //
        // 	if(!new_ptr) {
        // 		RET_ERR(pkg->handle, ALPM_ERR_WRONG_ARGS, -1);
        // 	}
        //
        // 	if(pkg->ops->force_load(pkg)) {
        // 		_alpm_log(pkg->handle, ALPM_LOG_WARNING,
        // 				_("could not fully load metadata for package %s-%s\n"),
        // 				pkg->name, pkg->version);
        // 		ret = 1;
        // 		pkg->handle->pm_errno = ALPM_ERR_PKG_INVALID;
        // 	}
        //
        // 	CALLOC(newpkg, 1, sizeof(Package), goto cleanup);
        //
        // 	newpkg->name_hash = pkg->name_hash;
        // 	STRDUP(newpkg->filename, pkg->filename, goto cleanup);
        // 	STRDUP(newpkg->base, pkg->base, goto cleanup);
        // 	STRDUP(newpkg->name, pkg->name, goto cleanup);
        // 	STRDUP(newpkg->version, pkg->version, goto cleanup);
        // 	STRDUP(newpkg->desc, pkg->desc, goto cleanup);
        // 	STRDUP(newpkg->url, pkg->url, goto cleanup);
        // 	newpkg->builddate = pkg->builddate;
        // 	newpkg->installdate = pkg->installdate;
        // 	STRDUP(newpkg->packager, pkg->packager, goto cleanup);
        // 	STRDUP(newpkg->md5sum, pkg->md5sum, goto cleanup);
        // 	STRDUP(newpkg->sha256sum, pkg->sha256sum, goto cleanup);
        // 	STRDUP(newpkg->arch, pkg->arch, goto cleanup);
        // 	newpkg->size = pkg->size;
        // 	newpkg->isize = pkg->isize;
        // 	newpkg->scriptlet = pkg->scriptlet;
        // 	newpkg->reason = pkg->reason;
        // 	newpkg->validation = pkg->validation;
        //
        // 	newpkg->licenses   = alpm_list_strdup(pkg->licenses);
        // 	newpkg->replaces   = list_depdup(pkg->replaces);
        // 	newpkg->groups     = alpm_list_strdup(pkg->groups);
        // 	for(i = pkg->backup; i; i = i->next) {
        // 		newpkg->backup = alpm_list_add(newpkg->backup, _alpm_backup_dup(i->data));
        // 	}
        // 	newpkg->depends    = list_depdup(pkg->depends);
        // 	newpkg->optdepends = list_depdup(pkg->optdepends);
        // 	newpkg->conflicts  = list_depdup(pkg->conflicts);
        // 	newpkg->provides   = list_depdup(pkg->provides);
        // 	for(i = pkg->deltas; i; i = i->next) {
        // 		newpkg->deltas = alpm_list_add(newpkg->deltas, _alpm_delta_dup(i->data));
        // 	}
        //
        // 	if(pkg->files.count) {
        // 		size_t filenum;
        // 		size_t len = sizeof(alpm_file_t) * pkg->files.count;
        // 		MALLOC(newpkg->files.files, len, goto cleanup);
        // 		for(filenum = 0; filenum < pkg->files.count; filenum++) {
        // 			if(!_alpm_file_copy(newpkg->files.files + filenum,
        // 						pkg->files.files + filenum)) {
        // 				goto cleanup;
        // 			}
        // 		}
        // 		newpkg->files.count = pkg->files.count;
        // 	}
        //
        // 	/* internal */
        // 	newpkg->infolevel = pkg->infolevel;
        // 	newpkg->origin = pkg->origin;
        // 	if(newpkg->origin == File) {
        // 		STRDUP(newpkg->origin_data.file, pkg->origin_data.file, goto cleanup);
        // 	} else {
        // 		newpkg->origin_data.db = pkg->origin_data.db;
        // 	}
        // 	newpkg->ops = pkg->ops;
        // 	newpkg->handle = pkg->handle;
        //
        // 	*new_ptr = newpkg;
        // 	return ret;
        //
        // cleanup:
        // 	RET_ERR(pkg->handle, ALPM_ERR_MEMORY, -1);
    }

    /// Is spkg an upgrade for localpkg?
    pub fn compare_versions(&self, localpkg: &Package) -> i8 {
        alpm_pkg_vercmp(&self.version, &localpkg.version)
    }

    fn lazy_load(&mut self, info: i32, db: &mut Database) {
        if self.infolevel & info == 0 {
            self.local_db_read(db, info);
        }
    }

    fn _cache_get_base(&self) -> Result<&String> {
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        }
        return Ok(&self.base);
    }

    fn _cache_get_desc(&self) -> Result<&String> {
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        }
        return Ok(&self.desc);
    }

    fn _cache_get_url(&self) -> Result<&String> {
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        }
        return Ok(&self.url);
    }

    fn _cache_get_builddate(&self) -> Result<Time> {
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        }
        return Ok(self.builddate);
    }

    fn _cache_get_installdate(&self) -> Result<Time> {
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        }
        Ok(self.installdate)
    }

    fn _cache_get_packager(&self) -> Result<&String> {
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        }
        Ok(&self.packager)
    }

    fn _cache_get_arch(&self) -> Result<&String> {
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        }
        Ok(&self.arch)
    }

    fn _cache_get_isize(&mut self, db: &mut Database) -> Result<i64> {
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        }
        Ok(self.isize)
    }

    fn _cache_get_reason(&mut self, db: &mut Database) -> Result<&PackageReason> {
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        }
        Ok(&self.reason)
    }

    fn _cache_get_validation(&mut self, db: &mut Database) -> Result<i32> {
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        }
        Ok(self.validation)
    }

    fn _cache_get_licenses(&mut self, db: &mut Database) -> &Vec<String> {
        self.lazy_load(INFRQ_DESC, db);
        return &self.licenses;
    }

    fn _cache_get_groups(&mut self, db: &mut Database) -> &Vec<String> {
        self.lazy_load(INFRQ_DESC, db);
        return &self.groups;
    }

    fn _cache_has_scriptlet(&mut self, db: &mut Database) -> i32 {
        self.lazy_load(INFRQ_SCRIPTLET, db);
        return self.scriptlet;
    }

    fn _cache_get_depends(&mut self, db: &mut Database) -> &Vec<Dependency> {
        self.lazy_load(INFRQ_DESC, db);
        return &self.depends;
    }

    fn _cache_get_optdepends(&mut self, db: &mut Database) -> &Vec<Dependency> {
        self.lazy_load(INFRQ_DESC, db);
        return &self.optdepends;
    }

    fn _cache_get_conflicts(&mut self, db: &mut Database) -> &Vec<Dependency> {
        self.lazy_load(INFRQ_DESC, db);
        return &self.conflicts;
    }

    fn _cache_get_provides(&mut self, db: &mut Database) -> &Vec<Dependency> {
        self.lazy_load(INFRQ_DESC, db);
        return &self.provides;
    }

    fn _cache_get_replaces(&mut self, db: &mut Database) -> &Vec<Dependency> {
        self.lazy_load(INFRQ_DESC, db);
        return &self.replaces;
    }

    // pub fn _cache_get_files(&mut self, db: &mut Database) {
    //     self.lazy_load(INFRQ_DESC, db);
    //     return &self.files;
    // }

    fn _cache_get_backup(&mut self, db: &mut Database) -> &Vec<String> {
        self.lazy_load(INFRQ_FILES, db);
        return &self.backup;
    }

    ///Open a package changelog for reading. Similar to fopen in functionality,
    ///except that the returned 'file stream' is from the database.
    ///@param pkg the package (from db) to read the changelog
    ///@return a 'file stream' to the package changelog
    fn _cache_changelog_open(&self) -> std::fs::File {
        unimplemented!();
        //     let db = self.alpm_pkg_get_db();
        //     let clfile = db._alpm_local_db_pkgpath(self, "changelog");
        //     let f = std::fs::File::open(clfile);
        //     // 	free(clfile);
        //     return f.unwrap();
    }

    ///Read data from an open changelog 'file stream'. Similar to fread in
    ///functionality, this function takes a buffer and amount of data to read.
    ///@param ptr a buffer to fill with raw changelog data
    ///@param size the size of the buffer
    ///@param pkg the package that the changelog is being read from
    ///@param fp a 'file stream' to the package changelog
    ///@return the number of characters read, or 0 if there is no more data
    // static size_t _cache_changelog_read(void *ptr, size_t size,
    // 		const Package UNUSED *pkg, void *fp)
    // {
    // 	return fread(ptr, 1, size, (FILE *)fp);
    // }

    ///Close a package changelog for reading. Similar to fclose in functionality,
    ///except that the 'file stream' is from the database.
    ///@param pkg the package that the changelog was read from
    ///@param fp a 'file stream' to the package changelog
    ///@return whether closing the package changelog stream was successful
    // static int _cache_changelog_close(const Package UNUSED *pkg, void *fp)
    // {
    // 	return fclose((FILE *)fp);
    // }

    ///Open a package mtree file for reading.
    ///@param pkg the local package to read the changelog of
    ///@return a archive structure for the package mtree file
    // static struct archive *_cache_mtree_open(&self)
    // {
    // 	int r;
    // 	struct archive *mtree;
    //
    // 	Database *db = alpm_pkg_get_db(pkg);
    // 	char *mtfile = _alpm_local_db_pkgpath(db, pkg, "mtree");
    //
    // 	if(access(mtfile, F_OK) != 0) {
    // 		/* there is no mtree file for this package */
    // 		goto error;
    // 	}
    //
    // 	if((mtree = archive_read_new()) == NULL) {
    // 		pkg.handle.pm_errno = ALPM_ERR_LIBARCHIVE;
    // 		goto error;
    // 	}
    //
    // 	_alpm_archive_read_support_filter_all(mtree);
    // 	archive_read_support_format_mtree(mtree);
    //
    // 	if((r = _alpm_archive_read_open_file(mtree, mtfile, ALPM_BUFFER_SIZE))) {
    // 		_alpm_log(pkg.handle, ALPM_LOG_ERROR, _("error while reading file {}: {}"),
    // 					mtfile, archive_error_string(mtree));
    // 		pkg.handle.pm_errno = ALPM_ERR_LIBARCHIVE;
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

    ///Read next entry from a package mtree file.
    /// @param pkg the package that the mtree file is being read from
    /// @param archive the archive structure reading from the mtree file
    /// @param entry an archive_entry to store the entry header information
    ///@return 0 if end of archive is reached, non-zero otherwise.
    // static int _cache_mtree_next(const Package UNUSED *pkg,
    // 		struct archive *mtree, struct archive_entry **entry)
    // {
    // 	return archive_read_next_header(mtree, entry);
    // }

    ///Close a package mtree file for reading.
    ///@param pkg the package that the mtree file was read from
    ///@param mtree the archive structure use for reading from the mtree file
    ///@return whether closing the package changelog stream was successful
    // static int _cache_mtree_close(const Package UNUSED *pkg,
    // 		struct archive *mtree)
    // {
    // 	return _alpm_archive_read_free(mtree);
    // }

    fn _cache_force_load(&mut self, db: &mut Database) -> i32 {
        return self.local_db_read(db, INFRQ_ALL);
    }

    // fn is_dir(path: &Path, entry: dirent) -> i32 {
    //     unimplemented!();
    //     // #ifdef HAVE_STRUCT_DIRENT_D_TYPE
    //     // 	if(entry.d_type != DT_UNKNOWN) {
    //     // 		return (entry.d_type == DT_DIR);
    //     // 	}
    //     // #endif
    //     // 	{
    //     // 		char buffer[PATH_MAX];
    //     // 		struct stat sbuf;
    //     //
    //     // 		snprintf(buffer, PATH_MAX, "{}/{}", path, entry.d_name);
    //     //
    //     // 		if(!stat(buffer, &sbuf)) {
    //     // 			return S_ISDIR(sbuf.st_mode);
    //     // 		}
    //     // 	}
    //     //
    //     // 	return 0;
    // }

    fn write_deps(fp: File, header: &String, deplist: Vec<Dependency>) {
        unimplemented!();
        // 	alpm_list_t *lp;
        // 	if(!deplist) {
        // 		return;
        // 	}
        // 	fputs(header, fp);
        // 	fputc('', fp);
        // 	for(lp = deplist; lp; lp = lp.next) {
        // 		char *depstring = alpm_dep_compute_string(lp.data);
        // 		fputs(depstring, fp);
        // 		fputc('', fp);
        // 		free(depstring);
        // 	}
        // 	fputc('', fp);
    }

    pub fn set_reason(&mut self, reason: PackageReason) -> i32 {
        // debug!("setting install reason {} for {}", reason, self.get_name());
        /* set reason (in pkgcache) */
        self.reason = reason;
        // 	/* write DESC */
        // 	if(_alpm_local_db_write(pkg->handle->db_local, pkg, INFRQ_DESC)) {
        // 		RET_ERR(pkg->handle, ALPM_ERR_DB_WRITE, -1);
        // 	}
        //
        return 0;
    }

    /** Compute the size of the files that will be downloaded to install a
     * package.
     * @param newpkg the new package to upgrade to
     */
    pub fn compute_download_size(&self) -> i32 {
        // 	const char *fname;
        // 	char *fpath, *fnamepart = NULL;
        // 	off_t size = 0;
        // 	alpm_handle_t *handle = newpkg.handle;
        // 	int ret = 0;
        //
        // 	if(newpkg.origin != SyncDatabase) {
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
        unimplemented!();
    }

    pub fn local_db_read(&mut self, db: &Database, inforeq: i32) -> i32 {
        enum NextLineType {
            None,
            Name,
            Version,
            Base,
            Desc,
            Groups,
            Url,
            License,
            Arch,
            BuildDate,
            InstallDate,
            Packager,
            Reason,
            Validation,
            Size,
            Replaces,
            Depends,
            OptDepends,
            Confilcts,
            Provides,
            Files,
            Backup,
        }

        /* bitmask logic here:
         * infolevel: 00001111
         * inforeq:   00010100
         * & result:  00000100
         * == to inforeq? nope, we need to load more info. */
        if (self.infolevel & inforeq) == inforeq {
            /* already loaded all of this info, do nothing */
            return 0;
        }

        if self.infolevel & INFRQ_ERROR != 0 {
            /* We've encountered an error loading this package before. Don't attempt
             * repeated reloads, just give up. */
            return -1;
        }

        info!(
            "loading package data for {} : level=0x{:x}",
            self.get_name(),
            inforeq
        );

        /* DESC */
        if inforeq & INFRQ_DESC != 0 && (self.infolevel & INFRQ_DESC) == 0 {
            let path = db.local_db_pkgpath(self, &String::from("desc"));
            let mut fp = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    error!("could not open file {}: {}", path, e);
                    self.infolevel |= INFRQ_ERROR;
                    return -1;
                }
            };
            use std::io::prelude::*;
            let mut lines: String = String::new();
            match fp.read_to_string(&mut lines) {
                Ok(_) => {}
                Err(_) => {
                    return -1;
                }
            }

            let lines_iter = lines.lines();
            let mut next_line_type = NextLineType::None;
            for mut line in lines_iter {
                if String::from(line).trim().len() == 0 {
                    /* length of stripped line was zero */
                    continue;
                }

                match next_line_type {
                    NextLineType::None => {}
                    NextLineType::Name => {
                        if line != self.get_name() {
                            error!(
                                "{} database is inconsistent: name mismatch on package {}",
                                db.get_name(),
                                self.get_name()
                            );
                        }
                    }
                    NextLineType::Version => {
                        if line != self.get_version() {
                            error!(
                                "{} database is inconsistent: version mismatch on package {}",
                                db.get_name(),
                                self.get_name()
                            );
                        }
                    }
                    NextLineType::Base => {
                        self.set_base(line);
                    }
                    NextLineType::Desc => {
                        self.set_desc(String::from(line));
                    }
                    NextLineType::Groups => {
                        if line != "" {
                            self.groups.push(String::from(line));
                            continue;
                        }
                    }
                    NextLineType::Url => {
                        self.set_url(String::from(line));
                    }
                    NextLineType::License => {
                        if line != "" {
                            self.licenses.push(String::from(line));
                            continue;
                        }
                    }
                    NextLineType::Arch => {
                        self.arch = String::from(line);
                    }
                    NextLineType::BuildDate => {
                        self.builddate = _alpm_parsedate(line);
                    }
                    NextLineType::InstallDate => {
                        self.installdate = _alpm_parsedate(line);
                    }
                    NextLineType::Packager => {
                        self.packager = String::from(line);
                    }
                    NextLineType::Reason => {
                        self.reason = PackageReason::from(u8::from_str_radix(line, 10).unwrap());
                    }
                    NextLineType::Validation => {
                        unimplemented!();
                        // // alpm_list_t *i, *v = NULL;
                        // READ_AND_STORE_ALL(v);
                        // // for(i = v; i; i = alpm_list_next(i))
                        // {
                        //     if (strcmp(i.data, "none") == 0) {
                        //         info.validation |= ALPM_PKG_VALIDATION_NONE;
                        //     } else if (strcmp(i.data, "md5") == 0) {
                        //         info.validation |= ALPM_PKG_VALIDATION_MD5SUM;
                        //     } else if (strcmp(i.data, "sha256") == 0) {
                        //         info.validation |= ALPM_PKG_VALIDATION_SHA256SUM;
                        //     } else if (strcmp(i.data, "pgp") == 0) {
                        //         info.validation |= ALPM_PKG_VALIDATION_SIGNATURE;
                        //     } else {
                        //         info!(
                        //             "unknown validation type for package {}: {}",
                        //             pkg.get_name(), i.data
                        //         );
                        //     }
                        // }
                        // FREELIST(v);
                    }
                    NextLineType::Size => {
                        self.isize = _alpm_strtoofft(&String::from(line));
                    }
                    NextLineType::Replaces => {
                        if line != "" {
                            self.replaces.push(alpm_dep_from_string(&String::from(line)));
                            continue;
                        };
                    }
                    NextLineType::Depends => {
                        if line != "" {
                            self.depends.push(alpm_dep_from_string(&String::from(line)));
                            continue;
                        };
                    }
                    NextLineType::OptDepends => {
                        if line != "" {
                            self.optdepends
                                .push(alpm_dep_from_string(&String::from(line)));
                            continue;
                        };
                    }
                    NextLineType::Confilcts => {
                        if line != "" {
                            self.conflicts
                                .push(alpm_dep_from_string(&String::from(line)));
                            continue;
                        };
                    }
                    NextLineType::Provides => {
                        if line != "" {
                            self.provides.push(alpm_dep_from_string(&String::from(line)));
                            continue;
                        };
                    }
                    _ => {}
                }

                next_line_type = NextLineType::None;

                if line == "%NAME%" {
                    next_line_type = NextLineType::Name;
                } else if line == "%VERSION%" {
                    next_line_type = NextLineType::Version;
                } else if line == "%BASE%" {
                    next_line_type = NextLineType::Base;
                } else if line == "%DESC%" {
                    next_line_type = NextLineType::Desc;
                } else if line == "%GROUPS%" {
                    next_line_type = NextLineType::Groups;
                } else if line == "%URL%" {
                    next_line_type = NextLineType::Url;
                } else if line == "%LICENSE%" {
                    next_line_type = NextLineType::License;
                } else if line == "%ARCH%" {
                    next_line_type = NextLineType::Arch;
                } else if line == "%BUILDDATE%" {
                    next_line_type = NextLineType::BuildDate;
                } else if line == "%INSTALLDATE%" {
                    next_line_type = NextLineType::InstallDate;
                } else if line == "%PACKAGER%" {
                    next_line_type = NextLineType::Packager;
                } else if line == "%REASON%" {
                    next_line_type = NextLineType::Reason;
                } else if line == "%VALIDATION%" {
                    next_line_type = NextLineType::Validation;
                } else if line == "%SIZE%" {
                    next_line_type = NextLineType::Size;
                } else if line == "%REPLACES%" {
                    next_line_type = NextLineType::Replaces;
                } else if line == "%DEPENDS%" {
                    next_line_type = NextLineType::Depends;
                } else if line == "%OPTDEPENDS%" {
                    next_line_type = NextLineType::OptDepends;
                } else if line == "%CONFLICTS%" {
                    next_line_type = NextLineType::Confilcts;
                } else if line == "%PROVIDES%" {
                    next_line_type = NextLineType::Provides;
                }
            }
            self.infolevel |= INFRQ_DESC;
        }

        /* FILES */
        if inforeq & INFRQ_FILES != 0 && (self.infolevel & INFRQ_FILES) == 0 {
            unimplemented!();
            let path = db.local_db_pkgpath(self, &String::from("desc"));
            let mut fp = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    error!("could not open file {}: {}", path, e);
                    self.infolevel |= INFRQ_ERROR;
                    return -1;
                }
            };
            use std::io::prelude::*;
            let mut lines: String = String::new();
            match fp.read_to_string(&mut lines) {
                Ok(_) => {}
                Err(e) => {
                    return -1;
                }
            }

            let lines_iter = lines.lines();
            let mut next_line_type = NextLineType::None;
            let mut files_count = 0;
            let mut files_size = 0;
            let mut len = 0;
            let mut files = Vec::new();
            for mut line in lines_iter {
                match next_line_type {
                    NextLineType::Files => {
                        if line == "" {
                            next_line_type = NextLineType::None;
                            // info.files.count = files_count;
                            // info.files.files = files;
                            // _alpm_filelist_sort(&info.files);
                            continue;
                        }
                        files.push(line);
                    }
                    NextLineType::Backup => {
                        if line == "" {
                            next_line_type = NextLineType::None;
                            continue;
                        }
                        // let backup: alpm_backup_t;
                        // if (_alpm_split_backup(line, &backup)) {
                        //     info.infolevel |= INFRQ_ERROR;
                        //     return -1;
                        // }
                        // info.backup.push(backup);
                    }
                    _ => {}
                }
                unimplemented!();
                if line == "%FILES%" {
                    next_line_type = NextLineType::Files;
                } else if line == "%BACKUP%" {
                    next_line_type = NextLineType::Backup;
                }
            }
            self.infolevel |= INFRQ_FILES;
        }

        /* INSTALL */
        if inforeq & INFRQ_SCRIPTLET != 0 && (self.infolevel & INFRQ_SCRIPTLET) == 0 {
            let path = db.local_db_pkgpath(self, &String::from("install"));
            use std::path::Path;
            let install_path = Path::new(&path);
            if install_path.exists() {
                self.scriptlet = 1;
            }
            self.infolevel |= INFRQ_SCRIPTLET;
        }

        return 0;

        // error:
        // 	info->infolevel |= INFRQ_ERROR;
        // 	if(fp) {
        // 		fclose(fp);
        // 	}
        // 	return -1;
    }
}

use std::cmp;
impl cmp::Ord for Package {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.name.cmp(&other.name)
    }
}
impl PartialOrd for Package {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Package {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}
impl Eq for Package {}
/// Helper function for comparing packages
pub fn pkg_cmp(pkg1: &Package, pkg2: &Package) -> std::cmp::Ordering {
    pkg1.name.cmp(&pkg2.name)
}

/// Find a package in a list by name.
///
/// * `haystack` - a Vec of Package
/// * `needle` - the package name
///
/// returns a pointer to the package if found or None
pub fn alpm_pkg_find<'a>(haystack: &'a mut Vec<Package>, needle: &String) -> Option<&'a Package> {
    haystack.sort();
    match haystack.binary_search_by_key(needle, |ref a| a.name.clone()) {
        Ok(i) => {
            return Some(&haystack[i]);
        }
        Err(_) => return None,
    }
}
