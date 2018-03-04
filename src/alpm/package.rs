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

    // alpm_filelist_t files;

    /* origin == PKG_FROM_FILE, use pkg->origin_data.file
     * origin == PKG_FROM_*DB, use pkg->origin_data.db */
    // pub db: Database,
    file: String,
    origin: PackageFrom,
    reason: PackageReason,
    scriptlet: i32,

    /* Bitfield from alpm_dbinfrq_t */
    infolevel: i32,
    /* Bitfield from alpm_pkgvalidation_t */
    validation: i32,
}

const T_ARCHITECTURE: &str = "Architecture";
const T_BACKUP_FILES: &str = "Backup Files";
const T_BUILD_DATE: &str = "Build Date";
const T_COMPRESSED_SIZE: &str = "Compressed Size";
const T_CONFLICTS_WITH: &str = "Conflicts With";
const T_DEPENDS_ON: &str = "Depends On";
const T_DESCRIPTION: &str = "Description";
const T_DOWNLOAD_SIZE: &str = "Download Size";
const T_GROUPS: &str = "Groups";
const T_INSTALL_DATE: &str = "Install Date";
const T_INSTALL_REASON: &str = "Install Reason";
const T_INSTALL_SCRIPT: &str = "Install Script";
const T_INSTALLED_SIZE: &str = "Installed Size";
const T_LICENSES: &str = "Licenses";
const T_MD5_SUM: &str = "MD5 Sum";
const T_NAME: &str = "Name";
const T_OPTIONAL_DEPS: &str = "Optional Deps";
const T_OPTIONAL_FOR: &str = "Optional For";
const T_PACKAGER: &str = "Packager";
const T_PROVIDES: &str = "Provides";
const T_REPLACES: &str = "Replaces";
const T_REPOSITORY: &str = "Repository";
const T_REQUIRED_BY: &str = "Required By";
const T_SHA_256_SUM: &str = "SHA-256 Sum";
const T_SIGNATURES: &str = "Signatures";
const T_URL: &str = "URL";
const T_VALIDATED_BY: &str = "Validated By";
const T_VERSION: &str = "Version";

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
    fn _sync_get_validation(&self) -> i32 {
        unimplemented!();
        // if self.validation != 0 {
        //     return self.validation;
        // }
        //
        // if self.md5sum != "" {
        //     self.validation |= ALPM_PKG_VALIDATION_MD5SUM;
        // }
        // if self.sha256sum != "" {
        //     self.validation |= ALPM_PKG_VALIDATION_SHA256SUM;
        // }
        // if self.base64_sig != "" {
        //     self.validation |= ALPM_PKG_VALIDATION_SIGNATURE;
        // }
        //
        // if !self.validation == 0 {
        //     self.validation |= ALPM_PKG_VALIDATION_NONE;
        // }
        //
        // return self.validation;
    }

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

    pub fn depcmp_literal(&self, dep: &Dependency) -> bool {
        if self.name != dep.name {
            /* skip more expensive checks */
            return false;
        }
        return dep_vercmp(&self.version, &dep.depmod, &dep.version);
    }

    pub fn depcmp(&self, dep: &Dependency) -> bool {
        return self.depcmp_literal(dep) || dep.provides(&self.provides);
    }

    pub fn get_filename(&self) -> String {
        return self.filename.clone();
    }

    pub fn get_base(&self) -> String {
        unimplemented!();
        // return self.ops.get_base(self);
    }

    // pub fn set_base(&mut self, base: &str) {
    //     self.name = String::from(base);
    // }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn set_name(&mut self, name: &String) {
        self.name = name.clone();
    }

    pub fn set_name_hash(&mut self, name_hash: u64) {
        self.name_hash = name_hash;
    }

    pub fn get_name_hash(&mut self) -> u64 {
        self.name_hash
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

    /// Get the description of the package
    pub fn get_desc(&self) -> Result<&String> {
        match self.get_origin() {
            PackageFrom::LocalDatabase => {
                if self.infolevel & INFRQ_DESC == 0 {
                    return Err(Error::PkgNotLoaded);
                }
                return Ok(&self.desc);
            }
            _ => unimplemented!(),
        }
        // return self.ops.get_desc(self);
    }

    /// Sets the description of the package
    pub fn set_desc(&mut self, desc: String) {
        self.desc = desc
    }

    /// Gets the URL of the Package
    pub fn get_url(&self) -> Result<&String> {
        if self.infolevel & INFRQ_DESC == 0 {
            Err(Error::PkgNotLoaded)
        } else {
            Ok(&self.url)
        }
        // return self.ops.get_url(self);
    }

    /// Get the build date
    pub fn get_builddate(&self) -> Result<Time> {
        if self.infolevel & INFRQ_DESC == 0 {
            Err(Error::PkgNotLoaded)
        } else {
            Ok(self.builddate)
        }
    }

    /// Get the install date of the package
    pub fn get_installdate(&self) -> Result<Time> {
        if self.infolevel & INFRQ_DESC == 0 {
            Err(Error::PkgNotLoaded)
        } else {
            Ok(self.installdate)
        }
    }

    /// Get the packager of the package
    pub fn packager(&self) -> Result<&String> {
        if self.infolevel & INFRQ_DESC == 0 {
            Err(Error::PkgNotLoaded)
        } else {
            Ok(&self.packager)
        }
        // 	return pkg->ops->get_packager(pkg);
    }

    /// Gets the md5sum of the package
    pub fn md5sum(&self) -> &String {
        return &self.md5sum;
    }

    /// Gets the sha256sum of the package
    pub fn sha256sum(&self) -> &String {
        return &self.sha256sum;
    }

    pub fn base64_sig(&self) -> &String {
        return &self.base64_sig;
    }

    /// Get the architecture of the package
    pub fn get_arch(&self) -> Result<&String> {
        if self.infolevel & INFRQ_DESC == 0 {
            Err(Error::PkgNotLoaded)
        } else {
            Ok(&self.arch)
        }
        // return self.ops.get_arch(self);
    }

    /// Get the size of the package
    pub fn get_size(&self) -> i64 {
        return self.size;
    }

    pub fn get_isize(&self) -> Result<i64> {
        match self.origin {
            PackageFrom::LocalDatabase => {
                if self.infolevel & INFRQ_DESC == 0 {
                    return Err(Error::PkgNotLoaded);
                }
                Ok(self.isize)
            }
            _ => unimplemented!(),
        }
        // return self.ops.get_isize(pkg);
    }

    pub fn get_reason(&self) -> Result<&PackageReason> {
        match self.origin {
            PackageFrom::LocalDatabase => {
                if self.infolevel & INFRQ_DESC == 0 {
                    return Err(Error::PkgNotLoaded);
                }
                Ok(&self.reason)
            }
            _ => unimplemented!(),
        }
        //return pkg.ops.get_reason(pkg);
    }

    pub fn get_validation(&self) -> Result<i32> {
        match self.origin {
            PackageFrom::LocalDatabase => {
                if self.infolevel & INFRQ_DESC == 0 {
                    return Err(Error::PkgNotLoaded);
                }
                Ok(self.validation)
            }
            _ => unimplemented!(),
        }
    }

    pub fn get_licenses(&self) -> Result<&Vec<String>> {
        match self.origin {
            PackageFrom::LocalDatabase => {
                if self.infolevel & INFRQ_DESC == 0 {
                    return Err(Error::PkgNotLoaded);
                }
                Ok(&self.licenses)
            }
            _ => unimplemented!(),
        }
        // 	return pkg->ops->get_licenses(pkg);
    }

    pub fn get_groups(&self) -> Result<&Vec<String>> {
        match self.origin {
            PackageFrom::LocalDatabase => {
                if self.infolevel & INFRQ_DESC == 0 {
                    Err(Error::PkgNotLoaded)
                } else {
                    Ok(&self.groups)
                }
            }
            _ => unimplemented!(),
        }
        // 	return pkg->ops->get_groups(pkg);
    }

    pub fn get_depends(&self) -> Result<&Vec<Dependency>> {
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        } else {
            Ok(&self.depends)
        }
    }

    pub fn get_optdepends(&self) -> Result<&Vec<Dependency>> {
        match self.origin {
            PackageFrom::LocalDatabase => {
                if self.infolevel & INFRQ_DESC == 0 {
                    Err(Error::PkgNotLoaded)
                } else {
                    Ok(&self.optdepends)
                }
            }
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

    pub fn get_conflicts(&self) -> Result<&Vec<Dependency>> {
        match self.origin {
            PackageFrom::LocalDatabase => {
                if self.infolevel & INFRQ_DESC == 0 {
                    Err(Error::PkgNotLoaded)
                } else {
                    Ok(&self.conflicts)
                }
            }
            _ => unimplemented!(),
        }
        // return pkg->ops->get_conflicts(pkg);
    }

    pub fn get_provides(&self) -> Result<&Vec<Dependency>> {
        match self.origin {
            PackageFrom::LocalDatabase => {
                if self.infolevel & INFRQ_DESC == 0 {
                    Err(Error::PkgNotLoaded)
                } else {
                    Ok(&self.provides)
                }
            }
            _ => unimplemented!(),
        }
        // return pkg->ops->get_provides(pkg);
    }

    pub fn get_replaces(&self) -> Result<&Vec<Dependency>> {
        match self.origin {
            PackageFrom::LocalDatabase => {
                if self.infolevel & INFRQ_DESC == 0 {
                    return Err(Error::PkgNotLoaded);
                }
                Ok(&self.replaces)
            }
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

    // / Open a package changelog for reading.
    // pub fn changelog_open(&self) {
    //     unimplemented!();
    //     // return pkg->ops->changelog_open(pkg);
    // }

    // /// Read data from an open changelog 'file stream'.
    // pub fn changelog_read(void *ptr, size_t size,
    // 		const &self, void *fp) -> usize
    // {
    //     unimplemented!();
    // 	// return pkg->ops->changelog_read(ptr, size, pkg, fp);
    // }

    // / Close a package changelog for reading.
    // pub fn changelog_close(const &self, void *fp) -> i64
    // {
    //     unimplemented!();
    // 	// return pkg->ops->changelog_close(pkg, fp);
    // }

    // / Open a package mtree file for reading.
    // pub fn mtree_open(&self) -> archive {
    //     unimplemented!();
    //     // return pkg->ops->mtree_open(pkg);
    // }

    // / Read entry from an open mtree file.
    // int SYMEXPORT _mtree_next(const Package * pkg, struct archive *archive,
    // 	struct archive_entry **entry)
    // {
    // 	ASSERT(pkg != NULL, return -1);
    // 	pkg->handle->pm_errno = ALPM_ERR_OK;
    // 	return pkg->ops->mtree_next(pkg, archive, entry);
    // }

    // / Close a package mtree file for reading.
    // pub fn mtree_close(&self, archive: &archive) -> i64 {
    //     unimplemented!();
    //     // 	return pkg->ops->mtree_close(pkg, archive);
    // }

    /// Checks if the package has a scriptlet
    pub fn has_scriptlet(&self) -> Result<i32> {
        if self.infolevel & INFRQ_SCRIPTLET == 0 {
            Err(Error::PkgNotLoaded)
        } else {
            Ok(self.scriptlet)
        }
        // 	return pkg->ops->has_scriptlet(pkg);
    }

    fn find_requiredby(&self, db: &Database, optional: bool) -> Result<Vec<String>> {
        let mut reqs: Vec<String> = Vec::new();
        for cachepkg in db.get_pkgcache()? {
            let j;
            let cachepkgname = cachepkg.name.clone();

            if optional {
                j = cachepkg.get_optdepends()?;
            } else {
                j = cachepkg.get_depends()?;
            }
            for data in j {
                if self.depcmp(data) {
                    if !reqs.contains(&cachepkgname) {
                        reqs.push(cachepkgname.clone());
                    }
                }
            }
        }

        Ok(reqs)
    }

    /// Compute the packages requiring a given package.
    pub fn compute_requiredby(
        &self,
        optional: bool,
        db_local: &Database,
        dbs_sync: &Vec<Database>,
    ) -> Result<Vec<String>> {
        let mut reqs = Vec::new();

        match self.origin {
            PackageFrom::File => {
                /* The sane option; search locally for things that require this. */
                reqs = self.find_requiredby(db_local, optional)?;
            }
            PackageFrom::LocalDatabase => {
                reqs = self.find_requiredby(db_local, optional)?;
            }
            PackageFrom::SyncDatabase => {
                for db in dbs_sync {
                    reqs = self.find_requiredby(db, optional)?;
                }
                reqs.sort();
            }
        }

        Ok(reqs)
    }

    /// Compute the packages optionally requiring a given package.
    pub fn compute_optionalfor(
        &self,
        db_local: &Database,
        dbs_sync: &Vec<Database>,
    ) -> Result<Vec<String>> {
        self.compute_requiredby(true, db_local, dbs_sync)
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

    // fn lazy_load(&mut self, info: i32, db: &mut Database) {
    //     if self.infolevel & info == 0 {
    //         self.local_db_read(db, info);
    //     }
    // }

    /// Open a package changelog for reading. Similar to fopen in functionality,
    /// except that the returned 'file stream' is from the database.
    /// * `pkg` the package (from db) to read the changelog
    fn _cache_changelog_open(&self) -> std::fs::File {
        unimplemented!();
        //     let db = self.alpm_pkg_get_db();
        //     let clfile = db._alpm_local_db_pkgpath(self, "changelog");
        //     let f = std::fs::File::open(clfile);
        //     // 	free(clfile);
        //     return f.unwrap();
    }

    // /Read data from an open changelog 'file stream'. Similar to fread in
    // /functionality, this function takes a buffer and amount of data to read.
    // /@param ptr a buffer to fill with raw changelog data
    // /@param size the size of the buffer
    // /@param pkg the package that the changelog is being read from
    // /@param fp a 'file stream' to the package changelog
    // /@return the number of characters read, or 0 if there is no more data
    // static size_t _cache_changelog_read(void *ptr, size_t size,
    // 		const Package UNUSED *pkg, void *fp)
    // {
    // 	return fread(ptr, 1, size, (FILE *)fp);
    // }

    // /Close a package changelog for reading. Similar to fclose in functionality,
    // /except that the 'file stream' is from the database.
    // /@param pkg the package that the changelog was read from
    // /@param fp a 'file stream' to the package changelog
    // /@return whether closing the package changelog stream was successful
    // static int _cache_changelog_close(const Package UNUSED *pkg, void *fp)
    // {
    // 	return fclose((FILE *)fp);
    // }

    // /Open a package mtree file for reading.
    // /@param pkg the local package to read the changelog of
    // /@return a archive structure for the package mtree file
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

    // ///Read next entry from a package mtree file.
    // /// @param pkg the package that the mtree file is being read from
    // /// @param archive the archive structure reading from the mtree file
    // /// @param entry an archive_entry to store the entry header information
    // ///@return 0 if end of archive is reached, non-zero otherwise.
    // static int _cache_mtree_next(const Package UNUSED *pkg,
    // 		struct archive *mtree, struct archive_entry **entry)
    // {
    // 	return archive_read_next_header(mtree, entry);
    // }

    // /// Close a package mtree file for reading.
    // /// @param pkg the package that the mtree file was read from
    // /// * `mtree` the archive structure use for reading from the mtree file
    // /// @return whether closing the package changelog stream was successful
    // static int _cache_mtree_close(const Package UNUSED *pkg,
    // 		struct archive *mtree)
    // {
    // 	return _alpm_archive_read_free(mtree);
    // }

    pub fn _cache_force_load(&mut self, db: &mut Database) -> Result<()> {
        self.local_db_read(db, INFRQ_ALL)
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

    /// Compute the size of the files that will be downloaded to install a package.
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

    pub fn local_db_read(&mut self, db: &Database, inforeq: i32) -> Result<()> {
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
            return Ok(());
        }

        if self.infolevel & INFRQ_ERROR != 0 {
            /* We've encountered an error loading this package before. Don't attempt
             * repeated reloads, just give up. */
            return Err(Error::PkgInvalid);
        }

        info!(
            "loading package data for {} : level=0x{:x}",
            self.get_name(),
            inforeq
        );

        /* DESC */
        if inforeq & INFRQ_DESC != 0 && (self.infolevel & INFRQ_DESC) == 0 {
            let path = db.local_db_pkgpath(self, &String::from("desc"))?;
            let mut fp = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    error!("could not open file {}: {}", path, e);
                    self.infolevel |= INFRQ_ERROR;
                    return Err(Error::from(e));
                }
            };
            use std::io::prelude::*;
            let mut lines: String = String::new();
            fp.read_to_string(&mut lines)?;

            let lines_iter = lines.lines();
            let mut next_line_type = NextLineType::None;
            for mut line in lines_iter {
                // if String::from(line).trim().len() == 0 {
                //     /* length of stripped line was zero */
                //     continue;
                // }

                match next_line_type {
                    NextLineType::None => {
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
                        continue;
                    }
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
                        self.base = String::from(line);
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
                        self.url = String::from(line);
                    }
                    NextLineType::License => {
                        if line != "" {
                            self.licenses.push(String::from(line));
                            continue;
                        }
                        next_line_type = NextLineType::None;
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
                        // unimplemented!();
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
                            self.replaces
                                .push(alpm_dep_from_string(&String::from(line)));
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
                            self.provides
                                .push(alpm_dep_from_string(&String::from(line)));
                            continue;
                        };
                    }
                    _ => {}
                }

                next_line_type = NextLineType::None;
            }
            self.infolevel |= INFRQ_DESC;
        }

        /* FILES */
        if inforeq & INFRQ_FILES != 0 && (self.infolevel & INFRQ_FILES) == 0 {
            let path = db.local_db_pkgpath(self, &String::from("desc"))?;
            let mut fp = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    error!("could not open file {}: {}", path, e);
                    self.infolevel |= INFRQ_ERROR;
                    return Err(Error::from(e));
                }
            };
            use std::io::prelude::*;
            let mut lines: String = String::new();
            fp.read_to_string(&mut lines)?;

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
                            unimplemented!();
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
                        unimplemented!();
                        // let backup: alpm_backup_t;
                        // if (_alpm_split_backup(line, &backup)) {
                        //     info.infolevel |= INFRQ_ERROR;
                        //     return -1;
                        // }
                        // info.backup.push(backup);
                    }
                    _ => {}
                }
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
            let path = db.local_db_pkgpath(self, &String::from("install"))?;
            use std::path::Path;
            let install_path = Path::new(&path);
            if install_path.exists() {
                self.scriptlet = 1;
            }
            self.infolevel |= INFRQ_SCRIPTLET;
        }

        return Ok(());

        // error:
        // 	info->infolevel |= INFRQ_ERROR;
        // 	if(fp) {
        // 		fclose(fp);
        // 	}
        // 	return -1;
    }

    /// Display the details of a package.
    /// Extra information entails 'required by' info for sync packages and backup
    /// files info for local packages.
    pub fn dump_full(
        &self,
        extra: bool,
        // config: &Config,
        db_local: &Database,
        dbs_sync: &Vec<Database>,
    ) -> Result<()> {
        // unimplemented!();
        // unsigned short cols;
        let bdate: i64;
        let idate: i64;
        let from: PackageFrom;
        let mut size: f64;
        let mut label: String = String::from("\0");
        let reason: String;
        let mut validation: Vec<String> = Vec::new();
        let requiredby: Vec<String>;
        let optionalfor: Vec<String>;

        /* make aligned titles once only */
        // static int need_alignment = 1;
        // static mut need_alignment: bool = true;
        // if need_alignment {
        // 	need_alignment = false;
        // 	make_aligned_titles();
        // }

        from = self.get_origin();

        /* set variables here, do all output below */
        bdate = match self.get_builddate() {
            Err(e) => unimplemented!(),
            Ok(d) => d,
        };
        if bdate != 0 {
            // unimplemented!();
            // bdatestr = time::strftime("%c", localtime(&bdate));
        }
        idate = match self.get_installdate() {
            Err(e) => unimplemented!(),
            Ok(d) => d,
        };
        if idate != 0 {
            // unimplemented!();
            // strftime(idatestr, 50, "%c", localtime(&idate));
        }

        reason = match self.get_reason() {
            Ok(&PackageReason::Explicit) => "Explicitly installed".to_owned(),
            Ok(&PackageReason::Dependency) => {
                "Installed as a dependency for another package".to_owned()
            }
            _ => "Unknown".to_owned(),
        };
        let v = self.get_validation()?;
        if v != 0 {
            if v & PackageValidation::None as i32 != 0 {
                validation.push(String::from("None"));
            } else {
                if v & PackageValidation::MD5Sum as i32 != 0 {
                    validation.push(String::from("MD5 Sum"));
                }
                if v & PackageValidation::SHA256Sum as i32 != 0 {
                    validation.push(String::from("SHA-256 Sum"));
                }
                if v & PackageValidation::Signature as i32 != 0 {
                    validation.push(String::from("Signature"));
                }
            }
        } else {
            validation.push(String::from("Unknown"));
        }

        match (&from, extra) {
            (&PackageFrom::LocalDatabase, _) | (_, true) => {
                /* compute this here so we don't get a pause in the middle of output */
                requiredby = self.compute_requiredby(false, db_local, dbs_sync)?;
                optionalfor = self.compute_optionalfor(db_local, dbs_sync)?;
            }
            _ => {}
        }

        // let cols = getcols();
        /* actual output */
        match from {
            PackageFrom::SyncDatabase => {
                // string_display(T_REPOSITORY, pkg.alpm_db_get_name(get_db(pkg)), config)
            }
            _ => {}
        }
        string_display(T_NAME, self.get_name());
        string_display(T_VERSION, self.get_version());
        string_display(T_DESCRIPTION, self.get_desc()?);
        string_display(T_ARCHITECTURE, self.get_arch()?);
        string_display(T_URL, self.get_url()?);
        list_display(T_LICENSES, self.get_licenses()?);
        list_display(T_GROUPS, self.get_groups()?);
        deplist_display(T_PROVIDES, self.get_provides()?);
        deplist_display(T_DEPENDS_ON, self.get_depends()?);
        // optdeplist_display(pkg);

        match from {
            PackageFrom::LocalDatabase if extra => {
                // list_display(T_REQUIRED_BY, requiredby);
                // list_display(T_OPTIONAL_FOR, optionalfor);
            }
            _ => {}
        }
        deplist_display(T_CONFLICTS_WITH, self.get_conflicts()?);
        deplist_display(T_REPLACES, self.get_replaces()?);

        size = humanize_size(self.get_size(), '\0', 2, &mut label);
        match from {
            PackageFrom::SyncDatabase => {
                print!("{} {} {}\n", T_DOWNLOAD_SIZE, size, label);
            }
            PackageFrom::File => {
                print!("{} {} {}\n", T_COMPRESSED_SIZE, size, label);
            }
            _ => {}
        }
        size = humanize_size(
            self.get_isize()?,
            label.chars().collect::<Vec<char>>()[0],
            2,
            &mut label,
        );
        string_display(T_INSTALLED_SIZE, &format!("{} {}", size, label));

        string_display(T_PACKAGER, self.packager()?);
        // string_display(T_BUILD_DATE, bdatestr);
        match from {
            PackageFrom::LocalDatabase => {
                // string_display(T_INSTALL_DATE, idatestr);
                string_display(T_INSTALL_REASON, &reason);
            }
            _ => {}
        }
        let has_scriptlet = if self.has_scriptlet()? != 0 {
            String::from("Yes")
        } else {
            String::from("No")
        };
        match from {
            PackageFrom::File | PackageFrom::LocalDatabase => {
                string_display(T_INSTALL_SCRIPT, &has_scriptlet);
            }
            _ => {}
        }

        match from {
            PackageFrom::SyncDatabase if extra => {
                unimplemented!();
                let base64_sig = self.base64_sig();
                let mut keys = Vec::new();
                if !base64_sig.is_empty() {
                    unimplemented!();
                // unsigned char *decoded_sigdata = NULL;
                // size_t data_len;
                // alpm_decode_signature(base64_sig, &decoded_sigdata, &data_len);
                // alpm_extract_keyid(config.handle, get_name(pkg),
                // 		decoded_sigdata, data_len, &keys);
                } else {
                    keys.push(String::from("None"));
                }

                string_display(T_MD5_SUM, &self.md5sum());
                string_display(T_SHA_256_SUM, &self.sha256sum());
                list_display(T_SIGNATURES, &keys);
            }
            _ => {
                list_display(T_VALIDATED_BY, &validation);
            }
        }

        /* Print additional package info if info flag passed more than once */
        match from {
            PackageFrom::File => {
                unimplemented!();
                // 		alpm_siglist_t siglist;
                // 		int err = check_pgp_signature(pkg, &siglist);
                // 		if(err && alpm_errno(config->handle) == ALPM_ERR_SIG_MISSING) {
                // 			string_display(titles[T_SIGNATURES], _("None"));
                // 		} else if(err) {
                // 			string_display(titles[T_SIGNATURES],
                // 					alpm_strerror(alpm_errno(config->handle)));
                // 		} else {
                // 			signature_display(titles[T_SIGNATURES], &siglist);
                // 		}
                // 		alpm_siglist_cleanup(&siglist);
            }
            PackageFrom::LocalDatabase if extra => {
                unimplemented!();
                // pkg.dump_pkg_backups();
            }
            _ => {}
        }

        /* final newline to separate packages */
        print!("\n");
        Ok(())
    }

    /// Loop through the files of the package to check if they exist.
    pub fn check_fast(&self) -> i32 {
        unimplemented!();
        // 	const char *root, *pkgname;
        // 	size_t errors = 0;
        // 	size_t rootlen;
        // 	char filepath[PATH_MAX];
        // 	alpm_filelist_t *filelist;
        // 	size_t i;
        //
        // 	root = alpm_option_get_root(config->handle);
        // 	rootlen = strlen(root);
        // 	if(rootlen + 1 > PATH_MAX) {
        // 		/* we are in trouble here */
        // 		pm_printf(ALPM_LOG_ERROR, _("path too long: %s%s\n"), root, "");
        // 		return 1;
        // 	}
        // 	strcpy(filepath, root);
        //
        // 	pkgname = alpm_pkg_get_name(pkg);
        // 	filelist = alpm_pkg_get_files(pkg);
        // 	for(i = 0; i < filelist->count; i++) {
        // 		const alpm_file_t *file = filelist->files + i;
        // 		struct stat st;
        // 		int exists;
        // 		const char *path = file->name;
        // 		size_t plen = strlen(path);
        //
        // 		if(rootlen + 1 + plen > PATH_MAX) {
        // 			pm_printf(ALPM_LOG_WARNING, _("path too long: %s%s\n"), root, path);
        // 			continue;
        // 		}
        // 		strcpy(filepath + rootlen, path);
        //
        // 		exists = check_file_exists(pkgname, filepath, rootlen, &st);
        // 		if(exists == 0) {
        // 			int expect_dir = path[plen - 1] == '/' ? 1 : 0;
        // 			int is_dir = S_ISDIR(st.st_mode) ? 1 : 0;
        // 			if(expect_dir != is_dir) {
        // 				pm_printf(ALPM_LOG_WARNING, _("%s: %s (File type mismatch)\n"),
        // 						pkgname, filepath);
        // 				++errors;
        // 			}
        // 		} else if(exists == 1) {
        // 			++errors;
        // 		}
        // 	}
        //
        // 	if(!config->quiet) {
        // 		printf(_n("%s: %jd total file, ", "%s: %jd total files, ",
        // 					(unsigned long)filelist->count), pkgname, (intmax_t)filelist->count);
        // 		printf(_n("%jd missing file\n", "%jd missing files\n",
        // 					(unsigned long)errors), (intmax_t)errors);
        // 	}
        //
        // 	return (errors != 0 ? 1 : 0);
    }

    /// Loop though files in a package and perform full file property checking.
    pub fn check_full(&self) -> i32 {
        unimplemented!();
        // 	const char *root, *pkgname;
        // 	size_t errors = 0;
        // 	size_t rootlen;
        // 	struct archive *mtree;
        // 	struct archive_entry *entry = NULL;
        // 	size_t file_count = 0;
        // 	const alpm_list_t *lp;
        //
        // 	root = alpm_option_get_root(config->handle);
        // 	rootlen = strlen(root);
        // 	if(rootlen + 1 > PATH_MAX) {
        // 		/* we are in trouble here */
        // 		pm_printf(ALPM_LOG_ERROR, _("path too long: %s%s\n"), root, "");
        // 		return 1;
        // 	}
        //
        // 	pkgname = alpm_pkg_get_name(pkg);
        // 	mtree = alpm_pkg_mtree_open(pkg);
        // 	if(mtree == NULL) {
        // 		/* TODO: check error to confirm failure due to no mtree file */
        // 		if(!config->quiet) {
        // 			printf(_("%s: no mtree file\n"), pkgname);
        // 		}
        // 		return 0;
        // 	}
        //
        // 	while(alpm_pkg_mtree_next(pkg, mtree, &entry) == ARCHIVE_OK) {
        // 		struct stat st;
        // 		const char *path = archive_entry_pathname(entry);
        // 		char filepath[PATH_MAX];
        // 		int filepath_len;
        // 		mode_t type;
        // 		size_t file_errors = 0;
        // 		int backup = 0;
        // 		int exists;
        //
        // 		/* strip leading "./" from path entries */
        // 		if(path[0] == '.' && path[1] == '/') {
        // 			path += 2;
        // 		}
        //
        // 		if(*path == '.') {
        // 			const char *dbfile = NULL;
        //
        // 			if(strcmp(path, ".INSTALL") == 0) {
        // 				dbfile = "install";
        // 			} else if(strcmp(path, ".CHANGELOG") == 0) {
        // 				dbfile = "changelog";
        // 			} else {
        // 				continue;
        // 			}
        //
        // 			/* Do not append root directory as alpm_option_get_dbpath is already
        // 			 * an absoute path */
        // 			filepath_len = snprintf(filepath, PATH_MAX, "%slocal/%s-%s/%s",
        // 					alpm_option_get_dbpath(config->handle),
        // 					pkgname, alpm_pkg_get_version(pkg), dbfile);
        // 			if(filepath_len >= PATH_MAX) {
        // 				pm_printf(ALPM_LOG_WARNING, _("path too long: %slocal/%s-%s/%s\n"),
        // 						alpm_option_get_dbpath(config->handle),
        // 						pkgname, alpm_pkg_get_version(pkg), dbfile);
        // 				continue;
        // 			}
        // 		} else {
        // 			filepath_len = snprintf(filepath, PATH_MAX, "%s%s", root, path);
        // 			if(filepath_len >= PATH_MAX) {
        // 				pm_printf(ALPM_LOG_WARNING, _("path too long: %s%s\n"), root, path);
        // 				continue;
        // 			}
        // 		}
        //
        // 		file_count++;
        //
        // 		exists = check_file_exists(pkgname, filepath, rootlen, &st);
        // 		if(exists == 1) {
        // 			errors++;
        // 			continue;
        // 		} else if(exists == -1) {
        // 			/* NoExtract */
        // 			continue;
        // 		}
        //
        // 		type = archive_entry_filetype(entry);
        //
        // 		if(type != AE_IFDIR && type != AE_IFREG && type != AE_IFLNK) {
        // 			pm_printf(ALPM_LOG_WARNING, _("file type not recognized: %s%s\n"), root, path);
        // 			continue;
        // 		}
        //
        // 		if(check_file_type(pkgname, filepath, &st, entry) == 1) {
        // 			errors++;
        // 			continue;
        // 		}
        //
        // 		file_errors += check_file_permissions(pkgname, filepath, &st, entry);
        //
        // 		if(type == AE_IFLNK) {
        // 			file_errors += check_file_link(pkgname, filepath, &st, entry);
        // 		}
        //
        // 		/* the following checks are expected to fail if a backup file has been
        // 		   modified */
        // 		for(lp = alpm_pkg_get_backup(pkg); lp; lp = lp->next) {
        // 			alpm_backup_t *bl = lp->data;
        //
        // 			if(strcmp(path, bl->name) == 0) {
        // 				backup = 1;
        // 				break;
        // 			}
        // 		}
        //
        // 		if(type != AE_IFDIR) {
        // 			/* file or symbolic link */
        // 			file_errors += check_file_time(pkgname, filepath, &st, entry, backup);
        // 		}
        //
        // 		if(type == AE_IFREG) {
        // 			file_errors += check_file_size(pkgname, filepath, &st, entry, backup);
        // 			/* file_errors += check_file_md5sum(pkgname, filepath, &st, entry, backup); */
        // 		}
        //
        // 		if(config->quiet && file_errors) {
        // 			printf("%s %s\n", pkgname, filepath);
        // 		}
        //
        // 		errors += (file_errors != 0 ? 1 : 0);
        // 	}
        //
        // 	alpm_pkg_mtree_close(pkg, mtree);
        //
        // 	if(!config->quiet) {
        // 		printf(_n("%s: %jd total file, ", "%s: %jd total files, ",
        // 					(unsigned long)file_count), pkgname, (intmax_t)file_count);
        // 		printf(_n("%jd altered file\n", "%jd altered files\n",
        // 					(unsigned long)errors), (intmax_t)errors);
        // 	}
        //
        // 	return (errors != 0 ? 1 : 0);
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
}

impl std::cmp::Ord for Package {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl PartialOrd for Package {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Package {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Package {}
