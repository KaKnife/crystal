// local
use alpm::pkg_vercmp;
use alpm::Time;
use dep_vercmp;
use PackageReason;
use Dependency;
use Database;
use dep_from_string;
use util::{deplist_display, humanize_size, list_display, parsedate, string_display, strtoofft};
use consts::INFRQ_DESC;
use consts::INFRQ_SCRIPTLET;
use consts::INFRQ_FILES;
use consts::INFRQ_ERROR;
use consts::INFRQ_ALL;
use Handle;
use Result;
use Error;
// std
use std::cmp::Ordering;
use std::cmp::Ord;
use std::fs::File;
use std::time::Duration;
use std::time::UNIX_EPOCH;
// crates
use humantime::format_rfc3339;

/// Location a package object was loaded from.
#[derive(Debug, Clone, Copy)]
pub enum PackageFrom {
    File = 1,
    LocalDatabase,
    SyncDatabase,
}
impl Default for PackageFrom {
    fn default() -> Self {
        PackageFrom::File
    }
}

/// Method used to validate a package.
pub enum PackageValidation {
    Unkown = 0,
    None = (1 << 0),
    MD5Sum = (1 << 1),
    SHA256Sum = (1 << 2),
    Signature = (1 << 3),
}

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

#[derive(Default, Debug, Clone)]
pub struct Package {
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

    // pub handle: handle_t,
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
    pub removes: Vec<Package>,
    /* in transaction targets only */
    // pub oldpkg: Option<Package>, /* in transaction targets only */

    // filelist_t files;

    /* origin == PKG_FROM_FILE, use pkg->origin_data.file
    * origin == PKG_FROM_*DB, use pkg->origin_data.db */
    // pub db: Database,
    file: String,
    origin: PackageFrom,
    reason: PackageReason,
    scriptlet: i32,

    /* Bitfield from dbinfrq_t */
    pub infolevel: i32,
    /* Bitfield from pkgvalidation_t */
    validation: i32,
}

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
//     get_builddate: fn(&Package) -> time_t,
//     get_installdate: fn(&Package) -> time_t,
//     // const char *(*get_packager) (Package *);
//     // const char *(*get_arch) (Package *);
//     // off_t (*get_isize) (Package *);
//     // PackageReason (*get_reason) (Package *);
//     // int (*get_validation) (Package *);
//     // int (*has_scriptlet) (Package *);
//
//     // list_t *(*get_licenses) (Package *);
//     // list_t *(*get_groups) (Package *);
//     // list_t *(*get_depends) (Package *);
//     // list_t *(*get_optdepends) (Package *);
//     // list_t *(*get_checkdepends) (Package *);
//     // list_t *(*get_makedepends) (Package *);
//     // list_t *(*get_conflicts) (Package *);
//     // list_t *(*get_provides) (Package *);
//     // list_t *(*get_replaces) (Package *);
//     // filelist_t *(*get_files) (Package *);
//     // list_t *(*get_backup) (Package *);
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
const T_OPTIONAL_DEPS: &str = "Optional Deps";
const T_OPTIONAL_FOR: &str = "Optional For";
const T_PACKAGER: &str = "Packager";
const T_PROVIDES: &str = "Provides";
const T_REPLACES: &str = "Replaces";
const T_REPOSITORY: &str = "Repository";
const T_SIGNATURES: &str = "Signatures";
const T_URL: &str = "URL";
const T_VALIDATED_BY: &str = "Validated By";
const T_VERSION: &str = "Version";

// impl<'a> Clone for Package<'a> {
//     fn clone(&self) -> Self {
//         Package {
//             filename: self.filename.clone(),
//             base: self.base.clone(),
//             name: self.name.clone(),
//             version: self.version.clone(),
//             desc: self.desc.clone(),
//             url: self.url.clone(),
//             packager: self.packager.clone(),
//             md5sum: self.md5sum.clone(),
//             sha256sum: self.sha256sum.clone(),
//             base64_sig: self.base64_sig.clone(),
//             arch: self.arch.clone(),
//
//             builddate: self.Time,
//             installdate: self.Time,
//
//             size: self.i64,
//             isize: self.i64,
//             download_size: self.i64,
//
//             // pub handle: handle_t,
//             licenses: self.Vec<String>,
//             replaces: self.Vec<Dependency>,
//             groups: self.Vec<String>,
//             backup: self.Vec<String>,
//             depends: self.Vec<Dependency>,
//             optdepends: self.Vec<Dependency>,
//             checkdepends: self.Vec<Dependency>,
//             makedepends: self.Vec<Dependency>,
//             conflicts: self.Vec<Dependency>,
//             provides: self.Vec<Dependency>,
//             deltas: self.Vec<Dependency>,
//             delta_path: self.Vec<Dependency>,
//             pub removes: self.Vec<&'a Package<'a>>,
//             /* in transaction targets only */
//             // pub oldpkg: Option<Package>, /* in transaction targets only */
//
//             // filelist_t files;
//
//             /* origin == PKG_FROM_FILE, use pkg->origin_data.file
//              * origin == PKG_FROM_*DB, use pkg->origin_data.db */
//             // pub db: Database,
//             file: String,
//             origin: PackageFrom,
//             reason: PackageReason,
//             scriptlet: i32,
//
//             /* Bitfield from dbinfrq_t */
//             pub infolevel: i32,
//             /* Bitfield from pkgvalidation_t */
//             validation: i32,
//         }
//     }
// }

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
        // fpath = _filecache_find(pkg.handle, pkg.filename);
        //
        // retval = _test_checksum(fpath, pkg.md5sum, ALPM_PKG_VALIDATION_MD5SUM);
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
        // 	list_t *i;
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
        // 		spkg = _db_get_pkgfromcache(db, pkg->name);
        // 	}
        //
        // 	if(spkg == NULL) {
        // 		_log(pkg->handle, ALPM_LOG_DEBUG, "'{}' not found in sync db => no upgrade\n",
        // 				pkg->name);
        // 		return NULL;
        // 	}
        //
        // 	/* compare versions and see if spkg is an upgrade */
        // 	if(_pkg_compare_versions(spkg, pkg) > 0) {
        // 		_log(pkg->handle, ALPM_LOG_DEBUG, "new version of '{}' found ({} => {})\n",
        // 					pkg->name, pkg->version, spkg->version);
        // 		return spkg;
        // 	}
        // 	/* spkg is not an upgrade */
        // 	return NULL;
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

    /// Returns the package name.
    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn set_name(&mut self, name: &String) {
        self.name = name.clone();
    }

    /// Returns the package version as a string.
    /// This includes all available epoch, version, and pkgrel components. Use
    /// pkg_vercmp() to compare version strings if necessary.
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

    /// Returns the build timestamp of the package.
    pub fn get_builddate(&self) -> Result<Time> {
        if self.infolevel & INFRQ_DESC == 0 {
            Err(Error::PkgNotLoaded)
        } else {
            Ok(self.builddate)
        }
    }

    /// Returns the install timestamp of the package.
    pub fn get_installdate(&self) -> Result<Time> {
        if self.infolevel & INFRQ_DESC == 0 {
            Err(Error::PkgNotLoaded)
        } else {
            Ok(self.installdate)
        }
    }

    /// Returns the packager's name.
    pub fn packager(&self) -> Result<&String> {
        if self.infolevel & INFRQ_DESC == 0 {
            Err(Error::PkgNotLoaded)
        } else {
            Ok(&self.packager)
        }
        // 	return pkg->ops->get_packager(pkg);
    }

    /// Returns the package's MD5 checksum as a string.
    /// The returned string is a sequence of 32 lowercase hexadecimal digits.
    pub fn md5sum(&self) -> &String {
        return &self.md5sum;
    }

    /// Returns the package's SHA256 checksum as a string.
    /// The returned string is a sequence of 64 lowercase hexadecimal digits.
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
        if self.infolevel & INFRQ_DESC == 0 {
            Err(Error::PkgNotLoaded)
        } else {
            Ok(&self.groups)
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
        if self.infolevel & INFRQ_DESC == 0 {
            return Err(Error::PkgNotLoaded);
        }
        Ok(&self.replaces)
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

    // pub fn pkg_get_db(&self) -> &Database {
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

    // file_t *_file_copy(file_t *dest,
    // 		const file_t *src)
    // {
    // 	STRDUP(dest->name, src->name, return NULL);
    // 	dest->size = src->size;
    // 	dest->mode = src->mode;
    //
    // 	return dest;
    // }

    // static list_t *list_depdup(list_t *old)
    // {
    // 	list_t *i, *new = NULL;
    // 	for(i = old; i; i = i->next) {
    // 		new = list_add(new, _dep_dup(i->data));
    // 	}
    // 	return new;
    // }
    //

    /// Duplicate a package data struct.
    pub fn dup(&self) -> Result<Package> {
        unimplemented!();
        // 	Package *newpkg;
        // 	list_t *i;
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
        // 		_log(pkg->handle, ALPM_LOG_WARNING,
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
        // 	newpkg->licenses   = list_strdup(pkg->licenses);
        // 	newpkg->replaces   = list_depdup(pkg->replaces);
        // 	newpkg->groups     = list_strdup(pkg->groups);
        // 	for(i = pkg->backup; i; i = i->next) {
        // 		newpkg->backup = list_add(newpkg->backup, _backup_dup(i->data));
        // 	}
        // 	newpkg->depends    = list_depdup(pkg->depends);
        // 	newpkg->optdepends = list_depdup(pkg->optdepends);
        // 	newpkg->conflicts  = list_depdup(pkg->conflicts);
        // 	newpkg->provides   = list_depdup(pkg->provides);
        // 	for(i = pkg->deltas; i; i = i->next) {
        // 		newpkg->deltas = list_add(newpkg->deltas, _delta_dup(i->data));
        // 	}
        //
        // 	if(pkg->files.count) {
        // 		size_t filenum;
        // 		size_t len = sizeof(file_t) * pkg->files.count;
        // 		MALLOC(newpkg->files.files, len, goto cleanup);
        // 		for(filenum = 0; filenum < pkg->files.count; filenum++) {
        // 			if(!_file_copy(newpkg->files.files + filenum,
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
        pkg_vercmp(&self.version, &localpkg.version)
    }

    // fn lazy_load(&mut self, info: i32, db: &mut Database) {
    //     if self.infolevel & info == 0 {
    //         self.local_db_read(db, info);
    //     }
    // }

    /// Open a package changelog for reading. Similar to fopen in functionality,
    /// except that the returned 'file stream' is from the database.
    /// * `pkg` the package (from db) to read the changelog
    fn _cache_changelog_open(&self) -> File {
        unimplemented!();
        //     let db = self.pkg_get_db();
        //     let clfile = db._local_db_pkgpath(self, "changelog");
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
    // 	Database *db = pkg_get_db(pkg);
    // 	char *mtfile = _local_db_pkgpath(db, pkg, "mtree");
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
    // 	_archive_read_support_filter_all(mtree);
    // 	archive_read_support_format_mtree(mtree);
    //
    // 	if((r = _archive_read_open_file(mtree, mtfile, ALPM_BUFFER_SIZE))) {
    // 		_log(pkg.handle, ALPM_LOG_ERROR, _("error while reading file {}: {}"),
    // 					mtfile, archive_error_string(mtree));
    // 		pkg.handle.pm_errno = ALPM_ERR_LIBARCHIVE;
    // 		_archive_read_free(mtree);
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
    // 	return _archive_read_free(mtree);
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
        // 	list_t *lp;
        // 	if(!deplist) {
        // 		return;
        // 	}
        // 	fputs(header, fp);
        // 	fputc('', fp);
        // 	for(lp = deplist; lp; lp = lp.next) {
        // 		char *depstring = dep_compute_string(lp.data);
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
        // 	if(_local_db_write(pkg->handle->db_local, pkg, INFRQ_DESC)) {
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
        // 	handle_t *handle = newpkg.handle;
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
        // 	fpath = _filecache_find(handle, fname);
        //
        // 	/* downloaded file exists, so there's nothing to grab */
        // 	if(fpath) {
        // 		size = 0;
        // 		goto finish;
        // 	}
        //
        // 	CALLOC(fnamepart, strlen(fname) + 6, sizeof(char), return -1);
        // 	sprintf(fnamepart, "{}.part", fname);
        // 	fpath = _filecache_find(handle, fnamepart);
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
        // 		dltsize = _shortest_delta_path(handle, newpkg.deltas,
        // 				newpkg.filename, &newpkg.delta_path);
        //
        // 		if(newpkg.delta_path && (dltsize < newpkg.size * handle.deltaratio)) {
        // 			debug!("using delta size\n");
        // 			size = dltsize;
        // 		} else {
        // 			debug!("using package size\n");
        // 			size = newpkg.size;
        // 			list_free(newpkg.delta_path);
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

    pub fn parse_lines(&mut self, lines: Vec<&str>, dbname: &str) {
        let mut next_line_type = NextLineType::None;
        let mut files_count = 0;
        let mut files_size = 0;
        let mut len = 0;
        let mut files = Vec::new();

        for mut line in lines {
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
                    } else if line == "%FILES%" {
                        next_line_type = NextLineType::Files;
                    } else if line == "%BACKUP%" {
                        next_line_type = NextLineType::Backup;
                    }
                    continue;
                }
                NextLineType::Name => {
                    if line != self.get_name() {
                        error!(
                            "{} database is inconsistent: name mismatch on package {}",
                            dbname,
                            self.get_name()
                        );
                    }
                }
                NextLineType::Version => {
                    if line != self.get_version() {
                        error!(
                            "{} database is inconsistent: version mismatch on package {}",
                            dbname,
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
                    self.builddate = parsedate(line);
                }
                NextLineType::InstallDate => {
                    self.installdate = parsedate(line);
                }
                NextLineType::Packager => {
                    self.packager = String::from(line);
                }
                NextLineType::Reason => {
                    self.reason = PackageReason::from(u8::from_str_radix(line, 10).unwrap());
                }
                NextLineType::Validation => {
                    // unimplemented!();
                    // // list_t *i, *v = NULL;
                    // READ_AND_STORE_ALL(v);
                    // // for(i = v; i; i = list_next(i))
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
                    self.isize = strtoofft(&String::from(line));
                }
                NextLineType::Replaces => {
                    if line != "" {
                        self.replaces.push(dep_from_string(&String::from(line)));
                        continue;
                    };
                }
                NextLineType::Depends => {
                    if line != "" {
                        self.depends.push(dep_from_string(&String::from(line)));
                        continue;
                    };
                }
                NextLineType::OptDepends => {
                    if line != "" {
                        self.optdepends.push(dep_from_string(&String::from(line)));
                        continue;
                    };
                }
                NextLineType::Confilcts => {
                    if line != "" {
                        self.conflicts.push(dep_from_string(&String::from(line)));
                        continue;
                    };
                }
                NextLineType::Provides => {
                    if line != "" {
                        self.provides.push(dep_from_string(&String::from(line)));
                        continue;
                    };
                }
                NextLineType::Files => {
                    if line == "" {
                        next_line_type = NextLineType::None;
                        unimplemented!();
                        // info.files.count = files_count;
                        // info.files.files = files;
                        // _filelist_sort(&info.files);
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
                    // let backup: backup_t;
                    // if (_split_backup(line, &backup)) {
                    //     info.infolevel |= INFRQ_ERROR;
                    //     return -1;
                    // }
                    // info.backup.push(backup);
                } // _ => {}
            }

            next_line_type = NextLineType::None;
        }
    }

    pub fn local_db_read(&mut self, db: &Database, inforeq: i32) -> Result<()> {
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

        debug!(
            "loading package data for {} : level=0x{:x}",
            self.get_name(),
            inforeq
        );

        /* DESC */
        if inforeq & INFRQ_DESC != 0 && (self.infolevel & INFRQ_DESC) == 0 {
            use std::io::prelude::*;
            let path;
            let mut fp;
            let mut lines: String = String::new();
            let lines_iter;

            path = db.local_db_pkgpath(self, &String::from("desc"))?;
            fp = match File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    error!("could not open file {}: {}", path, e);
                    self.infolevel |= INFRQ_ERROR;
                    return Err(Error::from(e));
                }
            };

            fp.read_to_string(&mut lines)?;
            lines_iter = lines.lines().collect();
            self.parse_lines(lines_iter, db.get_name());
            self.infolevel |= INFRQ_DESC;
        }

        /* FILES */
        if inforeq & INFRQ_FILES != 0 && (self.infolevel & INFRQ_FILES) == 0 {
            let path = db.local_db_pkgpath(self, &String::from("desc"))?;
            let mut fp = match File::open(&path) {
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

            let lines_iter = lines.lines().collect();
            self.parse_lines(lines_iter, db.get_name());
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
        let bdate;
        let idate;
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
        bdate = UNIX_EPOCH + Duration::from_secs(self.get_builddate()? as u64);
        let bdatestr = format!("{}", format_rfc3339(bdate));
        idate = UNIX_EPOCH + Duration::from_secs(self.get_installdate()? as u64);
        let idatestr = format!("{}", format_rfc3339(idate));

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

        /* actual output */
        // match from {
        //     PackageFrom::SyncDatabase => {
        //         string_display(T_REPOSITORY, pkg.db_get_name(get_db(pkg)), config)
        //     }
        //     _ => {}
        // }
        string_display("Name", self.get_name());
        string_display("Version", self.get_version());
        string_display("Description", self.get_desc()?);
        string_display("Architecture", self.get_arch()?);
        string_display("URL", self.get_url()?);
        list_display("Licenses", self.get_licenses()?);
        list_display(T_GROUPS, self.get_groups()?);
        deplist_display(T_PROVIDES, self.get_provides()?);
        deplist_display(T_DEPENDS_ON, self.get_depends()?);
        // optdeplist_display(pkg);

        match from {
            PackageFrom::LocalDatabase if extra => {
                // list_display("Required By", requiredby);
                // list_display("Optional For", optionalfor);
            }
            _ => {}
        }
        deplist_display(T_CONFLICTS_WITH, self.get_conflicts()?);
        deplist_display(T_REPLACES, self.get_replaces()?);

        size = humanize_size(self.get_size(), &mut label);
        match from {
            PackageFrom::SyncDatabase => {
                info!("{:15}: {:2} {}", "Download Size", size, label);
            }
            PackageFrom::File => {
                info!("{:15}: {:2} {}", T_COMPRESSED_SIZE, size, label);
            }
            _ => {}
        }
        size = humanize_size(self.get_isize()?, &mut label);
        string_display(T_INSTALLED_SIZE, &format!("{:.2} {}", size, label));

        string_display(T_PACKAGER, self.packager()?);
        string_display("Build Date", &bdatestr);
        match from {
            PackageFrom::LocalDatabase => {
                string_display(T_INSTALL_DATE, &idatestr);
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
                // decode_signature(base64_sig, &decoded_sigdata, &data_len);
                // extract_keyid(config.handle, get_name(pkg),
                // 		decoded_sigdata, data_len, &keys);
                } else {
                    keys.push(String::from("None"));
                }

                string_display("MD5 Sum", &self.md5sum());
                string_display("SHA-256 Sum", &self.sha256sum());
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
                // 		siglist_t siglist;
                // 		int err = check_pgp_signature(pkg, &siglist);
                // 		if(err && errno(config->handle) == ALPM_ERR_SIG_MISSING) {
                // 			string_display(titles[T_SIGNATURES], _("None"));
                // 		} else if(err) {
                // 			string_display(titles[T_SIGNATURES],
                // 					strerror(errno(config->handle)));
                // 		} else {
                // 			signature_display(titles[T_SIGNATURES], &siglist);
                // 		}
                // 		siglist_cleanup(&siglist);
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
        // 	filelist_t *filelist;
        // 	size_t i;
        //
        // 	root = option_get_root(config->handle);
        // 	rootlen = strlen(root);
        // 	if(rootlen + 1 > PATH_MAX) {
        // 		/* we are in trouble here */
        // 		pm_printf(ALPM_LOG_ERROR, _("path too long: %s%s\n"), root, "");
        // 		return 1;
        // 	}
        // 	strcpy(filepath, root);
        //
        // 	pkgname = pkg_get_name(pkg);
        // 	filelist = pkg_get_files(pkg);
        // 	for(i = 0; i < filelist->count; i++) {
        // 		const file_t *file = filelist->files + i;
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
        // 	const list_t *lp;
        //
        // 	root = option_get_root(config->handle);
        // 	rootlen = strlen(root);
        // 	if(rootlen + 1 > PATH_MAX) {
        // 		/* we are in trouble here */
        // 		pm_printf(ALPM_LOG_ERROR, _("path too long: %s%s\n"), root, "");
        // 		return 1;
        // 	}
        //
        // 	pkgname = pkg_get_name(pkg);
        // 	mtree = pkg_mtree_open(pkg);
        // 	if(mtree == NULL) {
        // 		/* TODO: check error to confirm failure due to no mtree file */
        // 		if(!config->quiet) {
        // 			printf(_("%s: no mtree file\n"), pkgname);
        // 		}
        // 		return 0;
        // 	}
        //
        // 	while(pkg_mtree_next(pkg, mtree, &entry) == ARCHIVE_OK) {
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
        // 			/* Do not append root directory as option_get_dbpath is already
        // 			 * an absoute path */
        // 			filepath_len = snprintf(filepath, PATH_MAX, "%slocal/%s-%s/%s",
        // 					option_get_dbpath(config->handle),
        // 					pkgname, pkg_get_version(pkg), dbfile);
        // 			if(filepath_len >= PATH_MAX) {
        // 				pm_printf(ALPM_LOG_WARNING, _("path too long: %slocal/%s-%s/%s\n"),
        // 						option_get_dbpath(config->handle),
        // 						pkgname, pkg_get_version(pkg), dbfile);
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
        // 		for(lp = pkg_get_backup(pkg); lp; lp = lp->next) {
        // 			backup_t *bl = lp->data;
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
        // 	pkg_mtree_close(pkg, mtree);
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
    // static time_t _pkg_get_builddate(Package *pkg)   { return pkg->builddate; }
    // static time_t _pkg_get_installdate(Package *pkg) { return pkg->installdate; }
    // static const char *_pkg_get_packager(Package *pkg)    { return pkg->packager; }
    // static const char *_pkg_get_arch(Package *pkg)        { return pkg->arch; }
    // static off_t _pkg_get_isize(Package *pkg)             { return pkg->isize; }
    // static PackageReason _pkg_get_reason(Package *pkg) { return pkg->reason; }
    // static int _pkg_get_validation(Package *pkg) { return pkg->validation; }
    // static int _pkg_has_scriptlet(Package *pkg)           { return pkg->scriptlet; }
    //
    // static list_t *_pkg_get_licenses(Package *pkg)   { return pkg->licenses; }
    // static list_t *_pkg_get_groups(Package *pkg)     { return pkg->groups; }
    // static list_t *_pkg_get_depends(Package *pkg)    { return pkg->depends; }
    // static list_t *_pkg_get_optdepends(Package *pkg) { return pkg->optdepends; }
    // static list_t *_pkg_get_checkdepends(Package *pkg) { return pkg->checkdepends; }
    // static list_t *_pkg_get_makedepends(Package *pkg) { return pkg->makedepends; }
    // static list_t *_pkg_get_conflicts(Package *pkg)  { return pkg->conflicts; }
    // static list_t *_pkg_get_provides(Package *pkg)   { return pkg->provides; }
    // static list_t *_pkg_get_replaces(Package *pkg)   { return pkg->replaces; }
    // static filelist_t *_pkg_get_files(Package *pkg)  { return &(pkg->files); }
    // static list_t *_pkg_get_backup(Package *pkg)     { return pkg->backup; }
}

impl<'a> Ord for Package {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

impl<'a> PartialOrd for Package {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> PartialEq for Package {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl<'a> Eq for Package {}

/*
 *  package.c
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

// #define CLBUF_SIZE 4096

// /* The term "title" refers to the first field of each line in the package
//  * information displayed by pacman. Titles are stored in the `titles` array and
//  * referenced by the following indices.
//  */
// enum title_enum {
// 	T_ARCHITECTURE = 0,
// 	T_BACKUP_FILES,
// 	T_BUILD_DATE,
// 	T_COMPRESSED_SIZE,
// 	T_CONFLICTS_WITH,
// 	T_DEPENDS_ON,
// 	T_DESCRIPTION,
// 	T_DOWNLOAD_SIZE,
// 	T_GROUPS,
// 	T_INSTALL_DATE,
// 	T_INSTALL_REASON,
// 	T_INSTALL_SCRIPT,
// 	T_INSTALLED_SIZE,
// 	T_LICENSES,
// 	T_MD5_SUM,
// 	T_NAME,
// 	T_OPTIONAL_DEPS,
// 	T_OPTIONAL_FOR,
// 	T_PACKAGER,
// 	T_PROVIDES,
// 	T_REPLACES,
// 	T_REPOSITORY,
// 	T_REQUIRED_BY,
// 	T_SHA_256_SUM,
// 	T_SIGNATURES,
// 	T_URL,
// 	T_VALIDATED_BY,
// 	T_VERSION,
// 	/* the following is a sentinel and should remain in last position */
// 	_T_MAX,
// }
//
// /* As of 2015/10/20, the longest title (all locales considered) was less than 30
//  * characters long. We set the title maximum length to 50 to allow for some
//  * potential growth.
//  */
// #define TITLE_MAXLEN 50
//
// static char titles[_T_MAX][TITLE_MAXLEN * sizeof(wchar_t)];
//
// /** Build the `titles` array of localized titles and pad them with spaces so
//  * that they align with the longest title. Storage for strings is stack
//  * allocated and naively truncated to TITLE_MAXLEN characters.
//  */

pub fn make_aligned_titles() {
    unimplemented!();
    // 	unsigned int i;
    // 	size_t maxlen = 0;
    // 	int maxcol = 0;
    // 	static const wchar_t title_suffix[] = L" :";
    // 	wchar_t wbuf[ARRAYSIZE(titles)][TITLE_MAXLEN + ARRAYSIZE(title_suffix)];
    // 	size_t wlen[ARRAYSIZE(wbuf)];
    // 	int wcol[ARRAYSIZE(wbuf)];
    // 	char *buf[ARRAYSIZE(wbuf)];
    // let buf: [&str; _T_MAX as i32]
    // 	buf[T_ARCHITECTURE] = _("Architecture");
    // 	buf[T_BACKUP_FILES] = _("Backup Files");
    // 	buf[T_BUILD_DATE] = _("Build Date");
    // 	buf[T_COMPRESSED_SIZE] = _("Compressed Size");
    // 	buf[T_CONFLICTS_WITH] = _("Conflicts With");
    // 	buf[T_DEPENDS_ON] = _("Depends On");
    // 	buf[T_DESCRIPTION] = _("Description");
    // 	buf[T_DOWNLOAD_SIZE] = _("Download Size");
    // 	buf[T_GROUPS] = _("Groups");
    // 	buf[T_INSTALL_DATE] = _("Install Date");
    // 	buf[T_INSTALL_REASON] = _("Install Reason");
    // 	buf[T_INSTALL_SCRIPT] = _("Install Script");
    // 	buf[T_INSTALLED_SIZE] = _("Installed Size");
    // 	buf[T_LICENSES] = _("Licenses");
    // 	buf[T_MD5_SUM] = _("MD5 Sum");
    // 	buf[T_NAME] = _("Name");
    // 	buf[T_OPTIONAL_DEPS] = _("Optional Deps");
    // 	buf[T_OPTIONAL_FOR] = _("Optional For");
    // 	buf[T_PACKAGER] = _("Packager");
    // 	buf[T_PROVIDES] = _("Provides");
    // 	buf[T_REPLACES] = _("Replaces");
    // 	buf[T_REPOSITORY] = _("Repository");
    // 	buf[T_REQUIRED_BY] = _("Required By");
    // 	buf[T_SHA_256_SUM] = _("SHA-256 Sum");
    // 	buf[T_SIGNATURES] = _("Signatures");
    // 	buf[T_URL] = _("URL");
    // 	buf[T_VALIDATED_BY] = _("Validated By");
    // 	buf[T_VERSION] = _("Version");
    //
    // 	for(i = 0; i < ARRAYSIZE(wbuf); i++) {
    // 		wlen[i] = mbstowcs(wbuf[i], buf[i], strlen(buf[i]) + 1);
    // 		wcol[i] = wcswidth(wbuf[i], wlen[i]);
    // 		if(wcol[i] > maxcol) {
    // 			maxcol = wcol[i];
    // 		}
    // 		if(wlen[i] > maxlen) {
    // 			maxlen = wlen[i];
    // 		}
    // 	}
    //
    // 	for(i = 0; i < ARRAYSIZE(wbuf); i++) {
    // 		size_t padlen = maxcol - wcol[i];
    // 		wmemset(wbuf[i] + wlen[i], L' ', padlen);
    // 		wmemcpy(wbuf[i] + wlen[i] + padlen, title_suffix, ARRAYSIZE(title_suffix));
    // 		wcstombs(titles[i], wbuf[i], sizeof(wbuf[i]));
    // 	}
}

// /** Turn a optdepends list into a text list.
//  * @param optdeps a list with items of type depend_t
//  */
// static void optdeplist_display(Package *pkg, unsigned short cols)
// {
// 	alpm_list_t *i, *text = NULL;
// 	Database *localdb = alpm_get_localdb(config->handle);
// 	for(i = get_optdepends(pkg); i; i = alpm_list_next(i)) {
// 		depend_t *optdep = i->data;
// 		char *depstring = alpm_dep_compute_string(optdep);
// 		if(get_origin(pkg) == LocalDatabase) {
// 			if(alpm_find_satisfier(get_pkgcache(localdb), optdep->name)) {
// 				const char *installed = _(" [installed]");
// 				depstring = realloc(depstring, strlen(depstring) + strlen(installed) + 1);
// 				strcpy(depstring + strlen(depstring), installed);
// 			}
// 		}
// 		text = alpm_list_add(text, depstring);
// 	}
// 	list_display_linebreak(titles[T_OPTIONAL_DEPS], text, cols);
// 	FREELIST(text);
// }

// static const char *get_backup_file_status(const char *root,
// 		const alpm_backup_t *backup)
// {
// 	char path[PATH_MAX];
// 	const char *ret;
//
// 	snprintf(path, PATH_MAX, "{}{}", root, backup->name);
//
// 	/* if we find the file, calculate checksums, otherwise it is missing */
// 	if(access(path, R_OK) == 0) {
// 		char *md5sum = alpm_compute_md5sum(path);
//
// 		if(md5sum == NULL) {
// 			pm_printf(ALPM_LOG_ERROR,
// 					_("could not calculate checksums for {}\n"), path);
// 			return NULL;
// 		}
//
// 		/* if checksums don't match, file has been modified */
// 		if(strcmp(md5sum, backup->hash) != 0) {
// 			ret = "MODIFIED";
// 		} else {
// 			ret = "UNMODIFIED";
// 		}
// 		free(md5sum);
// 	} else {
// 		switch(errno) {
// 			case EACCES:
// 				ret = "UNREADABLE";
// 				break;
// 			case ENOENT:
// 				ret = "MISSING";
// 				break;
// 			default:
// 				ret = "UNKNOWN";
// 		}
// 	}
// 	return ret;
// }
//
// /* Display list of backup files and their modification states
//  */
// void dump_pkg_backups(Package *pkg)
// {
// 	alpm_list_t *i;
// 	const char *root = alpm_option_get_root(config->handle);
// 	printf("{}{}\n{}", config->colstr.title, titles[T_BACKUP_FILES],
// 				 config->colstr.nocolor);
// 	if(get_backup(pkg)) {
// 		/* package has backup files, so print them */
// 		for(i = get_backup(pkg); i; i = alpm_list_next(i)) {
// 			const alpm_backup_t *backup = i->data;
// 			const char *value;
// 			if(!backup->hash) {
// 				continue;
// 			}
// 			value = get_backup_file_status(root, backup);
// 			printf("{}\t{}{}\n", value, root, backup->name);
// 		}
// 	} else {
// 		/* package had no backup files */
// 		printf(_("(none)\n"));
// 	}
// }

/// List all files contained in a package
pub fn dump_pkg_files(pkg: &Package, quiet: bool) {
    unimplemented!();
    // 	const char *pkgname, *root;
    // 	alpm_filelist_t *pkgfiles;
    // 	size_t i;
    //
    // 	pkgname = get_name(pkg);
    // 	pkgfiles = get_files(pkg);
    // 	root = alpm_option_get_root(config->handle);
    //
    // 	for(i = 0; i < pkgfiles->count; i++) {
    // 		const alpm_file_t *file = pkgfiles->files + i;
    // 		/* Regular: '<pkgname> <root><filepath>\n'
    // 		 * Quiet  : '<root><filepath>\n'
    // 		 */
    // 		if(!quiet) {
    // 			printf("{}{}{} ", config->colstr.title, pkgname, config->colstr.nocolor);
    // 		}
    // 		printf("{}{}\n", root, file->name);
    // 	}
    //
    // 	fflush(stdout);
}

/// Display the changelog of a package
pub fn dump_pkg_changelog(pkg: &Package) {
    unimplemented!();
    // 	void *fp = NULL;
    //
    // 	if((fp = changelog_open(pkg)) == NULL) {
    // 		pm_printf(ALPM_LOG_ERROR, _("no changelog available for '{}'.\n"),
    // 				get_name(pkg));
    // 		return;
    // 	} else {
    // 		fprintf(stdout, _("Changelog for {}:\n"), get_name(pkg));
    // 		/* allocate a buffer to get the changelog back in chunks */
    // 		char buf[CLBUF_SIZE];
    // 		size_t ret = 0;
    // 		while((ret = changelog_read(buf, CLBUF_SIZE, pkg, fp))) {
    // 			if(ret < CLBUF_SIZE) {
    // 				/* if we hit the end of the file, we need to add a null terminator */
    // 				*(buf + ret) = '\0';
    // 			}
    // 			fputs(buf, stdout);
    // 		}
    // 		changelog_close(pkg, fp);
    // 		putchar('\n');
    // 	}
}

// void print_installed(Database *db_local, Package *pkg)
// {
// 	const char *pkgname = get_name(pkg);
// 	const char *pkgver = get_version(pkg);
// 	Package *lpkg = get_pkg(db_local, pkgname);
// 	if(lpkg) {
// 		const char *lpkgver = get_version(lpkg);
// 		const colstr_t *colstr = &config->colstr;
// 		if(strcmp(lpkgver, pkgver) == 0) {
// 			printf(" {}[{}]{}", colstr->meta, _("installed"), colstr->nocolor);
// 		} else {
// 			printf(" {}[{}: {}]{}", colstr->meta, _("installed"),
// 					lpkgver, colstr->nocolor);
// 		}
// 	}
// }

/// Display the details of a search.
pub fn dump_pkg_search(
    db: &mut Database,
    targets: &Vec<String>,
    show_status: i32,
    handle: &Handle,
    quiet: bool,
) -> Result<()> {
    unimplemented!();
    // 	int freelist = 0;
    // 	Database *db_local;
    let db_local;
    // 	alpm_list_t *i, *searchlist;
    let searchlist;
    let mut freelist = 0;
    // 	unsigned short cols;
    // 	const colstr_t *colstr = &config->colstr;
    // let colstr = &config.colstr;
    //
    if show_status != 0 {
        db_local = handle.get_localdb();
    }

    /* if we have a targets list, search for packages matching it */
    if !targets.is_empty() {
        searchlist = db.search(targets).clone();
        freelist = 1;
    } else {
        searchlist = db.get_pkgcache()?;
        freelist = 0;
    }
    if searchlist.is_empty() {
        return Err(Error::Other);
    }

    for pkg in searchlist {
        // let grp;
        // 		alpm_list_t *grp;
        // 		Package *pkg = i->data;
        //
        if quiet {
            print!("{}", pkg.get_name())
        // 			fputs(get_name(pkg), stdout);
        } else {
            print!("{}/{} {}", db.get_name(), pkg.get_name(), pkg.get_version(),);
            // grp = pkg.get_groups();
            // if grp.is_some() {
            // 	// 				alpm_list_t *k;
            // 	// 				printf(" {}(", colstr->groups);
            // 	for group in grp {
            // 		// 					const char *group = k->data;
            // 		// 					fputs(group, stdout);
            // 		// 					if(alpm_list_next(k)) {
            // 		// 						/* only print a spacer if there are more groups */
            // 		// 						putchar(' ');
            // 		// 					}
            // 	}
            // 	// print!("){}", colstr->nocolor);
            // }
            //
            // 			if(show_status) {
            // 				print_installed(db_local, pkg);
            // 			}
            //
            // 			/* we need a newline and initial indent first */
            // 			fputs("\n    ", stdout);
            // 			indentprint(get_desc(pkg), 4, cols);
        }
        // print!("\n");
    }

    // /* we only want to free if the list was a search list */
    // if (freelist != 0) {
    // 	alpm_list_free(searchlist);
    // }

    return Ok(());
}
