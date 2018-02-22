#[macro_use]
pub mod util;
pub mod handle;
pub mod deps;
pub mod db;
pub mod package;
pub mod trans;
pub mod version;
pub mod be_local;
pub mod conflict;
pub mod error;
pub mod remove;
pub mod be_package;
pub mod dload;
pub mod sync;
pub mod pkghash;
pub mod be_sync;
pub mod signing;
pub mod alpm_list;
use self::alpm_list::*;
use self::signing::*;
// use self::be_sync::*;
use self::pkghash::*;
// use self::sync::*;
use self::util::*;
use self::dload::*;
// use self::add::*;
// use self::be_package::*;
// use self::remove::*;
// use self::error::*;
// use self::conflict::*;
// use self::be_local::*;
use self::version::*;
use self::trans::*;
use self::package::*;
use self::handle::*;
use self::db::*;
// use self::deps::*;

pub use self::sync::alpm_sync_sysupgrade;
pub use self::remove::alpm_remove_pkg;
pub use self::package::pkg_t;
pub use self::handle::alpm_list_t;
pub use self::handle::alpm_handle_t;
pub use self::db::alpm_db_t;
pub use self::deps::alpm_dep_from_string;
pub use self::be_sync::alpm_db_update;
pub use self::deps::alpm_find_satisfier;
pub use self::error::errno_t;

const SYSHOOKDIR: &str = "/usr/local/share/libalpm/hooks/";

pub type Result<T> = std::result::Result<T, errno_t>;

// /*
//  * alpm.h
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
// #ifndef ALPM_H
// #define ALPM_H
//
// #ifdef __cplusplus
// extern "C" {
// #endif

// libarchive
// #include <archive.h>
// #include <archive_entry.h>

/* Arch Linux Package Management library */

/* Opaque Structures */

type __alpm_handle_t = alpm_handle_t;
type __alpm_db_t = alpm_db_t;
type __pkg_t = pkg_t;
type __alpm_trans_t = alpm_trans_t;
type alpm_time_t = i64;

/// Package install reasons.
#[derive(Debug, Clone)]
pub enum pkgreason_t {
    /// Explicitly requested by the user.
    ALPM_PKG_REASON_EXPLICIT = 0,
    /// Installed as a dependency for another package.
    ALPM_PKG_REASON_DEPEND = 1,
}
impl Default for pkgreason_t {
    fn default() -> Self {
        pkgreason_t::ALPM_PKG_REASON_EXPLICIT
    }
}
impl From<u8> for pkgreason_t {
    fn from(n: u8) -> pkgreason_t {
        match n {
            0 => pkgreason_t::ALPM_PKG_REASON_EXPLICIT,
            1 => pkgreason_t::ALPM_PKG_REASON_DEPEND,
            _ => unimplemented!(),
        }
    }
}

impl Default for pkgfrom_t {
    fn default() -> Self {
        pkgfrom_t::ALPM_PKG_FROM_FILE
    }
}

/// Location a package object was loaded from.
#[derive(Debug, Clone)]
pub enum pkgfrom_t {
    ALPM_PKG_FROM_FILE = 1,
    ALPM_PKG_FROM_LOCALDB,
    ALPM_PKG_FROM_SYNCDB,
}

/// Method used to validate a package.
pub enum pkgvalidation_t {
    ALPM_PKG_VALIDATION_UNKNOWN = 0,
    ALPM_PKG_VALIDATION_NONE = (1 << 0),
    ALPM_PKG_VALIDATION_MD5SUM = (1 << 1),
    ALPM_PKG_VALIDATION_SHA256SUM = (1 << 2),
    ALPM_PKG_VALIDATION_SIGNATURE = (1 << 3),
}

/// Types of version constraints in dependency specs.
#[derive(Debug, Clone)]
pub enum depmod_t {
    /// No version constraint
    ALPM_DEP_MOD_ANY = 1,
    /// Test version equality (package=x.y.z)
    ALPM_DEP_MOD_EQ,
    /// Test for at least a version (package>=x.y.z)
    ALPM_DEP_MOD_GE,
    /// Test for at most a version (package<=x.y.z)
    ALPM_DEP_MOD_LE,
    /// Test for greater than some version (package>x.y.z)
    ALPM_DEP_MOD_GT,
    /// Test for less than some version (package<x.y.z)
    ALPM_DEP_MOD_LT,
}

impl Default for depmod_t {
    fn default() -> Self {
        depmod_t::ALPM_DEP_MOD_ANY
    }
}

/// File conflict type.
/// Whether the conflict results from a file existing on the filesystem, or with
/// another target in the transaction.
#[derive(Debug)]
enum fileconflicttype_t {
    ALPM_FILECONFLICT_TARGET = 1,
    ALPM_FILECONFLICT_FILESYSTEM,
}

/// PGP signature verification options
#[derive(Default, Clone, Debug, Copy)]
pub struct siglevel {
    pub ALPM_SIG_PACKAGE: bool,
    pub ALPM_SIG_PACKAGE_OPTIONAL: bool,
    pub ALPM_SIG_PACKAGE_MARGINAL_OK: bool,
    pub ALPM_SIG_PACKAGE_UNKNOWN_OK: bool,

    pub ALPM_SIG_DATABASE: bool,
    pub ALPM_SIG_DATABASE_OPTIONAL: bool,
    pub ALPM_SIG_DATABASE_MARGINAL_OK: bool,
    pub ALPM_SIG_DATABASE_UNKNOWN_OK: bool,

    pub ALPM_SIG_USE_DEFAULT: bool,
}
use std;
impl std::ops::BitOr for siglevel {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        let mut new = siglevel::default();
        new.ALPM_SIG_PACKAGE = self.ALPM_SIG_PACKAGE | rhs.ALPM_SIG_PACKAGE;
        new.ALPM_SIG_PACKAGE_OPTIONAL =
            self.ALPM_SIG_PACKAGE_OPTIONAL | rhs.ALPM_SIG_PACKAGE_OPTIONAL;
        new.ALPM_SIG_PACKAGE_MARGINAL_OK =
            self.ALPM_SIG_PACKAGE_MARGINAL_OK | rhs.ALPM_SIG_PACKAGE_MARGINAL_OK;
        new.ALPM_SIG_PACKAGE_UNKNOWN_OK =
            self.ALPM_SIG_PACKAGE_UNKNOWN_OK | rhs.ALPM_SIG_PACKAGE_UNKNOWN_OK;

        new.ALPM_SIG_DATABASE = self.ALPM_SIG_DATABASE | rhs.ALPM_SIG_DATABASE;
        new.ALPM_SIG_DATABASE_OPTIONAL =
            self.ALPM_SIG_DATABASE_OPTIONAL | rhs.ALPM_SIG_DATABASE_OPTIONAL;
        new.ALPM_SIG_DATABASE_MARGINAL_OK =
            self.ALPM_SIG_DATABASE_MARGINAL_OK | rhs.ALPM_SIG_DATABASE_MARGINAL_OK;
        new.ALPM_SIG_DATABASE_UNKNOWN_OK =
            self.ALPM_SIG_DATABASE_UNKNOWN_OK | rhs.ALPM_SIG_DATABASE_UNKNOWN_OK;

        new.ALPM_SIG_USE_DEFAULT = self.ALPM_SIG_USE_DEFAULT | rhs.ALPM_SIG_USE_DEFAULT;
        new
    }
}
impl std::ops::BitAnd for siglevel {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        let mut new = siglevel::default();
        new.ALPM_SIG_PACKAGE = self.ALPM_SIG_PACKAGE & rhs.ALPM_SIG_PACKAGE;
        new.ALPM_SIG_PACKAGE_OPTIONAL =
            self.ALPM_SIG_PACKAGE_OPTIONAL & rhs.ALPM_SIG_PACKAGE_OPTIONAL;
        new.ALPM_SIG_PACKAGE_MARGINAL_OK =
            self.ALPM_SIG_PACKAGE_MARGINAL_OK & rhs.ALPM_SIG_PACKAGE_MARGINAL_OK;
        new.ALPM_SIG_PACKAGE_UNKNOWN_OK =
            self.ALPM_SIG_PACKAGE_UNKNOWN_OK & rhs.ALPM_SIG_PACKAGE_UNKNOWN_OK;

        new.ALPM_SIG_DATABASE = self.ALPM_SIG_DATABASE & rhs.ALPM_SIG_DATABASE;
        new.ALPM_SIG_DATABASE_OPTIONAL =
            self.ALPM_SIG_DATABASE_OPTIONAL & rhs.ALPM_SIG_DATABASE_OPTIONAL;
        new.ALPM_SIG_DATABASE_MARGINAL_OK =
            self.ALPM_SIG_DATABASE_MARGINAL_OK & rhs.ALPM_SIG_DATABASE_MARGINAL_OK;
        new.ALPM_SIG_DATABASE_UNKNOWN_OK =
            self.ALPM_SIG_DATABASE_UNKNOWN_OK & rhs.ALPM_SIG_DATABASE_UNKNOWN_OK;

        new.ALPM_SIG_USE_DEFAULT = self.ALPM_SIG_USE_DEFAULT & rhs.ALPM_SIG_USE_DEFAULT;
        new
    }
}
impl std::ops::Not for siglevel {
    type Output = Self;
    fn not(self) -> Self {
        let mut new = siglevel::default();
        new.ALPM_SIG_PACKAGE = self.ALPM_SIG_PACKAGE;
        new.ALPM_SIG_PACKAGE_OPTIONAL = self.ALPM_SIG_PACKAGE_OPTIONAL;
        new.ALPM_SIG_PACKAGE_MARGINAL_OK = self.ALPM_SIG_PACKAGE_MARGINAL_OK;
        new.ALPM_SIG_PACKAGE_UNKNOWN_OK = self.ALPM_SIG_PACKAGE_UNKNOWN_OK;

        new.ALPM_SIG_DATABASE = self.ALPM_SIG_DATABASE;
        new.ALPM_SIG_DATABASE_OPTIONAL = self.ALPM_SIG_DATABASE_OPTIONAL;
        new.ALPM_SIG_DATABASE_MARGINAL_OK = self.ALPM_SIG_DATABASE_MARGINAL_OK;
        new.ALPM_SIG_DATABASE_UNKNOWN_OK = self.ALPM_SIG_DATABASE_UNKNOWN_OK;

        new.ALPM_SIG_USE_DEFAULT = self.ALPM_SIG_USE_DEFAULT;
        new
    }
}
impl siglevel {
    pub fn not_zero(&self) -> bool {
        !(self.ALPM_SIG_PACKAGE || self.ALPM_SIG_PACKAGE_OPTIONAL
            || self.ALPM_SIG_PACKAGE_MARGINAL_OK || self.ALPM_SIG_PACKAGE_UNKNOWN_OK
            || self.ALPM_SIG_DATABASE || self.ALPM_SIG_DATABASE_OPTIONAL
            || self.ALPM_SIG_DATABASE_MARGINAL_OK || self.ALPM_SIG_DATABASE_UNKNOWN_OK
            || self.ALPM_SIG_USE_DEFAULT)
    }
}

/// PGP signature verification status return codes
#[derive(Debug, Clone)]
enum sigstatus_t {
    ALPM_SIGSTATUS_VALID,
    ALPM_SIGSTATUS_KEY_EXPIRED,
    ALPM_SIGSTATUS_SIG_EXPIRED,
    ALPM_SIGSTATUS_KEY_UNKNOWN,
    ALPM_SIGSTATUS_KEY_DISABLED,
    ALPM_SIGSTATUS_INVALID,
}
impl Default for sigstatus_t {
    fn default() -> Self {
        sigstatus_t::ALPM_SIGSTATUS_VALID
    }
}

/// PGP signature verification status return codes
#[derive(Debug, Clone)]
enum sigvalidity_t {
    ALPM_SIGVALIDITY_FULL,
    ALPM_SIGVALIDITY_MARGINAL,
    ALPM_SIGVALIDITY_NEVER,
    ALPM_SIGVALIDITY_UNKNOWN,
}
impl Default for sigvalidity_t {
    fn default() -> Self {
        sigvalidity_t::ALPM_SIGVALIDITY_UNKNOWN
    }
}

//Structures

/// Dependency
#[derive(Debug, Clone, Default)]
pub struct depend_t {
    pub name: String,
    pub version: String,
    desc: String,
    name_hash: u64,
    depmod: depmod_t,
}

/// Missing dependency
pub struct depmissing_t {
    pub target: String,
    pub depend: depend_t,
    /// this is used only in the case of a remove dependency error
    pub causingpkg: String,
}

/// Conflict
pub struct conflict_t {
    // unsigned long package1_hash;
    // unsigned long package2_hash;
    pub package1: String,
    pub package2: String,
    // depend_t *reason;
}

/// File conflict
struct fileconflict_t {
    target: String,
    ttype: fileconflicttype_t, //used to be type
    file: String,
    ctarget: String,
}

/// Package group
#[derive(Debug, Clone)]
pub struct group_t {
    /// group name
    pub name: String,
    /// list of packages
    pub packages: Vec<pkg_t>,
}

/// Package upgrade delta
struct _alpm_delta_t {
    // /// filename of the delta patch
    // delta: String,
    // /// md5sum of the delta file
    // 	char *delta_md5;
    // /// filename of the 'before' file
    // 	char *from;
    // /// filename of the 'after' file
    // 	char *to;
    // /// filesize of the delta file
    // 	off_t delta_size;
    // /// download filesize of the delta file
    // download_size: off_t,
}

/// File in a package
pub struct alpm_file_t {
	// char *name;
	// off_t size;
	// mode_t mode;
}

/// Package filelist container
struct alpm_filelist_t {
	// size_t count;
	// alpm_file_t *files;
}

// /// Local package or package file backup entry
// typedef struct _alpm_backup_t {
// 	char *name;
// 	char *hash;
// } alpm_backup_t;

#[derive(Debug, Clone, Default)]
struct alpm_pgpkey_t {
    // void *data;
    fingerprint: String,
    uid: String,
    name: String,
    email: String,
    created: alpm_time_t,
    expires: alpm_time_t,
    length: u32,
    revoked: u32,
    pubkey_algo: char,
}

/// Signature result. Contains the key, status, and validity of a given
/// signature.
#[derive(Debug, Clone, Default)]
struct alpm_sigresult_t {
    key: alpm_pgpkey_t,
    status: sigstatus_t,
    validity: sigvalidity_t,
}

/// Signature list. Contains the number of signatures found and a pointer to an
/// array of results. The array is of size count.
#[derive(Debug, Clone, Default)]
pub struct alpm_siglist_t {
    count: usize,
    results: alpm_sigresult_t,
}

//Hooks

// typedef enum _alpm_hook_when_t {
// 	ALPM_HOOK_PRE_TRANSACTION = 1,
// 	ALPM_HOOK_POST_TRANSACTION
// } alpm_hook_when_t;

// Logging facilities

/// Logging Levels
#[derive(Debug, Default)]
pub struct loglevel {
    pub ALPM_LOG_ERROR: bool,    //    = 1,
    pub ALPM_LOG_WARNING: bool,  //  = (1 << 1),
    pub ALPM_LOG_DEBUG: bool,    //    = (1 << 2),
    pub ALPM_LOG_FUNCTION: bool, // = (1 << 3)
}

// type alpm_cb_log = (alpm_loglevel_t, String, va_list);

/// Type of events.
enum alpm_event_type_t {
    /// Dependencies will be computed for a package.
    ALPM_EVENT_CHECKDEPS_START = 1,
    /// Dependencies were computed for a package.
    ALPM_EVENT_CHECKDEPS_DONE,
    /// File conflicts will be computed for a package.
    ALPM_EVENT_FILECONFLICTS_START,
    /// File conflicts were computed for a package.
    ALPM_EVENT_FILECONFLICTS_DONE,
    /// Dependencies will be resolved for target package.
    ALPM_EVENT_RESOLVEDEPS_START,
    /// Dependencies were resolved for target package.
    ALPM_EVENT_RESOLVEDEPS_DONE,
    /// Inter-conflicts will be checked for target package.
    ALPM_EVENT_INTERCONFLICTS_START,
    /// Inter-conflicts were checked for target package.
    ALPM_EVENT_INTERCONFLICTS_DONE,
    /// Processing the package transaction is starting.
    ALPM_EVENT_TRANSACTION_START,
    /// Processing the package transaction is finished.
    ALPM_EVENT_TRANSACTION_DONE,
    /// Package will be installed/upgraded/downgraded/re-installed/removed; See
    /// alpm_event_package_operation_t for arguments.
    ALPM_EVENT_PACKAGE_OPERATION_START,
    /// Package was installed/upgraded/downgraded/re-installed/removed; See
    /// alpm_event_package_operation_t for arguments.
    ALPM_EVENT_PACKAGE_OPERATION_DONE,
    /// Target package's integrity will be checked.
    ALPM_EVENT_INTEGRITY_START,
    /// Target package's integrity was checked.
    ALPM_EVENT_INTEGRITY_DONE,
    /// Target package will be loaded.
    ALPM_EVENT_LOAD_START,
    /// Target package is finished loading.
    ALPM_EVENT_LOAD_DONE,
    /// Target delta's integrity will be checked.
    ALPM_EVENT_DELTA_INTEGRITY_START,
    /// Target delta's integrity was checked.
    ALPM_EVENT_DELTA_INTEGRITY_DONE,
    /// Deltas will be applied to packages.
    ALPM_EVENT_DELTA_PATCHES_START,
    /// Deltas were applied to packages.
    ALPM_EVENT_DELTA_PATCHES_DONE,
    /// Delta patch will be applied to target package; See
    /// alpm_event_delta_patch_t for arguments..
    ALPM_EVENT_DELTA_PATCH_START,
    /// Delta patch was applied to target package.
    ALPM_EVENT_DELTA_PATCH_DONE,
    /// Delta patch failed to apply to target package.
    ALPM_EVENT_DELTA_PATCH_FAILED,
    /// Scriptlet has printed information; See alpm_event_scriptlet_info_t for
    /// arguments.
    ALPM_EVENT_SCRIPTLET_INFO,
    /// Files will be downloaded from a repository.
    ALPM_EVENT_RETRIEVE_START,
    /// Files were downloaded from a repository.
    ALPM_EVENT_RETRIEVE_DONE,
    /// Not all files were successfully downloaded from a repository.
    ALPM_EVENT_RETRIEVE_FAILED,
    /// A file will be downloaded from a repository; See alpm_event_pkgdownload_t
    /// for arguments
    ALPM_EVENT_PKGDOWNLOAD_START,
    /// A file was downloaded from a repository; See alpm_event_pkgdownload_t
    /// for arguments
    ALPM_EVENT_PKGDOWNLOAD_DONE,
    /// A file failed to be downloaded from a repository; See
    /// alpm_event_pkgdownload_t for arguments
    ALPM_EVENT_PKGDOWNLOAD_FAILED,
    /// Disk space usage will be computed for a package.
    ALPM_EVENT_DISKSPACE_START,
    /// Disk space usage was computed for a package.
    ALPM_EVENT_DISKSPACE_DONE,
    /// An optdepend for another package is being removed; See
    /// alpm_event_optdep_removal_t for arguments.
    ALPM_EVENT_OPTDEP_REMOVAL,
    /// A configured repository database is missing; See
    /// alpm_event_database_missing_t for arguments.
    ALPM_EVENT_DATABASE_MISSING,
    /// Checking keys used to create signatures are in keyring.
    ALPM_EVENT_KEYRING_START,
    /// Keyring checking is finished.
    ALPM_EVENT_KEYRING_DONE,
    /// Downloading missing keys into keyring.
    ALPM_EVENT_KEY_DOWNLOAD_START,
    /// Key downloading is finished.
    ALPM_EVENT_KEY_DOWNLOAD_DONE,
    /// A .pacnew file was created; See alpm_event_pacnew_created_t for arguments.
    ALPM_EVENT_PACNEW_CREATED,
    /// A .pacsave file was created; See alpm_event_pacsave_created_t for
    /// arguments
    ALPM_EVENT_PACSAVE_CREATED,
    /// Processing hooks will be started.
    ALPM_EVENT_HOOK_START,
    /// Processing hooks is finished.
    ALPM_EVENT_HOOK_DONE,
    /// A hook is starting
    ALPM_EVENT_HOOK_RUN_START,
    /// A hook has finished running
    ALPM_EVENT_HOOK_RUN_DONE,
}

// typedef struct _alpm_event_any_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// } alpm_event_any_t;

// typedef enum _alpm_package_operation_t {
// 	/// Package (to be) installed. (No oldpkg)
// 	ALPM_PACKAGE_INSTALL = 1,
// 	/// Package (to be) upgraded
// 	ALPM_PACKAGE_UPGRADE,
// 	/// Package (to be) re-installed.
// 	ALPM_PACKAGE_REINSTALL,
// 	/// Package (to be) downgraded.
// 	ALPM_PACKAGE_DOWNGRADE,
// 	/// Package (to be) removed. (No newpkg)
// 	ALPM_PACKAGE_REMOVE
// } alpm_package_operation_t;

// typedef struct _alpm_event_package_operation_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Type of operation.
// 	alpm_package_operation_t operation;
// 	/// Old package.
// 	pkg_t *oldpkg;
// 	/// New package.
// 	pkg_t *newpkg;
// } alpm_event_package_operation_t;

// typedef struct _alpm_event_optdep_removal_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Package with the optdep.
// 	pkg_t *pkg;
// 	/// Optdep being removed.
// 	depend_t *optdep;
// } alpm_event_optdep_removal_t;

// typedef struct _alpm_event_delta_patch_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Delta info
// 	alpm_delta_t *delta;
// } alpm_event_delta_patch_t;

// typedef struct _alpm_event_scriptlet_info_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Line of scriptlet output.
// 	const char *line;
// } alpm_event_scriptlet_info_t;

// typedef struct _alpm_event_database_missing_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Name of the database.
// 	const char *dbname;
// } alpm_event_database_missing_t;

// typedef struct _alpm_event_pkgdownload_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Name of the file
// 	const char *file;
// } alpm_event_pkgdownload_t;

// typedef struct _alpm_event_pacnew_created_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Whether the creation was result of a NoUpgrade or not
// 	int from_noupgrade;
// 	/// Old package.
// 	pkg_t *oldpkg;
// 	/// New Package.
// 	pkg_t *newpkg;
// 	/// Filename of the file without the .pacnew suffix
// 	const char *file;
// } alpm_event_pacnew_created_t;

// typedef struct _alpm_event_pacsave_created_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Old package.
// 	pkg_t *oldpkg;
// 	/// Filename of the file without the .pacsave suffix.
// 	const char *file;
// } alpm_event_pacsave_created_t;

// typedef struct _alpm_event_hook_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Type of hooks.
// 	alpm_hook_when_t when;
// } alpm_event_hook_t;

// typedef struct _alpm_event_hook_run_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Name of hook
// 	const char *name;
// 	/// Description of hook to be outputted
// 	const char *desc;
// 	/// position of hook being run
// 	size_t position;
// 	/// total hooks being run
// 	size_t total;
// } alpm_event_hook_run_t;

// /// Events.
//  * This is an union passed to the callback, that allows the frontend to know
//  * which type of event was triggered (via type). It is then possible to
//  * typecast the pointer to the right structure, or use the union field, in order
//  * to access event-specific data.
// typedef union _alpm_event_t {
// 	alpm_event_type_t type;
// 	alpm_event_any_t any;
// 	alpm_event_package_operation_t package_operation;
// 	alpm_event_optdep_removal_t optdep_removal;
// 	alpm_event_delta_patch_t delta_patch;
// 	alpm_event_scriptlet_info_t scriptlet_info;
// 	alpm_event_database_missing_t database_missing;
// 	alpm_event_pkgdownload_t pkgdownload;
// 	alpm_event_pacnew_created_t pacnew_created;
// 	alpm_event_pacsave_created_t pacsave_created;
// 	alpm_event_hook_t hook;
// 	alpm_event_hook_run_t hook_run;
// } alpm_event_t;

// /// Event callback.
// typedef void (*alpm_cb_event)(alpm_event_t *);

// ///
//  * Type of questions.
//  * Unlike the events or progress enumerations, this enum has bitmask values
//  * so a frontend can use a bitmask map to supply preselected answers to the
//  * different types of questions.
//
// typedef enum _alpm_question_type_t {
// 	ALPM_QUESTION_INSTALL_IGNOREPKG = (1 << 0),
// 	ALPM_QUESTION_REPLACE_PKG = (1 << 1),
// 	ALPM_QUESTION_CONFLICT_PKG = (1 << 2),
// 	ALPM_QUESTION_CORRUPTED_PKG = (1 << 3),
// 	ALPM_QUESTION_REMOVE_PKGS = (1 << 4),
// 	ALPM_QUESTION_SELECT_PROVIDER = (1 << 5),
// 	ALPM_QUESTION_IMPORT_KEY = (1 << 6)
// } alpm_question_type_t;

// typedef struct _alpm_question_any_t {
// 	/// Type of question.
// 	alpm_question_type_t type;
// 	/// Answer.
// 	int answer;
// } alpm_question_any_t;

// typedef struct _alpm_question_install_ignorepkg_t {
// 	/// Type of question.
// 	alpm_question_type_t type;
// 	/// Answer: whether or not to install pkg anyway.
// 	int install;
// 	/// Package in IgnorePkg/IgnoreGroup. */
// 	pkg_t *pkg;
// } alpm_question_install_ignorepkg_t;

// typedef struct _alpm_question_replace_t {
// 	/// Type of question.
// 	alpm_question_type_t type;
// 	/// Answer: whether or not to replace oldpkg with newpkg.
// 	int replace;
// 	/* Package to be replaced. */
// 	pkg_t *oldpkg;
// 	/* Package to replace with. */
// 	pkg_t *newpkg;
// 	/* DB of newpkg
// 	alpm_db_t *newdb;
// } alpm_question_replace_t;

// typedef struct _alpm_question_conflict_t {
// 	/// Type of question.
// 	alpm_question_type_t type;
// 	/// Answer: whether or not to remove conflict->package2.
// 	int remove;
// 	/// Conflict info.
// 	alpm_conflict_t *conflict;
// } alpm_question_conflict_t;

// typedef struct _alpm_question_corrupted_t {
// 	/// Type of question.
// 	alpm_question_type_t type;
// 	/// Answer: whether or not to remove filepath.
// 	int remove;
// 	/// Filename to remove
// 	const char *filepath;
// 	/// Error code indicating the reason for package invalidity
// 	errno_t reason;
// } alpm_question_corrupted_t;

// typedef struct _alpm_question_remove_pkgs_t {
// 	/// Type of question.
// 	alpm_question_type_t type;
// 	/// Answer: whether or not to skip packages.
// 	int skip;
// 	/// List of pkg_t* with unresolved dependencies.
// 	alpm_list_t *packages;
// } alpm_question_remove_pkgs_t;

// typedef struct _alpm_question_select_provider_t {
// 	/// Type of question.
// 	alpm_question_type_t type;
// 	/// Answer: which provider to use (index from providers).
// 	int use_index;
// 	/// List of pkg_t* as possible providers.
// 	alpm_list_t *providers;
// 	/// What providers provide for.
// 	depend_t *depend;
// } alpm_question_select_provider_t;

// typedef struct _alpm_question_import_key_t {
// 	/// Type of question.
// 	alpm_question_type_t type;
// 	/// Answer: whether or not to import key.
// 	int import;
// 	/// The key to import.
// 	alpm_pgpkey_t *key;
// } alpm_question_import_key_t;

// ///
//  * Questions.
//  * This is an union passed to the callback, that allows the frontend to know
//  * which type of question was triggered (via type). It is then possible to
//  * typecast the pointer to the right structure, or use the union field, in order
//  * to access question-specific data.
// typedef union _alpm_question_t {
// 	alpm_question_type_t type;
// 	alpm_question_any_t any;
// 	alpm_question_install_ignorepkg_t install_ignorepkg;
// 	alpm_question_replace_t replace;
// 	alpm_question_conflict_t conflict;
// 	alpm_question_corrupted_t corrupted;
// 	alpm_question_remove_pkgs_t remove_pkgs;
// 	alpm_question_select_provider_t select_provider;
// 	alpm_question_import_key_t import_key;
// } alpm_question_t;

// /// Question callback
// typedef void (*alpm_cb_question)(alpm_question_t *);

// /// Progress
// typedef enum _alpm_progress_t {
// 	ALPM_PROGRESS_ADD_START,
// 	ALPM_PROGRESS_UPGRADE_START,
// 	ALPM_PROGRESS_DOWNGRADE_START,
// 	ALPM_PROGRESS_REINSTALL_START,
// 	ALPM_PROGRESS_REMOVE_START,
// 	ALPM_PROGRESS_CONFLICTS_START,
// 	ALPM_PROGRESS_DISKSPACE_START,
// 	ALPM_PROGRESS_INTEGRITY_START,
// 	ALPM_PROGRESS_LOAD_START,
// 	ALPM_PROGRESS_KEYRING_START
// } alpm_progress_t;

// /// Progress callback
// typedef void (*alpm_cb_progress)(alpm_progress_t, const char *, int, size_t, size_t);

//Downloading

// /// Type of download progress callbacks.
//  * @param filename the name of the file being downloaded
//  * @param xfered the number of transferred bytes
//  * @param total the total number of bytes to transfer
//
// typedef void (*alpm_cb_download)(const char *filename,
// 		off_t xfered, off_t total);

// typedef void (*alpm_cb_totaldl)(off_t total);

/// A callback for downloading files
///
/// * url - the URL of the file to be downloaded
/// * localpath - the directory to which the file should be downloaded
/// * force - whether to force an update, even if the file is the same
/// * return - 0 on success, 1 if the file exists and is identical, -1 on error.
type alpm_cb_fetch = fn(&String, &String, i32) -> i32;

// /// Fetch a remote pkg.
//  * @param handle the context handle
//  * @param url URL of the package to download
//  * @return the downloaded filepath on success, NULL on error
//
// char *alpm_fetch_pkgurl(alpm_handle_t *handle, const char *url);

// /// @addtogroup alpm_api_options Options
//  * Libalpm option getters and setters
//  * @{
//
//
// /// Returns the callback used for logging.
// alpm_cb_log alpm_option_get_logcb(alpm_handle_t *handle);
// /// Sets the callback used for logging.
// int alpm_option_set_logcb(alpm_handle_t *handle, alpm_cb_log cb);
//
// /// Returns the callback used to report download progress.
// alpm_cb_download alpm_option_get_dlcb(alpm_handle_t *handle);
// /// Sets the callback used to report download progress.
// int alpm_option_set_dlcb(alpm_handle_t *handle, alpm_cb_download cb);
//
// /// Returns the downloading callback.
// alpm_cb_fetch alpm_option_get_fetchcb(alpm_handle_t *handle);
// /// Sets the downloading callback.
// int alpm_option_set_fetchcb(alpm_handle_t *handle, alpm_cb_fetch cb);
//
// /// Returns the callback used to report total download size.
// alpm_cb_totaldl alpm_option_get_totaldlcb(alpm_handle_t *handle);
// /// Sets the callback used to report total download size.
// int alpm_option_set_totaldlcb(alpm_handle_t *handle, alpm_cb_totaldl cb);
//
// /// Returns the callback used for events.
// alpm_cb_event alpm_option_get_eventcb(alpm_handle_t *handle);
// /// Sets the callback used for events.
// int alpm_option_set_eventcb(alpm_handle_t *handle, alpm_cb_event cb);
//
// /// Returns the callback used for questions.
// alpm_cb_question alpm_option_get_questioncb(alpm_handle_t *handle);
// /// Sets the callback used for questions.
// int alpm_option_set_questioncb(alpm_handle_t *handle, alpm_cb_question cb);
//
// /// Returns the callback used for operation progress.
// alpm_cb_progress alpm_option_get_progresscb(alpm_handle_t *handle);
// /// Sets the callback used for operation progress.
// int alpm_option_set_progresscb(alpm_handle_t *handle, alpm_cb_progress cb);
//
// /// Returns the root of the destination filesystem. Read-only.
// const char *alpm_option_get_root(alpm_handle_t *handle);
//
// /// Returns the path to the database directory. Read-only.
// const char *alpm_option_get_dbpath(alpm_handle_t *handle);
//
// /// Get the name of the database lock file. Read-only.
// const char *alpm_option_get_lockfile(alpm_handle_t *handle);
//
// /// @name Accessors to the list of package cache directories.
//  * @{
//
// alpm_list_t *alpm_option_get_cachedirs(alpm_handle_t *handle);
// int alpm_option_set_cachedirs(alpm_handle_t *handle, alpm_list_t *cachedirs);
// int alpm_option_add_cachedir(alpm_handle_t *handle, const char *cachedir);
// int alpm_option_remove_cachedir(alpm_handle_t *handle, const char *cachedir);
// /// @}
//
// /// @name Accessors to the list of package hook directories.
//  * @{
//
// alpm_list_t *alpm_option_get_hookdirs(alpm_handle_t *handle);
// int alpm_option_set_hookdirs(alpm_handle_t *handle, alpm_list_t *hookdirs);
// int alpm_option_add_hookdir(alpm_handle_t *handle, const char *hookdir);
// int alpm_option_remove_hookdir(alpm_handle_t *handle, const char *hookdir);
// /// @}
//
// alpm_list_t *alpm_option_get_overwrite_files(alpm_handle_t *handle);
// int alpm_option_set_overwrite_files(alpm_handle_t *handle, alpm_list_t *globs);
// int alpm_option_add_overwrite_file(alpm_handle_t *handle, const char *glob);
// int alpm_option_remove_overwrite_file(alpm_handle_t *handle, const char *glob);
//
// /// Returns the logfile name.
// const char *alpm_option_get_logfile(alpm_handle_t *handle);
// /// Sets the logfile name.
// int alpm_option_set_logfile(alpm_handle_t *handle, const char *logfile);
//
// /// Returns the path to libalpm's GnuPG home directory.
// const char *alpm_option_get_gpgdir(alpm_handle_t *handle);
// /// Sets the path to libalpm's GnuPG home directory.
// int alpm_option_set_gpgdir(alpm_handle_t *handle, const char *gpgdir);
//
// /// Returns whether to use syslog (0 is FALSE, TRUE otherwise).
// int alpm_option_get_usesyslog(alpm_handle_t *handle);
// /// Sets whether to use syslog (0 is FALSE, TRUE otherwise).
// int alpm_option_set_usesyslog(alpm_handle_t *handle, int usesyslog);
//
// /// @name Accessors to the list of no-upgrade files.
//  * These functions modify the list of files which should
//  * not be updated by package installation.
//  * @{
//
// alpm_list_t *alpm_option_get_noupgrades(alpm_handle_t *handle);
// int alpm_option_add_noupgrade(alpm_handle_t *handle, const char *path);
// int alpm_option_set_noupgrades(alpm_handle_t *handle, alpm_list_t *noupgrade);
// int alpm_option_remove_noupgrade(alpm_handle_t *handle, const char *path);
// int alpm_option_match_noupgrade(alpm_handle_t *handle, const char *path);
// /// @}
//
// /// @name Accessors to the list of no-extract files.
//  * These functions modify the list of filenames which should
//  * be skipped packages which should
//  * not be upgraded by a sysupgrade operation.
//  * @{
//
// alpm_list_t *alpm_option_get_noextracts(alpm_handle_t *handle);
// int alpm_option_add_noextract(alpm_handle_t *handle, const char *path);
// int alpm_option_set_noextracts(alpm_handle_t *handle, alpm_list_t *noextract);
// int alpm_option_remove_noextract(alpm_handle_t *handle, const char *path);
// int alpm_option_match_noextract(alpm_handle_t *handle, const char *path);
// /// @}
//
// /// @name Accessors to the list of ignored packages.
//  * These functions modify the list of packages that
//  * should be ignored by a sysupgrade.
//  * @{
//
// alpm_list_t *alpm_option_get_ignorepkgs(alpm_handle_t *handle);
// int alpm_option_add_ignorepkg(alpm_handle_t *handle, const char *pkg);
// int alpm_option_set_ignorepkgs(alpm_handle_t *handle, alpm_list_t *ignorepkgs);
// int alpm_option_remove_ignorepkg(alpm_handle_t *handle, const char *pkg);
// /// @}
//
// /// @name Accessors to the list of ignored groups.
//  * These functions modify the list of groups whose packages
//  * should be ignored by a sysupgrade.
//  * @{
//
// alpm_list_t *alpm_option_get_ignoregroups(alpm_handle_t *handle);
// int alpm_option_add_ignoregroup(alpm_handle_t *handle, const char *grp);
// int alpm_option_set_ignoregroups(alpm_handle_t *handle, alpm_list_t *ignoregrps);
// int alpm_option_remove_ignoregroup(alpm_handle_t *handle, const char *grp);
// /// @}

// /// @addtogroup alpm_api_databases Database Functions
//  * Functions to query and manipulate the database of libalpm.
//  * @{
//
//
// /// Get the database of locally installed packages.
//  * The returned pointer points to an internal structure
//  * of libalpm which should only be manipulated through
//  * libalpm functions.
//  * @return a reference to the local database
//
// alpm_db_t *alpm_get_localdb(alpm_handle_t *handle);
//
// /// Get the list of sync databases.
//  * Returns a list of alpm_db_t structures, one for each registered
//  * sync database.
//  * @param handle the context handle
//  * @return a reference to an internal list of alpm_db_t structures
//
// alpm_list_t *alpm_get_syncdbs(alpm_handle_t *handle);
//
// /// Register a sync database of packages.
//  * @param handle the context handle
//  * @param treename the name of the sync repository
//  * @param level what level of signature checking to perform on the
//  * database; note that this must be a '.sig' file type verification
//  * @return an alpm_db_t* on success (the value), NULL on error
//
// alpm_db_t *alpm_register_syncdb(alpm_handle_t *handle, const char *treename,
// 		int level);
//
// /// Unregister all package databases.
//  * @param handle the context handle
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_unregister_all_syncdbs(alpm_handle_t *handle);
//
// /// Unregister a package database.
//  * @param db pointer to the package database to unregister
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_db_unregister(alpm_db_t *db);
//
// /// Get the name of a package database.
//  * @param db pointer to the package database
//  * @return the name of the package database, NULL on error
//
// const char *alpm_db_get_name(const alpm_db_t *db);
//
// /// Get the signature verification level for a database.
//  * Will return the default verification level if this database is set up
//  * with ALPM_SIG_USE_DEFAULT.
//  * @param db pointer to the package database
//  * @return the signature verification level
//
// int alpm_db_get_siglevel(alpm_db_t *db);
//
// /// Check the validity of a database.
//  * This is most useful for sync databases and verifying signature status.
//  * If invalid, the handle error code will be set accordingly.
//  * @param db pointer to the package database
//  * @return 0 if valid, -1 if invalid (pm_errno is set accordingly)
//
// int alpm_db_get_valid(alpm_db_t *db);
//
// /// @name Accessors to the list of servers for a database.
//  * @{
//
// alpm_list_t *alpm_db_get_servers(const alpm_db_t *db);
// int alpm_db_set_servers(alpm_db_t *db, alpm_list_t *servers);
// int alpm_db_add_server(alpm_db_t *db, const char *url);
// int alpm_db_remove_server(alpm_db_t *db, const char *url);
// /// @}
//
// int alpm_db_update(int force, alpm_db_t *db);
//
// /// Get a package entry from a package database.
//  * @param db pointer to the package database to get the package from
//  * @param name of the package
//  * @return the package entry on success, NULL on error
//
// pkg_t *alpm_db_get_pkg(alpm_db_t *db, const char *name);
//
// /// Get the package cache of a package database.
//  * @param db pointer to the package database to get the package from
//  * @return the list of packages on success, NULL on error
//
// alpm_list_t *alpm_db_get_pkgcache(alpm_db_t *db);
//
// /// Get a group entry from a package database.
//  * @param db pointer to the package database to get the group from
//  * @param name of the group
//  * @return the groups entry on success, NULL on error
//
// group_t *alpm_db_get_group(alpm_db_t *db, const char *name);
//
// /// Get the group cache of a package database.
//  * @param db pointer to the package database to get the group from
//  * @return the list of groups on success, NULL on error
//
// alpm_list_t *alpm_db_get_groupcache(alpm_db_t *db);
//
// /// Searches a database with regular expressions.
//  * @param db pointer to the package database to search in
//  * @param needles a list of regular expressions to search for
//  * @return the list of packages matching all regular expressions on success, NULL on error
//
// alpm_list_t *alpm_db_search(alpm_db_t *db, const alpm_list_t *needles);

#[derive(Default, Debug, Clone, Copy)]
pub struct alpm_db_usage_t {
    pub ALPM_DB_USAGE_SYNC: bool,
    pub ALPM_DB_USAGE_SEARCH: bool,
    pub ALPM_DB_USAGE_INSTALL: bool,
    pub ALPM_DB_USAGE_UPGRADE: bool,
    pub ALPM_DB_USAGE_ALL: bool,
}

impl alpm_db_usage_t {
    pub fn is_zero(&self) -> bool {
        !(self.ALPM_DB_USAGE_SYNC && self.ALPM_DB_USAGE_SEARCH && self.ALPM_DB_USAGE_INSTALL
            && self.ALPM_DB_USAGE_UPGRADE && self.ALPM_DB_USAGE_ALL)
    }
}

// /// Sets the usage of a database.
//  * @param db pointer to the package database to set the status for
//  * @param usage a bitmask of alpm_db_usage_t values
//  * @return 0 on success, or -1 on error
//
// int alpm_db_set_usage(alpm_db_t *db, int usage);
//
// /// Gets the usage of a database.
//  * @param db pointer to the package database to get the status of
//  * @param usage pointer to an alpm_db_usage_t to store db's status
//  * @return 0 on success, or -1 on error
//
// int alpm_db_get_usage(alpm_db_t *db, int *usage);
//
// /// @}
//
// /// @addtogroup alpm_api_packages Package Functions
//  * Functions to manipulate libalpm packages
//  * @{
//
//
// /// Create a package from a file.
//  * If full is false, the archive is read only until all necessary
//  * metadata is found. If it is true, the entire archive is read, which
//  * serves as a verification of integrity and the filelist can be created.
//  * The allocated structure should be freed using alpm_pkg_free().
//  * @param handle the context handle
//  * @param filename location of the package tarball
//  * @param full whether to stop the load after metadata is read or continue
//  * through the full archive
//  * @param level what level of package signature checking to perform on the
//  * package; note that this must be a '.sig' file type verification
//  * @param pkg address of the package pointer
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_pkg_load(alpm_handle_t *handle, const char *filename, int full,
// 		int level, pkg_t **pkg);
//
// /* Find a package in a list by name.
//  * @param haystack a list of pkg_t
//  * @param needle the package name
//  * @return a pointer to the package if found or NULL
//
// pkg_t *alpm_pkg_find(alpm_list_t *haystack, const char *needle);
//
// /* Free a package.
//  * @param pkg package pointer to free
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_pkg_free(pkg_t *pkg);
//
// /// Check the integrity (with md5) of a package from the sync cache.
//  * @param pkg package pointer
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_pkg_checkmd5sum(pkg_t *pkg);
//
// /// Compare two version strings and determine which one is 'newer'.
// int alpm_pkg_vercmp(const char *a, const char *b);
//
// /// Computes the list of packages requiring a given package.
//  * The return value of this function is a newly allocated
//  * list of package names (char*), it should be freed by the caller.
//  * @param pkg a package
//  * @return the list of packages requiring pkg
//
// alpm_list_t *alpm_pkg_compute_requiredby(pkg_t *pkg);
//
// /// Computes the list of packages optionally requiring a given package.
//  * The return value of this function is a newly allocated
//  * list of package names (char*), it should be freed by the caller.
//  * @param pkg a package
//  * @return the list of packages optionally requiring pkg
//
// alpm_list_t *alpm_pkg_compute_optionalfor(pkg_t *pkg);
//
// /// Test if a package should be ignored.
//  * Checks if the package is ignored via IgnorePkg, or if the package is
//  * in a group ignored via IgnoreGroup.
//  * @param handle the context handle
//  * @param pkg the package to test
//  * @return 1 if the package should be ignored, 0 otherwise
//
// int alpm_pkg_should_ignore(alpm_handle_t *handle, pkg_t *pkg);
//
// /// @name Package Property Accessors
//  * Any pointer returned by these functions points to internal structures
//  * allocated by libalpm. They should not be freed nor modified in any
//  * way.
//  * @{
//
//
// /// Gets the name of the file from which the package was loaded.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_filename(pkg_t *pkg);
//
// /// Returns the package base name.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_base(pkg_t *pkg);
//
// /// Returns the package name.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_name(pkg_t *pkg);
//
// /// Returns the package version as a string.
//  * This includes all available epoch, version, and pkgrel components. Use
//  * alpm_pkg_vercmp() to compare version strings if necessary.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_version(pkg_t *pkg);
//
// /// Returns the origin of the package.
//  * @return an pkgfrom_t constant, -1 on error
//
// pkgfrom_t alpm_pkg_get_origin(pkg_t *pkg);
//
// /// Returns the package description.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_desc(pkg_t *pkg);
//
// /// Returns the package URL.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_url(pkg_t *pkg);
//
// /// Returns the build timestamp of the package.
//  * @param pkg a pointer to package
//  * @return the timestamp of the build time
//
// alpm_time_t alpm_pkg_get_builddate(pkg_t *pkg);
//
// /// Returns the install timestamp of the package.
//  * @param pkg a pointer to package
//  * @return the timestamp of the install time
//
// alpm_time_t alpm_pkg_get_installdate(pkg_t *pkg);
//
// /// Returns the packager's name.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_packager(pkg_t *pkg);
//
// /// Returns the package's MD5 checksum as a string.
//  * The returned string is a sequence of 32 lowercase hexadecimal digits.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_md5sum(pkg_t *pkg);
//
// /// Returns the package's SHA256 checksum as a string.
//  * The returned string is a sequence of 64 lowercase hexadecimal digits.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_sha256sum(pkg_t *pkg);
//
// /// Returns the architecture for which the package was built.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_arch(pkg_t *pkg);
//
// /// Returns the size of the package. This is only available for sync database
//  * packages and package files, not those loaded from the local database.
//  * @param pkg a pointer to package
//  * @return the size of the package in bytes.
//
// off_t alpm_pkg_get_size(pkg_t *pkg);
//
// /// Returns the installed size of the package.
//  * @param pkg a pointer to package
//  * @return the total size of files installed by the package.
//
// off_t alpm_pkg_get_isize(pkg_t *pkg);
//
// /// Returns the package installation reason.
//  * @param pkg a pointer to package
//  * @return an enum member giving the install reason.
//
// pkgreason_t alpm_pkg_get_reason(pkg_t *pkg);
//
// /// Returns the list of package licenses.
//  * @param pkg a pointer to package
//  * @return a pointer to an internal list of strings.
//
// alpm_list_t *alpm_pkg_get_licenses(pkg_t *pkg);
//
// /// Returns the list of package groups.
//  * @param pkg a pointer to package
//  * @return a pointer to an internal list of strings.
//
// alpm_list_t *alpm_pkg_get_groups(pkg_t *pkg);
//
// /// Returns the list of package dependencies as depend_t.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of depend_t structures.
//
// alpm_list_t *alpm_pkg_get_depends(pkg_t *pkg);
//
// /// Returns the list of package optional dependencies.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of depend_t structures.
//
// alpm_list_t *alpm_pkg_get_optdepends(pkg_t *pkg);
//
// /// Returns a list of package check dependencies
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of depend_t structures.
//
// alpm_list_t *alpm_pkg_get_checkdepends(pkg_t *pkg);
//
// /// Returns a list of package make dependencies
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of depend_t structures.
//
// alpm_list_t *alpm_pkg_get_makedepends(pkg_t *pkg);
//
// /// Returns the list of packages conflicting with pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of depend_t structures.
//
// alpm_list_t *alpm_pkg_get_conflicts(pkg_t *pkg);
//
// /// Returns the list of packages provided by pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of depend_t structures.
//
// alpm_list_t *alpm_pkg_get_provides(pkg_t *pkg);
//
// /// Returns the list of available deltas for pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of strings.
//
// alpm_list_t *alpm_pkg_get_deltas(pkg_t *pkg);
//
// /// Returns the list of packages to be replaced by pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of depend_t structures.
//
// alpm_list_t *alpm_pkg_get_replaces(pkg_t *pkg);
//
// /// Returns the list of files installed by pkg.
//  * The filenames are relative to the install root,
//  * and do not include leading slashes.
//  * @param pkg a pointer to package
//  * @return a pointer to a filelist object containing a count and an array of
//  * package file objects
//
// alpm_filelist_t *alpm_pkg_get_files(pkg_t *pkg);
//
// /// Returns the list of files backed up when installing pkg.
//  * @param pkg a pointer to package
//  * @return a reference to a list of alpm_backup_t objects
//
// alpm_list_t *alpm_pkg_get_backup(pkg_t *pkg);
//
// /// Returns the database containing pkg.
//  * Returns a pointer to the alpm_db_t structure the package is
//  * originating from, or NULL if the package was loaded from a file.
//  * @param pkg a pointer to package
//  * @return a pointer to the DB containing pkg, or NULL.
//
// alpm_db_t *alpm_pkg_get_db(pkg_t *pkg);
//
// /// Returns the base64 encoded package signature.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_base64_sig(pkg_t *pkg);
//
// /// Returns the method used to validate a package during install.
//  * @param pkg a pointer to package
//  * @return an enum member giving the validation method
//
// int alpm_pkg_get_validation(pkg_t *pkg);
//
// /* End of pkg_t accessors
// /* @}
//
// /// Open a package changelog for reading.
//  * Similar to fopen in functionality, except that the returned 'file
//  * stream' could really be from an archive as well as from the database.
//  * @param pkg the package to read the changelog of (either file or db)
//  * @return a 'file stream' to the package changelog
//
// void *alpm_pkg_changelog_open(pkg_t *pkg);
//
// /// Read data from an open changelog 'file stream'.
//  * Similar to fread in functionality, this function takes a buffer and
//  * amount of data to read. If an error occurs pm_errno will be set.
//  * @param ptr a buffer to fill with raw changelog data
//  * @param size the size of the buffer
//  * @param pkg the package that the changelog is being read from
//  * @param fp a 'file stream' to the package changelog
//  * @return the number of characters read, or 0 if there is no more data or an
//  * error occurred.
//
// size_t alpm_pkg_changelog_read(void *ptr, size_t size,
// 		const pkg_t *pkg, void *fp);
//
// int alpm_pkg_changelog_close(const pkg_t *pkg, void *fp);
//
// /// Open a package mtree file for reading.
//  * @param pkg the local package to read the changelog of
//  * @return a archive structure for the package mtree file
//
// struct archive *alpm_pkg_mtree_open(pkg_t *pkg);
//
// /// Read next entry from a package mtree file.
//  * @param pkg the package that the mtree file is being read from
//  * @param archive the archive structure reading from the mtree file
//  * @param entry an archive_entry to store the entry header information
//  * @return 0 if end of archive is reached, non-zero otherwise.
//
// int alpm_pkg_mtree_next(const pkg_t *pkg, struct archive *archive,
// 		struct archive_entry **entry);
//
// int alpm_pkg_mtree_close(const pkg_t *pkg, struct archive *archive);
//
// /// Returns whether the package has an install scriptlet.
//  * @return 0 if FALSE, TRUE otherwise
//
// int alpm_pkg_has_scriptlet(pkg_t *pkg);
//
// /// Returns the size of download.
//  * Returns the size of the files that will be downloaded to install a
//  * package.
//  * @param newpkg the new package to upgrade to
//  * @return the size of the download
//
// off_t alpm_pkg_download_size(pkg_t *newpkg);
//
// alpm_list_t *alpm_pkg_unused_deltas(pkg_t *pkg);
//
// /// Set install reason for a package in the local database.
//  * The provided package object must be from the local database or this method
//  * will fail. The write to the local database is performed immediately.
//  * @param pkg the package to update
//  * @param reason the new install reason
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_pkg_set_reason(pkg_t *pkg, pkgreason_t reason);
//
//
// /* End of alpm_pkg
// /// @}
//
// /*
//  * Filelists
//
//
// /// Determines whether a package filelist contains a given path.
//  * The provided path should be relative to the install root with no leading
//  * slashes, e.g. "etc/localtime". When searching for directories, the path must
//  * have a trailing slash.
//  * @param filelist a pointer to a package filelist
//  * @param path the path to search for in the package
//  * @return a pointer to the matching file or NULL if not found
//
// alpm_file_t *alpm_filelist_contains(alpm_filelist_t *filelist, const char *path);
//
// /*
//  * Signatures
//
//
// int alpm_pkg_check_pgp_signature(pkg_t *pkg, alpm_siglist_t *siglist);
//
// int alpm_db_check_pgp_signature(alpm_db_t *db, alpm_siglist_t *siglist);
//
// int alpm_siglist_cleanup(alpm_siglist_t *siglist);
//
// int alpm_decode_signature(const char *base64_data,
// 		unsigned char **data, size_t *data_len);
//
// int alpm_extract_keyid(alpm_handle_t *handle, const char *identifier,
// 		const unsigned char *sig, const size_t len, alpm_list_t **keys);
//
// /*
//  * Groups
//
//
// alpm_list_t *alpm_find_group_pkgs(alpm_list_t *dbs, const char *name);
//
// /*
//  * Sync
//
//
// pkg_t *alpm_sync_newversion(pkg_t *pkg, alpm_list_t *dbs_sync);
//
// /// @addtogroup alpm_api_trans Transaction Functions
//  * Functions to manipulate libalpm transactions
//  * @{
//
//

/// Transaction flags
#[derive(Default, Debug, Clone)]
pub struct alpm_transflag_t {
    /// Ignore dependency checks.
    pub NODEPS: bool,
    /// Ignore file conflicts and overwrite files.
    pub FORCE: bool,
    /// Delete files even if they are tagged as backup.
    pub NOSAVE: bool,
    /// Ignore version numbers when checking dependencies.
    pub NODEPVERSION: bool,
    /// Remove also any packages depending on a package being removed.
    pub CASCADE: bool,
    /// Remove packages and their unneeded deps (not explicitly installed).
    pub RECURSE: bool,
    /// Modify database but do not commit changes to the filesystem.
    pub DBONLY: bool,
    /* (1 << 7) flag can go here */
    /// Use ALPM_PKG_REASON_DEPEND when installing packages.
    pub ALLDEPS: bool,
    /// Only download packages and do not actually install.
    pub DOWNLOADONLY: bool,
    /// Do not execute install scriptlets after installing.
    pub NOSCRIPTLET: bool,
    /// Ignore dependency conflicts.
    pub NOCONFLICTS: bool,
    /* (1 << 12) flag can go here */
    /// Do not install a package if it is already installed and up to date.
    pub NEEDED: bool,
    /// Use ALPM_PKG_REASON_EXPLICIT when installing packages.
    pub ALLEXPLICIT: bool,
    /// Do not remove a package if it is needed by another one.
    pub UNNEEDED: bool,
    /// Remove also explicitly installed unneeded deps (use with pub RECURSE).
    pub RECURSEALL: bool,
    /// Do not lock the database during the operation.
    pub NOLOCK: bool,
}
//
// /// Returns the bitfield of flags for the current transaction.
//  * @param handle the context handle
//  * @return the bitfield of transaction flags
//
// int alpm_trans_get_flags(alpm_handle_t *handle);
//
// /// Returns a list of packages added by the transaction.
//  * @param handle the context handle
//  * @return a list of pkg_t structures
//
// alpm_list_t *alpm_trans_get_add(alpm_handle_t *handle);
//
// /// Returns the list of packages removed by the transaction.
//  * @param handle the context handle
//  * @return a list of pkg_t structures
//
// alpm_list_t *alpm_trans_get_remove(alpm_handle_t *handle);
//
// /// Initialize the transaction.
//  * @param handle the context handle
//  * @param flags flags of the transaction (like nodeps, etc; see alpm_transflag_t)
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_trans_init(alpm_handle_t *handle, int flags);
//
// /// Prepare a transaction.
//  * @param handle the context handle
//  * @param data the address of an alpm_list where a list
//  * of depmissing_t objects is dumped (conflicting packages)
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_trans_prepare(alpm_handle_t *handle, alpm_list_t **data);
//
// /// Commit a transaction.
//  * @param handle the context handle
//  * @param data the address of an alpm_list where detailed description
//  * of an error can be dumped (i.e. list of conflicting files)
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_trans_commit(alpm_handle_t *handle, alpm_list_t **data);
//
// /// Interrupt a transaction.
//  * @param handle the context handle
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_trans_interrupt(alpm_handle_t *handle);
//
// /// Release a transaction.
//  * @param handle the context handle
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_trans_release(alpm_handle_t *handle);
// /// @}
//
// /// @name Common Transactions
// /// @{
//
// /// Search for packages to upgrade and add them to the transaction.
//  * @param handle the context handle
//  * @param enable_downgrade allow downgrading of packages if the remote version is lower
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_sync_sysupgrade(alpm_handle_t *handle, int enable_downgrade);
//
// /// Add a package to the transaction.
//  * If the package was loaded by alpm_pkg_load(), it will be freed upon
//  * alpm_trans_release() invocation.
//  * @param handle the context handle
//  * @param pkg the package to add
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_add_pkg(alpm_handle_t *handle, pkg_t *pkg);
//
// /// Add a package removal action to the transaction.
//  * @param handle the context handle
//  * @param pkg the package to uninstall
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_remove_pkg(alpm_handle_t *handle, pkg_t *pkg);
//
// /// @}
//
// /// @addtogroup alpm_api_depends Dependency Functions
//  * Functions dealing with libalpm representation of dependency
//  * information.
//  * @{
//
//
// alpm_list_t *alpm_checkdeps(alpm_handle_t *handle, alpm_list_t *pkglist,
// 		alpm_list_t *remove, alpm_list_t *upgrade, int reversedeps);
// pkg_t *alpm_find_satisfier(alpm_list_t *pkgs, const char *depstring);
// pkg_t *alpm_find_dbs_satisfier(alpm_handle_t *handle,
// 		alpm_list_t *dbs, const char *depstring);
//
// alpm_list_t *alpm_checkconflicts(alpm_handle_t *handle, alpm_list_t *pkglist);
//
// /// Returns a newly allocated string representing the dependency information.
//  * @param dep a dependency info structure
//  * @return a formatted string, e.g. "glibc>=2.12"
//
// char *alpm_dep_compute_string(const depend_t *dep);
//

// depend_t *alpm_dep_from_string(const char *depstring);
//
// /// Free a dependency info structure
//  * @param dep struct to free
//
// void alpm_dep_free(depend_t *dep);
//
// /*
//  * Helpers
//
//
// /* checksums
// char *alpm_compute_md5sum(const char *filename);
// char *alpm_compute_sha256sum(const char *filename);
//
// alpm_handle_t *initialize(const char *root, const char *dbpath,
// 		errno_t *err);
// int alpm_release(alpm_handle_t *handle);
// int alpm_unlock(alpm_handle_t *handle);
#[derive(Default)]
// pub struct alpm_caps {
pub struct Capabilities {
    pub ALPM_CAPABILITY_NLS: bool,
    pub ALPM_CAPABILITY_DOWNLOADER: bool,
    pub ALPM_CAPABILITY_SIGNATURES: bool,
}

// const char *alpm_version(void);
// void alpm_fileconflict_free(fileconflict_t *conflict);
// void alpm_depmissing_free(depmissing_t *miss);
// void alpm_conflict_free(alpm_conflict_t *conflict);

// /*
//  *  alpm.c
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
//
//
// #ifdef HAVE_LIBCURL
// #include <curl/curl.h>
// #endif
//
// /* libalpm
// #include "alpm.h"
// #include "alpm_list.h"
// #include "handle.h"
// #include "log.h"
// #include "util.h"
//
// /// \addtogroup alpm_interface Interface Functions
//  * @brief Functions to initialize and release libalpm
//  * @{
//

/// Initializes the library.
/// Creates handle, connects to database and creates lockfile.
/// This must be called before any other functions are called.
/// * `root` the root path for all filesystem operations
/// * `dbpath` the absolute path to the libalpm database
/// * returns a context handle on success, or error
pub fn initialize(root: &String, dbpath: &String) -> Result<alpm_handle_t> {
    let myerr = errno_t::default();
    let lf = "db.lck";
    let hookdir;
    let mut myhandle = alpm_handle_t::_alpm_handle_new();

    _alpm_set_directory_option(root, &mut myhandle.root, true)?;
    _alpm_set_directory_option(dbpath, &mut myhandle.dbpath, true)?;

    /* to concatenate myhandle->root (ends with a slash) with SYSHOOKDIR (starts
     * with a slash) correctly, we skip SYSHOOKDIR[0]; the regular +1 therefore
     * disappears from the allocation */
    hookdir = format!("{}{}", myhandle.root, SYSHOOKDIR);
    myhandle.hookdirs = Vec::new();
    myhandle.hookdirs.push(hookdir);

    /* set default database extension */
    myhandle.dbext = String::from(".db");

    myhandle.lockfile = format!("{}{}", myhandle.alpm_option_get_dbpath(), lf);

    myhandle._alpm_db_register_local()?;

    // #ifdef ENABLE_NLS
    // 	bindtextdomain("libalpm", LOCALEDIR);
    // #endif
    //
    return Ok(myhandle);
}

/// Release the library.
/// Disconnects from the database, removes handle and lockfile
/// This should be the last alpm call you make.
/// After this returns, handle should be considered invalid and cannot be reused
/// in any way.
/// * `myhandle` the context handle
/// * returns 0 on success, -1 on error
pub fn alpm_release(myhandle: alpm_handle_t) -> i32 {
    unimplemented!();
    // 	int ret = 0;
    // 	alpm_db_t *db;
    //
    // 	CHECK_HANDLE(myhandle, return -1);
    //
    // 	/* close local database
    // 	db = myhandle->db_local;
    // 	if(db) {
    // 		db->ops->unregister(db);
    // 		myhandle->db_local = NULL;
    // 	}
    //
    // 	if(alpm_unregister_all_syncdbs(myhandle) == -1) {
    // 		ret = -1;
    // 	}
    //
    // 	_alpm_handle_unlock(myhandle);
    // 	_alpm_handle_free(myhandle);
    //
    // #ifdef HAVE_LIBCURL
    // 	curl_global_cleanup();
    // #endif
    //
    // 	return ret;
}

/// Get the version of library.
pub fn alpm_version() -> String {
    unimplemented!();
    // return LIB_VERSION;
}

/// Get the capabilities of the library.
pub fn capabilities() -> Capabilities {
    return Capabilities::default();
    // 	return 0
    // #ifdef ENABLE_NLS
    // 		| ALPM_CAPABILITY_NLS
    // #endif
    // #ifdef HAVE_LIBCURL
    // 		| ALPM_CAPABILITY_DOWNLOADER
    // #endif
    // #ifdef HAVE_LIBGPGME
    // 		| ALPM_CAPABILITY_SIGNATURES
    // #endif
    // 		| 0;
}
