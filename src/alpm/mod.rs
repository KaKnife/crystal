/*
 * alpm.h
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
#[macro_use]
mod util;
mod handle;
mod deps;
mod db;
mod package;
mod trans;
mod version;
mod conflict;
mod error;
mod remove;
mod be_package;
mod dload;
mod sync;
mod be_sync;
mod signing;
mod alpm_list;
use self::signing::*;
use self::util::*;
use self::dload::*;
use self::version::*;
use self::trans::*;
use self::handle::*;
use self::db::*;

pub use self::remove::alpm_remove_pkg;
pub use self::package::Package;
pub use self::handle::Handle;
pub use self::db::Database;
pub use self::deps::alpm_dep_from_string;
pub use self::be_sync::db_update;
pub use self::deps::alpm_find_satisfier;
pub use self::error::Error;

const SYSHOOKDIR: &str = "/usr/local/share/libalpm/hooks/";

pub type Result<T> = std::result::Result<T, self::Error>;

// libarchive
// #include <archive.h>
// #include <archive_entry.h>

/* Arch Linux Package Management library */

type Time = i64;

/// Package install reasons.
#[derive(Debug, Clone, Copy)]
pub enum PackageReason {
    /// Explicitly requested by the user.
    Explicit = 0,
    /// Installed as a dependency for another package.
    Dependency = 1,
}
impl Default for PackageReason {
    fn default() -> Self {
        PackageReason::Explicit
    }
}
impl From<u8> for PackageReason {
    fn from(n: u8) -> PackageReason {
        match n {
            0 => PackageReason::Explicit,
            1 => PackageReason::Dependency,
            _ => unimplemented!(),
        }
    }
}

impl Default for PackageFrom {
    fn default() -> Self {
        PackageFrom::File
    }
}

/// Location a package object was loaded from.
#[derive(Debug, Clone, Copy)]
pub enum PackageFrom {
    File = 1,
    LocalDatabase,
    SyncDatabase,
}

/// Method used to validate a package.
pub enum PackageValidation {
    Unkown = 0,
    None = (1 << 0),
    MD5Sum = (1 << 1),
    SHA256Sum = (1 << 2),
    Signature = (1 << 3),
}

/// Types of version constraints in dependency specs.
#[derive(Debug, Clone)]
pub enum Depmod {
    /// No version constraint
    Any,
    /// Test version equality (package=x.y.z)
    EQ,
    /// Test for at least a version (package>=x.y.z)
    GE,
    /// Test for at most a version (package<=x.y.z)
    LE,
    /// Test for greater than some version (package>x.y.z)
    GT,
    /// Test for less than some version (package<x.y.z)
    LT,
}

impl Default for Depmod {
    fn default() -> Self {
        Depmod::Any
    }
}

/// File conflict type.
/// Whether the conflict results from a file existing on the filesystem, or with
/// another target in the transaction.
#[derive(Debug)]
enum FileConflictType {
    Target = 1,
    Filesystem,
}

/// PGP signature verification options
#[derive(Default, Clone, Debug, Copy)]
pub struct SigLevel {
    pub package: bool,
    pub package_optional: bool,
    pub package_marginal_ok: bool,
    pub package_unknown_ok: bool,

    pub database: bool,
    pub database_optional: bool,
    pub database_marginal_ok: bool,
    pub database_unknown_ok: bool,

    pub use_default: bool,
}
use std;
impl std::ops::BitOr for SigLevel {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        let mut new = SigLevel::default();
        new.package = self.package | rhs.package;
        new.package_optional = self.package_optional | rhs.package_optional;
        new.package_marginal_ok = self.package_marginal_ok | rhs.package_marginal_ok;
        new.package_unknown_ok = self.package_unknown_ok | rhs.package_unknown_ok;

        new.database = self.database | rhs.database;
        new.database_optional = self.database_optional | rhs.database_optional;
        new.database_marginal_ok = self.database_marginal_ok | rhs.database_marginal_ok;
        new.database_unknown_ok = self.database_unknown_ok | rhs.database_unknown_ok;

        new.use_default = self.use_default | rhs.use_default;
        new
    }
}
impl std::ops::BitAnd for SigLevel {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        let mut new = SigLevel::default();
        new.package = self.package & rhs.package;
        new.package_optional = self.package_optional & rhs.package_optional;
        new.package_marginal_ok = self.package_marginal_ok & rhs.package_marginal_ok;
        new.package_unknown_ok = self.package_unknown_ok & rhs.package_unknown_ok;

        new.database = self.database & rhs.database;
        new.database_optional = self.database_optional & rhs.database_optional;
        new.database_marginal_ok = self.database_marginal_ok & rhs.database_marginal_ok;
        new.database_unknown_ok = self.database_unknown_ok & rhs.database_unknown_ok;

        new.use_default = self.use_default & rhs.use_default;
        new
    }
}
impl std::ops::Not for SigLevel {
    type Output = Self;
    fn not(self) -> Self {
        let mut new = SigLevel::default();
        new.package = self.package;
        new.package_optional = self.package_optional;
        new.package_marginal_ok = self.package_marginal_ok;
        new.package_unknown_ok = self.package_unknown_ok;

        new.database = self.database;
        new.database_optional = self.database_optional;
        new.database_marginal_ok = self.database_marginal_ok;
        new.database_unknown_ok = self.database_unknown_ok;

        new.use_default = self.use_default;
        new
    }
}
impl SigLevel {
    pub fn not_zero(&self) -> bool {
        !(self.package || self.package_optional || self.package_marginal_ok
            || self.package_unknown_ok || self.database || self.database_optional
            || self.database_marginal_ok || self.database_unknown_ok || self.use_default)
    }
}

/// PGP signature verification status return codes
#[derive(Debug, Clone)]
enum SignatureStatus {
    Valid,
    KeyExpired,
    SigExpired,
    Unknown,
    KeyDisabled,
    Invalid,
}
impl Default for SignatureStatus {
    fn default() -> Self {
        SignatureStatus::Valid
    }
}

/// PGP signature verification status return codes
#[derive(Debug, Clone)]
enum SigValidity {
    Full,
    Marginal,
    Never,
    Unknown,
}
impl Default for SigValidity {
    fn default() -> Self {
        SigValidity::Unknown
    }
}

/// Dependency
#[derive(Debug, Clone, Default)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    desc: String,
    depmod: Depmod,
}

/// Missing dependency
pub struct DepMissing {
    pub target: String,
    pub depend: Dependency,
    /// this is used only in the case of a remove dependency error
    pub causingpkg: String,
}

/// Conflict
pub struct Conflict<'a> {
    package1_hash: u64,
    package2_hash: u64,
    pub package1: String,
    pub package2: String,
    reason: &'a Dependency,
}

/// File conflict
struct FileConflict {
    target: String,
    ttype: FileConflictType,
    file: String,
    ctarget: String,
}

/// Package group. aka alpm_group_t
#[derive(Debug, Clone)]
pub struct Group {
    /// group name
    pub name: String,
    /// list of packages
    pub packages: Vec<Package>,
}

/// Package upgrade delta
struct Delta {
    /// filename of the delta patch
    delta: String,
    /// md5sum of the delta file
    delta_md5: String,
    /// filename of the 'before' file
    from: String,
    /// filename of the 'after' file
    to: String,
    /// filesize of the delta file
    delta_size: usize,
    /// download filesize of the delta file
    download_size: usize,
}

/// File in a package
pub struct File {
    name: String,
    size: usize,
    // mode_t mode: Mode
}

/// Package filelist container
struct FileList {
    count: usize,
    files: File,
}

/// Local package or package file backup entry
struct Backup {
    name: String,
    hash: String,
}

#[derive(Debug, Clone, Default)]
struct PgpKey {
    // void *data;
    fingerprint: String,
    uid: String,
    name: String,
    email: String,
    created: Time,
    expires: Time,
    length: u32,
    revoked: u32,
    pubkey_algo: char,
}

/// Signature result. Contains the key, status, and validity of a given
/// signature.
#[derive(Debug, Clone, Default)]
struct SignatureResult {
    key: PgpKey,
    status: SignatureStatus,
    validity: SigValidity,
}

/// Signature list. Contains the number of signatures found and a pointer to an
/// array of results. The array is of size count.
#[derive(Debug, Clone, Default)]
pub struct SignatureList {
    count: usize,
    results: SignatureResult,
}

enum HookWhen {
    PreTransaction = 1,
    PostTransaction,
}

/// Logging Levels
#[derive(Debug, Default)]
pub struct LogLevel {
    pub error: bool,    //    = 1,
    pub warning: bool,  //  = (1 << 1),
    pub debug: bool,    //    = (1 << 2),
    pub function: bool, // = (1 << 3)
}

// type alpm_cb_log = (alpm_loglevel_t, String, va_list);

/// Type of events.
enum EventType {
    //     /// Dependencies will be computed for a package.
    //     ALPM_EVENT_CHECKDEPS_START = 1,
    //     /// Dependencies were computed for a package.
    //     ALPM_EVENT_CHECKDEPS_DONE,
    //     /// File conflicts will be computed for a package.
    //     ALPM_EVENT_FILECONFLICTS_START,
    //     /// File conflicts were computed for a package.
    //     ALPM_EVENT_FILECONFLICTS_DONE,
    //     /// Dependencies will be resolved for target package.
    //     ALPM_EVENT_RESOLVEDEPS_START,
    //     /// Dependencies were resolved for target package.
    //     ALPM_EVENT_RESOLVEDEPS_DONE,
    //     /// Inter-conflicts will be checked for target package.
    //     ALPM_EVENT_INTERCONFLICTS_START,
    //     /// Inter-conflicts were checked for target package.
    //     ALPM_EVENT_INTERCONFLICTS_DONE,
    //     /// Processing the package transaction is starting.
    //     ALPM_EVENT_TRANSACTION_START,
    //     /// Processing the package transaction is finished.
    //     ALPM_EVENT_TRANSACTION_DONE,
    //     /// Package will be installed/upgraded/downgraded/re-installed/removed; See
    //     /// alpm_event_package_operation_t for arguments.
    //     ALPM_EVENT_package_OPERATION_START,
    //     /// Package was installed/upgraded/downgraded/re-installed/removed; See
    //     /// alpm_event_package_operation_t for arguments.
    //     ALPM_EVENT_package_OPERATION_DONE,
    //     /// Target package's integrity will be checked.
    //     ALPM_EVENT_INTEGRITY_START,
    //     /// Target package's integrity was checked.
    //     ALPM_EVENT_INTEGRITY_DONE,
    //     /// Target package will be loaded.
    //     ALPM_EVENT_LOAD_START,
    //     /// Target package is finished loading.
    //     ALPM_EVENT_LOAD_DONE,
    //     /// Target delta's integrity will be checked.
    //     ALPM_EVENT_DELTA_INTEGRITY_START,
    //     /// Target delta's integrity was checked.
    //     ALPM_EVENT_DELTA_INTEGRITY_DONE,
    //     /// Deltas will be applied to packages.
    //     ALPM_EVENT_DELTA_PATCHES_START,
    //     /// Deltas were applied to packages.
    //     ALPM_EVENT_DELTA_PATCHES_DONE,
    //     /// Delta patch will be applied to target package; See
    //     /// alpm_event_delta_patch_t for arguments..
    //     ALPM_EVENT_DELTA_PATCH_START,
    //     /// Delta patch was applied to target package.
    //     ALPM_EVENT_DELTA_PATCH_DONE,
    //     /// Delta patch failed to apply to target package.
    //     ALPM_EVENT_DELTA_PATCH_FAILED,
    //     /// Scriptlet has printed information; See alpm_event_scriptlet_info_t for
    //     /// arguments.
    //     ALPM_EVENT_SCRIPTLET_INFO,
    //     /// Files will be downloaded from a repository.
    //     ALPM_EVENT_RETRIEVE_START,
    //     /// Files were downloaded from a repository.
    //     ALPM_EVENT_RETRIEVE_DONE,
    //     /// Not all files were successfully downloaded from a repository.
    //     ALPM_EVENT_RETRIEVE_FAILED,
    //     /// A file will be downloaded from a repository; See alpm_event_pkgdownload_t
    //     /// for arguments
    //     ALPM_EVENT_PKGDOWNLOAD_START,
    //     /// A file was downloaded from a repository; See alpm_event_pkgdownload_t
    //     /// for arguments
    //     ALPM_EVENT_PKGDOWNLOAD_DONE,
    //     /// A file failed to be downloaded from a repository; See
    //     /// alpm_event_pkgdownload_t for arguments
    //     ALPM_EVENT_PKGDOWNLOAD_FAILED,
    //     /// Disk space usage will be computed for a package.
    //     ALPM_EVENT_DISKSPACE_START,
    //     /// Disk space usage was computed for a package.
    //     ALPM_EVENT_DISKSPACE_DONE,
    //     /// An optdepend for another package is being removed; See
    //     /// alpm_event_optdep_removal_t for arguments.
    //     ALPM_EVENT_OPTDEP_REMOVAL,
    //     /// A configured repository database is missing; See
    //     /// alpm_event_database_missing_t for arguments.
    //     ALPM_EVENT_database_MISSING,
    //     /// Checking keys used to create signatures are in keyring.
    //     ALPM_EVENT_KEYRING_START,
    //     /// Keyring checking is finished.
    //     ALPM_EVENT_KEYRING_DONE,
    //     /// Downloading missing keys into keyring.
    //     ALPM_EVENT_KEY_DOWNLOAD_START,
    //     /// Key downloading is finished.
    //     ALPM_EVENT_KEY_DOWNLOAD_DONE,
    //     /// A .pacnew file was created; See alpm_event_pacnew_created_t for arguments.
    //     ALPM_EVENT_PACNEW_CREATED,
    //     /// A .pacsave file was created; See alpm_event_pacsave_created_t for
    //     /// arguments
    //     ALPM_EVENT_PACSAVE_CREATED,
    //     /// Processing hooks will be started.
    //     ALPM_EVENT_HOOK_START,
    //     /// Processing hooks is finished.
    //     ALPM_EVENT_HOOK_DONE,
    //     /// A hook is starting
    //     ALPM_EVENT_HOOK_RUN_START,
    //     /// A hook has finished running
    //     ALPM_EVENT_HOOK_RUN_DONE,
}

struct EventAny {
    /// Type of event.
    event_type: EventType,
}

enum PackageOperation {
    /// Package (to be) installed. (No oldpkg)
    Install = 1,
    /// Package (to be) upgraded
    Upgrade,
    /// Package (to be) re-installed.
    Reinstall,
    /// Package (to be) downgraded.
    Downgrade,
    /// Package (to be) removed. (No newpkg)
    Remove,
}

struct EventPackageOperation<'a> {
    /// Type of event.
    etype: EventType,
    /// Type of operation.
    operation: PackageOperation,
    /// Old package.
    oldpkg: &'a Package,
    /// New package.
    newpkg: &'a Package,
}

// typedef struct _alpm_event_optdep_removal_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Package with the optdep.
// 	Package *pkg;
// 	/// Optdep being removed.
// 	Dependency *optdep;
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
// 	Package *oldpkg;
// 	/// New Package.
// 	Package *newpkg;
// 	/// Filename of the file without the .pacnew suffix
// 	const char *file;
// } alpm_event_pacnew_created_t;

// typedef struct _alpm_event_pacsave_created_t {
// 	/// Type of event.
// 	alpm_event_type_t type;
// 	/// Old package.
// 	Package *oldpkg;
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
// type CbEvent = fn(&mut Event);

/// Type of questions.
/// Unlike the events or progress enumerations, this enum has bitmask values
/// so a frontend can use a bitmask map to supply preselected answers to the
/// different types of questions.
enum QuestionType {
    InstallIgnorepkg = (1 << 0),
    ReplacePkg = (1 << 1),
    ConflictPkg = (1 << 2),
    CorruptedPkg = (1 << 3),
    RemovePkgs = (1 << 4),
    SelectProvider = (1 << 5),
    ImportKey = (1 << 6),
}

struct QestionAny {
    /// Type of question.
    qtype: QuestionType,
    /// Answer.
    answer: bool,
}

struct QuestionInstalIgnorePackage<'a> {
    /// Type of question.
    qtype: QuestionType,
    /// Answer: whether or not to install pkg anyway.
    install: bool,
    /// Package in IgnorePkg/IgnoreGroup.
    pkg: &'a Package,
}

struct QuestionReplace<'a> {
    /// Type of question.
    qtype: QuestionType,
    /// Answer: whether or not to replace oldpkg with newpkg.
    replace: bool,
    /// Package to be replaced.
    oldpkg: &'a Package,
    /// Package to replace with.
    newpkg: &'a Package,
    /// DB of newpkg
    newdb: &'a Database,
}

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
// 	/// List of Package* with unresolved dependencies.
// 	alpm_list_t *packages;
// } alpm_question_remove_pkgs_t;

// typedef struct _alpm_question_select_provider_t {
// 	/// Type of question.
// 	alpm_question_type_t type;
// 	/// Answer: which provider to use (index from providers).
// 	int use_index;
// 	/// List of Package* as possible providers.
// 	alpm_list_t *providers;
// 	/// What providers provide for.
// 	Dependency *depend;
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
// 	alpm_question_install_ignorePackage install_ignorepkg;
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

/// Type of download progress callbacks.
/// * @param filename the name of the file being downloaded
///  * @param xfered the number of transferred bytes
///  * @param total the total number of bytes to transfer
type CbDownload = fn(filename: &String, xfered: usize, total: usize);

// typedef void (*alpm_cb_totaldl)(off_t total);

/// A callback for downloading files
///
/// * url - the URL of the file to be downloaded
/// * localpath - the directory to which the file should be downloaded
/// * force - whether to force an update, even if the file is the same
/// * return - 0 on success, 1 if the file exists and is identical, -1 on error.
// type alpm_cb_fetch = fn(&String, &String, i32) -> i32;
type FetchCallback = fn(&String, &String, i32) -> i32;

// /// Fetch a remote pkg.
//  * @param handle the context handle
//  * @param url URL of the package to download
//  * @return the downloaded filepath on success, NULL on error
//
// char *alpm_fetch_pkgurl(Handle *handle, const char *url);

// /// Returns the callback used for logging.
// alpm_cb_log alpm_option_get_logcb(Handle *handle);

// /// Sets the callback used for logging.
// int alpm_option_set_logcb(Handle *handle, alpm_cb_log cb);

// /// Returns the callback used to report download progress.
// alpm_cb_download alpm_option_get_dlcb(Handle *handle);

// /// Sets the callback used to report download progress.
// int alpm_option_set_dlcb(Handle *handle, alpm_cb_download cb);

// /// Returns the downloading callback.
// alpm_cb_fetch alpm_option_get_fetchcb(Handle *handle);

// /// Sets the downloading callback.
// int alpm_option_set_fetchcb(Handle *handle, alpm_cb_fetch cb);

// /// Returns the callback used to report total download size.
// alpm_cb_totaldl alpm_option_get_totaldlcb(Handle *handle);

// /// Sets the callback used to report total download size.
// int alpm_option_set_totaldlcb(Handle *handle, alpm_cb_totaldl cb);

// /// Returns the callback used for events.
// alpm_cb_event alpm_option_get_eventcb(Handle *handle);

// /// Sets the callback used for events.
// int alpm_option_set_eventcb(Handle *handle, alpm_cb_event cb);

// /// Returns the callback used for questions.
// alpm_cb_question alpm_option_get_questioncb(Handle *handle);

// /// Sets the callback used for questions.
// int alpm_option_set_questioncb(Handle *handle, alpm_cb_question cb);

// /// Returns the callback used for operation progress.
// alpm_cb_progress alpm_option_get_progresscb(Handle *handle);

// /// Sets the callback used for operation progress.
// int alpm_option_set_progresscb(Handle *handle, alpm_cb_progress cb);

// /// Returns the root of the destination filesystem. Read-only.
// const char *alpm_option_get_root(Handle *handle);

// /// Returns the path to the database directory. Read-only.
// const char *alpm_option_get_dbpath(Handle *handle);

// /// Get the name of the database lock file. Read-only.
// const char *alpm_option_get_lockfile(Handle *handle);

// /// Returns the logfile name.
// const char *alpm_option_get_logfile(Handle *handle);

// /// Sets the logfile name.
// int alpm_option_set_logfile(Handle *handle, const char *logfile);

// /// Returns the path to libalpm's GnuPG home directory.
// const char *alpm_option_get_gpgdir(Handle *handle);

// /// Sets the path to libalpm's GnuPG home directory.
// int alpm_option_set_gpgdir(Handle *handle, const char *gpgdir);

// /// Returns whether to use syslog (0 is FALSE, TRUE otherwise).
// int alpm_option_get_usesyslog(Handle *handle);

// /// Sets whether to use syslog (0 is FALSE, TRUE otherwise).
// int alpm_option_set_usesyslog(Handle *handle, int usesyslog);

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
// Database *alpm_get_localdb(Handle *handle);
//
// /// Get the list of sync databases.
//  * Returns a list of Database structures, one for each registered
//  * sync database.
//  * @param handle the context handle
//  * @return a reference to an internal list of Database structures
//
// alpm_list_t *alpm_get_syncdbs(Handle *handle);
//
// /// Register a sync database of packages.
//  * @param handle the context handle
//  * @param treename the name of the sync repository
//  * @param level what level of signature checking to perform on the
//  * database; note that this must be a '.sig' file type verification
//  * @return an Database* on success (the value), NULL on error
//
// Database *alpm_register_syncdb(Handle *handle, const char *treename,
// 		int level);
//
// /// Unregister all package databases.
//  * @param handle the context handle
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_unregister_all_syncdbs(Handle *handle);
//
// /// Unregister a package database.
//  * @param db pointer to the package database to unregister
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_db_unregister(Database *db);
//
// /// Get the name of a package database.
//  * @param db pointer to the package database
//  * @return the name of the package database, NULL on error
//
// const char *alpm_db_get_name(const Database *db);
//
// /// Get the signature verification level for a database.
//  * Will return the default verification level if this database is set up
//  * with use_default.
//  * @param db pointer to the package database
//  * @return the signature verification level
//
// int alpm_db_get_siglevel(Database *db);
//
// /// Check the validity of a database.
//  * This is most useful for sync databases and verifying signature status.
//  * If invalid, the handle error code will be set accordingly.
//  * @param db pointer to the package database
//  * @return 0 if valid, -1 if invalid (pm_errno is set accordingly)
//
// int alpm_db_get_valid(Database *db);
//
// /// @name Accessors to the list of servers for a database.
//  * @{
//
// alpm_list_t *alpm_db_get_servers(const Database *db);
// int alpm_db_set_servers(Database *db, alpm_list_t *servers);
// int alpm_db_add_server(Database *db, const char *url);
// int alpm_db_remove_server(Database *db, const char *url);
// /// @}
//
// int alpm_db_update(int force, Database *db);
//
// /// Get a package entry from a package database.
//  * @param db pointer to the package database to get the package from
//  * @param name of the package
//  * @return the package entry on success, NULL on error
//
// Package *alpm_db_get_pkg(Database *db, const char *name);
//
// /// Get the package cache of a package database.
//  * @param db pointer to the package database to get the package from
//  * @return the list of packages on success, NULL on error
//
// alpm_list_t *alpm_db_get_pkgcache(Database *db);
//
// /// Get a group entry from a package database.
//  * @param db pointer to the package database to get the group from
//  * @param name of the group
//  * @return the groups entry on success, NULL on error
//
// group_t *alpm_db_get_group(Database *db, const char *name);
//
// /// Get the group cache of a package database.
//  * @param db pointer to the package database to get the group from
//  * @return the list of groups on success, NULL on error
//
// alpm_list_t *alpm_db_get_groupcache(Database *db);
//
// /// Searches a database with regular expressions.
//  * @param db pointer to the package database to search in
//  * @param needles a list of regular expressions to search for
//  * @return the list of packages matching all regular expressions on success, NULL on error
//
// alpm_list_t *alpm_db_search(Database *db, const alpm_list_t *needles);

#[derive(Default, Debug, Clone, Copy)]
pub struct DatabaseUsage {
    pub sync: bool,
    pub search: bool,
    pub install: bool,
    pub upgrade: bool,
}

impl DatabaseUsage {
    pub fn is_zero(&self) -> bool {
        !self.sync && !self.search && !self.install && !self.upgrade
    }
    pub fn set_all(&mut self) {
        self.sync = true;
        self.search = true;
        self.install = true;
        self.upgrade = true;
    }
}

// /// Sets the usage of a database.
//  * @param db pointer to the package database to set the status for
//  * @param usage a bitmask of DatabaseUsage values
//  * @return 0 on success, or -1 on error
//
// int alpm_db_set_usage(Database *db, int usage);

// /// Gets the usage of a database.
//  * @param db pointer to the package database to get the status of
//  * @param usage pointer to an DatabaseUsage to store db's status
//  * @return 0 on success, or -1 on error
// int alpm_db_get_usage(Database *db, int *usage);

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
// int alpm_pkg_load(Handle *handle, const char *filename, int full,
// 		int level, Package **pkg);

// /* Find a package in a list by name.
//  * @param haystack a list of Package
//  * @param needle the package name
//  * @return a pointer to the package if found or NULL
// Package *alpm_pkg_find(alpm_list_t *haystack, const char *needle);

// /* Free a package.
//  * @param pkg package pointer to free
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
// int alpm_pkg_free(Package *pkg);

// /// Computes the list of packages requiring a given package.
//  * The return value of this function is a newly allocated
//  * list of package names (char*), it should be freed by the caller.
//  * @param pkg a package
//  * @return the list of packages requiring pkg
// alpm_list_t *alpm_pkg_compute_requiredby(Package *pkg);

// /// Computes the list of packages optionally requiring a given package.
//  * The return value of this function is a newly allocated
//  * list of package names (char*), it should be freed by the caller.
//  * @param pkg a package
//  * @return the list of packages optionally requiring pkg
//
// alpm_list_t *alpm_pkg_compute_optionalfor(Package *pkg);

// /// Test if a package should be ignored.
//  * Checks if the package is ignored via IgnorePkg, or if the package is
//  * in a group ignored via IgnoreGroup.
//  * @param handle the context handle
//  * @param pkg the package to test
//  * @return 1 if the package should be ignored, 0 otherwise
//
// int alpm_pkg_should_ignore(Handle *handle, Package *pkg);

// /// Gets the name of the file from which the package was loaded.
// const char *alpm_pkg_get_filename(Package *pkg);

// /// Returns the package base name.
// const char *alpm_pkg_get_base(Package *pkg);

// /// Returns the origin of the package.
// PackageFrom alpm_pkg_get_origin(Package *pkg);

// /// Returns the package description.
// const char *alpm_pkg_get_desc(Package *pkg);

// /// Returns the architecture for which the package was built.
// const char *alpm_pkg_get_arch(Package *pkg);

// /// Returns the size of the package. This is only available for sync database
//  * packages and package files, not those loaded from the local database.
// off_t alpm_pkg_get_size(Package *pkg);

// /// Returns the installed size of the package.
// off_t alpm_pkg_get_isize(Package *pkg);

// /// Returns the package installation reason.
// PackageReason alpm_pkg_get_reason(Package *pkg);

// /// Returns the list of package licenses.
// alpm_list_t *alpm_pkg_get_licenses(Package *pkg);

// /// Returns the list of package groups.
// alpm_list_t *alpm_pkg_get_groups(Package *pkg);

// /// Returns the list of package dependencies as Dependency.
// alpm_list_t *alpm_pkg_get_depends(Package *pkg);

// /// Returns the list of package optional dependencies.
// alpm_list_t *alpm_pkg_get_optdepends(Package *pkg);

// /// Returns a list of package check dependencies
// alpm_list_t *alpm_pkg_get_checkdepends(Package *pkg);

// /// Returns a list of package make dependencies
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of Dependency structures.
//
// alpm_list_t *alpm_pkg_get_makedepends(Package *pkg);
//
// /// Returns the list of packages conflicting with pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of Dependency structures.
//
// alpm_list_t *alpm_pkg_get_conflicts(Package *pkg);
//
// /// Returns the list of packages provided by pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of Dependency structures.
//
// alpm_list_t *alpm_pkg_get_provides(Package *pkg);
//
// /// Returns the list of available deltas for pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of strings.
//
// alpm_list_t *alpm_pkg_get_deltas(Package *pkg);
//
// /// Returns the list of packages to be replaced by pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of Dependency structures.
//
// alpm_list_t *alpm_pkg_get_replaces(Package *pkg);
//
// /// Returns the list of files installed by pkg.
//  * The filenames are relative to the install root,
//  * and do not include leading slashes.
//  * @param pkg a pointer to package
//  * @return a pointer to a filelist object containing a count and an array of
//  * package file objects
//
// alpm_filelist_t *alpm_pkg_get_files(Package *pkg);
//
// /// Returns the list of files backed up when installing pkg.
//  * @param pkg a pointer to package
//  * @return a reference to a list of alpm_backup_t objects
//
// alpm_list_t *alpm_pkg_get_backup(Package *pkg);
//
// /// Returns the database containing pkg.
//  * Returns a pointer to the Database structure the package is
//  * originating from, or NULL if the package was loaded from a file.
//  * @param pkg a pointer to package
//  * @return a pointer to the DB containing pkg, or NULL.
//
// Database *alpm_pkg_get_db(Package *pkg);
//
// /// Returns the base64 encoded package signature.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *alpm_pkg_get_base64_sig(Package *pkg);
//
// /// Returns the method used to validate a package during install.
//  * @param pkg a pointer to package
//  * @return an enum member giving the validation method
//
// int alpm_pkg_get_validation(Package *pkg);
//
// /* End of Package accessors
// /* @}
//
// /// Open a package changelog for reading.
//  * Similar to fopen in functionality, except that the returned 'file
//  * stream' could really be from an archive as well as from the database.
//  * @param pkg the package to read the changelog of (either file or db)
//  * @return a 'file stream' to the package changelog
//
// void *alpm_pkg_changelog_open(Package *pkg);
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
// 		const Package *pkg, void *fp);
//
// int alpm_pkg_changelog_close(const Package *pkg, void *fp);
//
// /// Open a package mtree file for reading.
//  * @param pkg the local package to read the changelog of
//  * @return a archive structure for the package mtree file
//
// struct archive *alpm_pkg_mtree_open(Package *pkg);
//
// /// Read next entry from a package mtree file.
//  * @param pkg the package that the mtree file is being read from
//  * @param archive the archive structure reading from the mtree file
//  * @param entry an archive_entry to store the entry header information
//  * @return 0 if end of archive is reached, non-zero otherwise.
//
// int alpm_pkg_mtree_next(const Package *pkg, struct archive *archive,
// 		struct archive_entry **entry);
//
// int alpm_pkg_mtree_close(const Package *pkg, struct archive *archive);
//
// /// Returns whether the package has an install scriptlet.
//  * @return 0 if FALSE, TRUE otherwise
//
// int alpm_pkg_has_scriptlet(Package *pkg);
//
// /// Returns the size of download.
//  * Returns the size of the files that will be downloaded to install a
//  * package.
//  * @param newpkg the new package to upgrade to
//  * @return the size of the download
//
// off_t alpm_pkg_download_size(Package *newpkg);
//
// alpm_list_t *alpm_pkg_unused_deltas(Package *pkg);
//
// /// Set install reason for a package in the local database.
//  * The provided package object must be from the local database or this method
//  * will fail. The write to the local database is performed immediately.
//  * @param pkg the package to update
//  * @param reason the new install reason
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_pkg_set_reason(Package *pkg, PackageReason reason);
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
// int alpm_pkg_check_pgp_signature(Package *pkg, alpm_siglist_t *siglist);
//
// int alpm_db_check_pgp_signature(Database *db, alpm_siglist_t *siglist);
//
// int alpm_siglist_cleanup(alpm_siglist_t *siglist);
//
// int alpm_decode_signature(const char *base64_data,
// 		unsigned char **data, size_t *data_len);
//
// int alpm_extract_keyid(Handle *handle, const char *identifier,
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
// Package *alpm_sync_newversion(Package *pkg, alpm_list_t *dbs_sync);
//
// /// @addtogroup alpm_api_trans Transaction Functions
//  * Functions to manipulate libalpm transactions
//  * @{
//
//

/// Transaction flags
#[derive(Default, Debug, Clone)]
pub struct TransactionFlag {
    /// Ignore dependency checks.
    pub no_deps: bool,
    /// Ignore file conflicts and overwrite files.
    pub force: bool,
    /// Delete files even if they are tagged as backup.
    pub no_save: bool,
    /// Ignore version numbers when checking dependencies.
    pub no_depversion: bool,
    /// Remove also any packages depending on a package being removed.
    pub cascade: bool,
    /// Remove packages and their unneeded deps (not explicitly installed).
    pub recurse: bool,
    /// Modify database but do not commit changes to the filesystem.
    pub db_only: bool,
    /* (1 << 7) flag can go here */
    /// Use Depend when installing packages.
    pub all_deps: bool,
    /// Only download packages and do not actually install.
    pub download_only: bool,
    /// Do not execute install scriptlets after installing.
    pub no_scriptlet: bool,
    /// Ignore dependency conflicts.
    pub no_conflicts: bool,
    /* (1 << 12) flag can go here */
    /// Do not install a package if it is already installed and up to date.
    pub needed: bool,
    /// Use Explicit when installing packages.
    pub all_explicit: bool,
    /// Do not remove a package if it is needed by another one.
    pub unneeded: bool,
    /// Remove also explicitly installed unneeded deps (use with pub RECURSE).
    pub recurse_all: bool,
    /// Do not lock the database during the operation.
    pub no_lock: bool,
}
//
// /// Returns the bitfield of flags for the current transaction.
//  * @param handle the context handle
//  * @return the bitfield of transaction flags
//
// int alpm_trans_get_flags(Handle *handle);
//
// /// Returns a list of packages added by the transaction.
//  * @param handle the context handle
//  * @return a list of Package structures
//
// alpm_list_t *alpm_trans_get_add(Handle *handle);
//
// /// Returns the list of packages removed by the transaction.
//  * @param handle the context handle
//  * @return a list of Package structures
//
// alpm_list_t *alpm_trans_get_remove(Handle *handle);
//
// /// Initialize the transaction.
//  * @param handle the context handle
//  * @param flags flags of the transaction (like nodeps, etc; see alpm_transflag_t)
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_trans_init(Handle *handle, int flags);
//
// /// Prepare a transaction.
//  * @param handle the context handle
//  * @param data the address of an alpm_list where a list
//  * of depmissing_t objects is dumped (conflicting packages)
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_trans_prepare(Handle *handle, alpm_list_t **data);
//
// /// Commit a transaction.
//  * @param handle the context handle
//  * @param data the address of an alpm_list where detailed description
//  * of an error can be dumped (i.e. list of conflicting files)
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_trans_commit(Handle *handle, alpm_list_t **data);
//
// /// Interrupt a transaction.
//  * @param handle the context handle
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_trans_interrupt(Handle *handle);
//
// /// Release a transaction.
//  * @param handle the context handle
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_trans_release(Handle *handle);
// /// @}
//
// /// @name Common Transactions
// /// @{
//
//
// /// Add a package to the transaction.
//  * If the package was loaded by alpm_pkg_load(), it will be freed upon
//  * alpm_trans_release() invocation.
//  * @param handle the context handle
//  * @param pkg the package to add
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_add_pkg(Handle *handle, Package *pkg);
//
// /// Add a package removal action to the transaction.
//  * @param handle the context handle
//  * @param pkg the package to uninstall
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int alpm_remove_pkg(Handle *handle, Package *pkg);
//
// /// @}
//
// /// @addtogroup alpm_api_depends Dependency Functions
//  * Functions dealing with libalpm representation of dependency
//  * information.
//  * @{
//
//
// alpm_list_t *alpm_checkdeps(Handle *handle, alpm_list_t *pkglist,
// 		alpm_list_t *remove, alpm_list_t *upgrade, int reversedeps);
// Package *alpm_find_satisfier(alpm_list_t *pkgs, const char *depstring);
// Package *alpm_find_dbs_satisfier(Handle *handle,
// 		alpm_list_t *dbs, const char *depstring);
//
// alpm_list_t *alpm_checkconflicts(Handle *handle, alpm_list_t *pkglist);
//
// /// Returns a newly allocated string representing the dependency information.
//  * @param dep a dependency info structure
//  * @return a formatted string, e.g. "glibc>=2.12"
//
// char *alpm_dep_compute_string(const Dependency *dep);
//

// Dependency *alpm_dep_from_string(const char *depstring);

// /* checksums
// char *alpm_compute_md5sum(const char *filename);
// char *alpm_compute_sha256sum(const char *filename);
//
// Handle *initialize(const char *root, const char *dbpath,
// 		errno_t *err);
// int alpm_release(Handle *handle);
// int alpm_unlock(Handle *handle);
#[derive(Default)]
// pub struct alpm_caps {
pub struct Capabilities {
    pub nls: bool,
    pub downloader: bool,
    pub signatures: bool,
}

// const char *alpm_version(void);
// void alpm_fileconflict_free(fileconflict_t *conflict);
// void alpm_depmissing_free(depmissing_t *miss);
// void alpm_conflict_free(alpm_conflict_t *conflict);

/*
 *  alpm.c
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

// #ifdef HAVE_LIBCURL
// #include <curl/curl.h>
// #endif

/// Initializes the library.
/// Creates handle, connects to database and creates lockfile.
/// This must be called before any other functions are called.
/// * `root` the root path for all filesystem operations
/// * `dbpath` the absolute path to the libalpm database
/// * returns a context handle on success, or error
pub fn initialize(root: &String, dbpath: &String) -> Result<Handle> {
    // let myerr = errno_t::default();
    let lf = "db.lck";
    let hookdir;
    let mut myhandle = Handle::handle_new();

    *myhandle.get_root_mut() = _alpm_set_directory_option(root, true)?;
    *myhandle.get_dbpath_mut() = _alpm_set_directory_option(dbpath, true)?;

    /* to concatenate myhandle->root (ends with a slash) with SYSHOOKDIR (starts
     * with a slash) correctly, we skip SYSHOOKDIR[0]; the regular +1 therefore
     * disappears from the allocation */
    hookdir = format!("{}{}", myhandle.get_root(), SYSHOOKDIR);
    *myhandle.get_hookdirs_mut() = Vec::new();
    myhandle.get_hookdirs_mut().push(hookdir);

    /* set default database extension */
    myhandle.set_dbext(&String::from(".db"));

    *myhandle.get_lockfile_mut() = format!("{}{}", myhandle.get_dbpath(), lf);

    myhandle.db_register_local()?;

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
pub fn alpm_release(myhandle: Handle) -> i32 {
    unimplemented!();
    // 	int ret = 0;
    // 	Database *db;
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
