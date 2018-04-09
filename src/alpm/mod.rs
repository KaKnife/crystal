mod version;
mod conflict;
mod remove;
mod be_package;
mod dload;
mod sync;
mod be_sync;

use self::dload::DownloadPayload;
pub use self::version::pkg_vercmp;
pub use self::be_sync::db_update;

use {Database, Dependency, Error, Handle, Package};
// use std::result::Result as StdResult;

// libarchive
// #include <archive.h>
// #include <archive_entry.h>

/* Arch Linux Package Management library */

pub type Time = i64;

/// File conflict type.
/// Whether the conflict results from a file existing on the filesystem, or with
/// another target in the transaction.
#[derive(Debug)]
enum FileConflictType {
    Target = 1,
    Filesystem,
}

/// File conflict
struct FileConflict {
    target: String,
    ttype: FileConflictType,
    file: String,
    ctarget: String,
}

/// Package group.
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
    // mode mode: Mode
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
pub struct PgpKey {
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

enum HookWhen {
    PreTransaction = 1,
    PostTransaction,
}

/// Type of events.
pub enum EventType {
}

pub struct EventAny {
    /// Type of event.
    etype: EventType,
}

pub enum PackageOperation {
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

pub struct EventPackageOperation<'a> {
    /// Type of event.
    etype: EventType,
    /// Type of operation.
    operation: PackageOperation,
    /// Old package.
    oldpkg: &'a Package,
    /// New package.
    newpkg: &'a Package,
}

pub struct EventOptdepRemoval<'a> {
    /// Type of event.
    etype: EventType,
    /// Package with the optdep.
    pkg: &'a Package,
    /// Optdep being removed.
    optdep: &'a Dependency,
}

pub struct EventDeltaPatch {
    /// Type of event.
    etype: EventType, // 	/// Delta info
                      // 	delta *delta;
}

pub struct EventScriptletInfo {
    /// Type of event.
    eventype: EventType,
    /// Line of scriptlet output.
    line: String,
}

/// A configured repository database is missing; See
/// event_database_missing for arguments.
pub struct EventDatabaseMissing {
    /// Name of the database.
    pub dbname: String,
}

//  struct Eventpkgdownload {
// 	/// Type of event.
// 	eventype type;
// 	/// Name of the file
// 	const char *file;
// }

//  struct Eventpacnew_created {
// 	/// Type of event.
// 	eventype type;
// 	/// Whether the creation was result of a NoUpgrade or not
// 	int from_noupgrade;
// 	/// Old package.
// 	Package *oldpkg;
// 	/// New Package.
// 	Package *newpkg;
// 	/// Filename of the file without the .pacnew suffix
// 	const char *file;
// }

//  struct Eventpacsave_created {
// 	/// Type of event.
// 	EventType type;
// 	/// Old package.
// 	Package *oldpkg;
// 	/// Filename of the file without the .pacsave suffix.
// 	const char *file;
// }

//  struct Eventhook {
// 	/// Type of event.
// 	eventype type;
// 	/// Type of hooks.
// 	hook_when when;
// }

pub struct EventHookRun {
// 	/// Type of event.
// 	eventype type;
// 	/// Name of hook
// 	const char *name;
// 	/// Description of hook to be outputted
// 	const char *desc;
// 	/// position of hook being run
// 	size position;
// 	/// total hooks being run
// 	size total;
}

/// Events.
/// This is an union passed to the callback, that allows the frontend to know
/// which type of event was triggered (via type). It is then possible to
/// typecast the pointer to the right structure, or use the union field, in order
/// to access event-specific data.
pub enum Event<'a> {
    // 	eventype type;
    Any(EventAny),
    /// Dependencies will be resolved for target package.
    ResolveDepsStart,
    PackageOperation(EventPackageOperation<'a>),
    OptdepRemoval(EventOptdepRemoval<'a>),
    DeltaPatch(EventDeltaPatch),
    ScriptletInfo(EventScriptletInfo),
    DatabaseMissing(EventDatabaseMissing),
    // 	event_pkgdownload pkgdownload;
    // 	event_pacnew_created pacnew_created;
    // 	event_pacsave_created pacsave_created;
    // 	event_hook hook;
    // 	event_hook_run hook_run;
    /// Dependencies will be computed for a package.
    CheckdepsStart,
    /// Dependencies were computed for a package.
    CheckdepsDone,
    /// File conflicts will be computed for a package.
    FileConflictsStart,
    /// File conflicts were computed for a package.
    FileConflictsDone,
    /// Dependencies were resolved for target package.
    ResolveDepsDone,
    /// Inter-conflicts will be checked for target package.
    InterConflictsStart,
    /// Inter-conflicts were checked for target package.
    InterConflictsDone,
    /// Processing the package transaction is starting.
    TransactionStart,
    /// Processing the package transaction is finished.
    TransactionDone,
    /// Package will be installed/upgraded/downgraded/re-installed/removed; See
    /// event_package_operation for arguments.
    PackageOperationStart,
    /// Package was installed/upgraded/downgraded/re-installed/removed; See
    /// event_package_operation for arguments.
    PackageOperationDone,
    // /// Target package's integrity will be checked.
    // IntegrityStart,
    // /// Target package's integrity was checked.
    // INTEGRITY_Done,
    // /// Target package will be loaded.
    // LoadStart,
    // /// Target package is finished loading.
    // LoadDone,
    // /// Target delta's integrity will be checked.
    // DELTA_INTEGRITY_Start,
    // /// Target delta's integrity was checked.
    // DELTA_INTEGRITY_Done,
    // /// Deltas will be applied to packages.
    // DELTA_PATCHES_Start,
    // /// Deltas were applied to packages.
    // DELTA_PATCHES_Done,
    // /// Delta patch will be applied to target package; See
    // /// event_delta_patch for arguments..
    // DELTA_PATCH_Start,
    // /// Delta patch was applied to target package.
    // DELTA_PATCH_Done,
    // /// Delta patch failed to apply to target package.
    // DELTA_PATCH_FAILED,
    // /// Scriptlet has printed information; See event_scriptlet_info for
    // /// arguments.
    // SCRIPTLET_INFO,
    // /// Files will be downloaded from a repository.
    // RETRIEVE_Start,
    // /// Files were downloaded from a repository.
    // RETRIEVE_Done,
    // /// Not all files were successfully downloaded from a repository.
    // RETRIEVE_FAILED,
    // /// A file will be downloaded from a repository; See event_pkgdownload
    // /// for arguments
    // PKGDOWNLOAD_Start,
    // /// A file was downloaded from a repository; See event_pkgdownload
    // /// for arguments
    // PKGDOWNLOAD_Done,
    // /// A file failed to be downloaded from a repository; See
    // /// event_pkgdownload for arguments
    // PKGDOWNLOAD_FAILED,
    // /// Disk space usage will be computed for a package.
    // DISKSPACE_Start,
    // /// Disk space usage was computed for a package.
    // DISKSPACE_Done,
    // /// An optdepend for another package is being removed; See
    // /// event_optdep_removal for arguments.
    // OPTDEP_REMOVAL,
    // /// Checking keys used to create signatures are in keyring.
    // KEYRING_Start,
    // /// Keyring checking is finished.
    // KEYRING_Done,
    // /// Downloading missing keys into keyring.
    // KEY_DOWNLOAD_Start,
    // /// Key downloading is finished.
    // KEY_DOWNLOAD_Done,
    // /// A .pacnew file was created; See event_pacnew_created for arguments.
    // PACNEW_CREATED,
    // /// A .pacsave file was created; See event_pacsave_created for
    // /// arguments
    // PACSAVE_CREATED,
    // /// Processing hooks will be started.
    // HOOK_Start,
    // /// Processing hooks is finished.
    // HOOK_Done,
    // /// A hook is starting
    // HOOK_RUN_Start,
    // /// A hook has finished running
    // HOOK_RUN_Done,
}

/// Event callback.
pub type CbEvent = Option<fn(&mut Event)>;

// /// Progress
// typedef enum _progress {
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
// } progress;

// /// Progress callback
// typedef void (*cb_progress) = fn(progress, const char *, int, size, size);

//Downloading

/// Type of download progress callbacks.
/// filename is the name of the file being downloaded.
/// xfered is the number of transferred bytes.
/// total is the total number of bytes to transfer.
pub type CbDownload = fn(filename: &String, xfered: usize, total: usize);

// typedef void (*cbotaldl)(off total);

/// A callback for downloading files.
/// url is the URL of the file to be downloaded.
/// localpath is the directory to which the file should be downloaded.
/// force is whether to force an update, even if the file is the same.
/// returns 0 on success, 1 if the file exists and is identical, -1 on error.
// type cb_fetch = fn(&String, &String, i32) -> i32;
pub type CbFetch = Option<fn(url: &String, localpath: &String, force: i32) -> i32>;

// /// Fetch a remote pkg.
//  * @param url URL of the package to download
//  * @return the downloaded filepath on success, NULL on error
// char *fetch_pkgurl(Handle *handle, const char *url);

// /// Sets the callback used for logging.
// int option_set_logcb(Handle *handle, cb_log cb);

// /// Sets the callback used to report download progress.
// int option_set_dlcb(Handle *handle, cb_download cb);

// /// Sets the downloading callback.
// int option_set_fetchcb(Handle *handle, cb_fetch cb);

// /// Sets the callback used to report total download size.
// int option_setotaldlcb(Handle *handle, cbotaldl cb);

// /// Sets the callback used for events.
// int option_set_eventcb(Handle *handle, cb_event cb);

// /// Sets the callback used for questions.
// int option_set_questioncb(Handle *handle, cb_question cb);

// /// Sets the callback used for operation progress.
// int option_set_progresscb(Handle *handle, cb_progress cb);

// /// Sets the logfile name.
// int option_set_logfile(Handle *handle, const char *logfile);

// /// Returns the path to libalpm's GnuPG home directory.
// const char *option_get_gpgdir(Handle *handle);

// /// Sets whether to use syslog (0 is FALSE, TRUE otherwise).
// int option_set_usesyslog(Handle *handle, int usesyslog);

// /// @addtogroup api_databases Database Functions
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
// Database *get_localdb(Handle *handle);
//
// /// Get the list of sync databases.
//  * Returns a list of Database structures, one for each registered
//  * sync database.
//  * @param handle the context handle
//  * @return a reference to an internal list of Database structures
//
// list *get_syncdbs(Handle *handle);
//
// /// Register a sync database of packages.
//  * @param handle the context handle
//  * @param treename the name of the sync repository
//  * @param level what level of signature checking to perform on the
//  * database; note that this must be a '.sig' file type verification
//  * @return an Database* on success (the value), NULL on error
//
// Database *register_syncdb(Handle *handle, const char *treename,
// 		int level);
//
// /// Unregister all package databases.
//  * @param handle the context handle
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int unregister_all_syncdbs(Handle *handle);
//
// /// Unregister a package database.
//  * @param db pointer to the package database to unregister
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int db_unregister(Database *db);
//
// /// Get the name of a package database.
//  * @param db pointer to the package database
//  * @return the name of the package database, NULL on error
//
// const char *db_get_name(const Database *db);
//
// /// Get the signature verification level for a database.
//  * Will return the default verification level if this database is set up
//  * with use_default.
//  * @param db pointer to the package database
//  * @return the signature verification level
//
// int db_get_siglevel(Database *db);
//
// /// Check the validity of a database.
//  * This is most useful for sync databases and verifying signature status.
//  * If invalid, the handle error code will be set accordingly.
//  * @param db pointer to the package database
//  * @return 0 if valid, -1 if invalid (pm_errno is set accordingly)
//
// int db_get_valid(Database *db);
//
// /// @name Accessors to the list of servers for a database.
//  * @{
//
// list *db_get_servers(const Database *db);
// int db_set_servers(Database *db, list *servers);
// int db_add_server(Database *db, const char *url);
// int db_remove_server(Database *db, const char *url);
// /// @}
//
// int db_update(int force, Database *db);
//
// /// Get a package entry from a package database.
//  * @param db pointer to the package database to get the package from
//  * @param name of the package
//  * @return the package entry on success, NULL on error
//
// Package *db_get_pkg(Database *db, const char *name);
//
// /// Get the package cache of a package database.
//  * @param db pointer to the package database to get the package from
//  * @return the list of packages on success, NULL on error
//
// list *db_get_pkgcache(Database *db);
//
// /// Get a group entry from a package database.
//  * @param db pointer to the package database to get the group from
//  * @param name of the group
//  * @return the groups entry on success, NULL on error
//
// group *db_get_group(Database *db, const char *name);
//
// /// Get the group cache of a package database.
//  * @param db pointer to the package database to get the group from
//  * @return the list of groups on success, NULL on error
//
// list *db_get_groupcache(Database *db);
//
// /// Searches a database with regular expressions.
//  * @param db pointer to the package database to search in
//  * @param needles a list of regular expressions to search for
//  * @return the list of packages matching all regular expressions on success, NULL on error
//
// list *db_search(Database *db, const list *needles);

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

// /// Gets the usage of a database.
// /// usage is  pointer to an DatabaseUsage to store db's status
// int db_get_usage(Database *db, int *usage);

// /// Create a package from a file.
//  * If full is false, the archive is read only until all necessary
//  * metadata is found. If it is true, the entire archive is read, which
//  * serves as a verification of integrity and the filelist can be created.
//  * The allocated structure should be freed using pkg_free().
//  * @param handle the context handle
//  * @param filename location of the package tarball
//  * @param full whether to stop the load after metadata is read or continue
//  * through the full archive
//  * @param level what level of package signature checking to perform on the
//  * package; note that this must be a '.sig' file type verification
//  * @param pkg address of the package pointer
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
// int pkg_load(Handle *handle, const char *filename, int full,
// 		int level, Package **pkg);

// /* Find a package in a list by name.
//  * @param haystack a list of Package
//  * @param needle the package name
//  * @return a pointer to the package if found or NULL
// Package *pkg_find(list *haystack, const char *needle);

// /* Free a package.
//  * @param pkg package pointer to free
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
// int pkg_free(Package *pkg);

// /// Computes the list of packages requiring a given package.
//  * The return value of this function is a newly allocated
//  * list of package names (char*), it should be freed by the caller.
//  * @param pkg a package
//  * @return the list of packages requiring pkg
// list *pkg_compute_requiredby(Package *pkg);

// /// Computes the list of packages optionally requiring a given package.
//  * The return value of this function is a newly allocated
//  * list of package names (char*), it should be freed by the caller.
//  * @param pkg a package
//  * @return the list of packages optionally requiring pkg
//
// list *pkg_compute_optionalfor(Package *pkg);

// /// Test if a package should be ignored.
//  * Checks if the package is ignored via IgnorePkg, or if the package is
//  * in a group ignored via IgnoreGroup.
//  * @param handle the context handle
//  * @param pkg the package to test
//  * @return 1 if the package should be ignored, 0 otherwise
//
// int pkg_should_ignore(Handle *handle, Package *pkg);

// /// Gets the name of the file from which the package was loaded.
// const char *pkg_get_filename(Package *pkg);

// /// Returns the package base name.
// const char *pkg_get_base(Package *pkg);

// /// Returns the origin of the package.
// PackageFrom pkg_get_origin(Package *pkg);

// /// Returns the package description.
// const char *pkg_get_desc(Package *pkg);

// /// Returns the architecture for which the package was built.
// const char *pkg_get_arch(Package *pkg);

// /// Returns the size of the package. This is only available for sync database
//  * packages and package files, not those loaded from the local database.
// off pkg_get_size(Package *pkg);

// /// Returns the installed size of the package.
// off pkg_get_isize(Package *pkg);

// /// Returns the package installation reason.
// PackageReason pkg_get_reason(Package *pkg);

// /// Returns the list of package licenses.
// list *pkg_get_licenses(Package *pkg);

// /// Returns the list of package groups.
// list *pkg_get_groups(Package *pkg);

// /// Returns the list of package dependencies as Dependency.
// list *pkg_get_depends(Package *pkg);

// /// Returns the list of package optional dependencies.
// list *pkg_get_optdepends(Package *pkg);

// /// Returns a list of package check dependencies
// list *pkg_get_checkdepends(Package *pkg);

// /// Returns a list of package make dependencies
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of Dependency structures.
//
// list *pkg_get_makedepends(Package *pkg);
//
// /// Returns the list of packages conflicting with pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of Dependency structures.
//
// list *pkg_get_conflicts(Package *pkg);
//
// /// Returns the list of packages provided by pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of Dependency structures.
//
// list *pkg_get_provides(Package *pkg);
//
// /// Returns the list of available deltas for pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of strings.
//
// list *pkg_get_deltas(Package *pkg);
//
// /// Returns the list of packages to be replaced by pkg.
//  * @param pkg a pointer to package
//  * @return a reference to an internal list of Dependency structures.
//
// list *pkg_get_replaces(Package *pkg);
//
// /// Returns the list of files installed by pkg.
//  * The filenames are relative to the install root,
//  * and do not include leading slashes.
//  * @param pkg a pointer to package
//  * @return a pointer to a filelist object containing a count and an array of
//  * package file objects
//
// filelist *pkg_get_files(Package *pkg);
//
// /// Returns the list of files backed up when installing pkg.
//  * @param pkg a pointer to package
//  * @return a reference to a list of backup objects
//
// list *pkg_get_backup(Package *pkg);
//
// /// Returns the database containing pkg.
//  * Returns a pointer to the Database structure the package is
//  * originating from, or NULL if the package was loaded from a file.
//  * @param pkg a pointer to package
//  * @return a pointer to the DB containing pkg, or NULL.
//
// Database *pkg_get_db(Package *pkg);
//
// /// Returns the base64 encoded package signature.
//  * @param pkg a pointer to package
//  * @return a reference to an internal string
//
// const char *pkg_get_base64_sig(Package *pkg);
//
// /// Returns the method used to validate a package during install.
//  * @param pkg a pointer to package
//  * @return an enum member giving the validation method
//
// int pkg_get_validation(Package *pkg);
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
// void *pkg_changelog_open(Package *pkg);
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
// size pkg_changelog_read(void *ptr, size size,
// 		const Package *pkg, void *fp);
//
// int pkg_changelog_close(const Package *pkg, void *fp);
//
// /// Open a package mtree file for reading.
//  * @param pkg the local package to read the changelog of
//  * @return a archive structure for the package mtree file
//
// struct archive *pkg_mtree_open(Package *pkg);
//
// /// Read next entry from a package mtree file.
//  * @param pkg the package that the mtree file is being read from
//  * @param archive the archive structure reading from the mtree file
//  * @param entry an archive_entry to store the entry header information
//  * @return 0 if end of archive is reached, non-zero otherwise.
//
// int pkg_mtree_next(const Package *pkg, struct archive *archive,
// 		struct archive_entry **entry);
//
// int pkg_mtree_close(const Package *pkg, struct archive *archive);
//
// /// Returns whether the package has an install scriptlet.
//  * @return 0 if FALSE, TRUE otherwise
//
// int pkg_has_scriptlet(Package *pkg);
//
// /// Returns the size of download.
//  * Returns the size of the files that will be downloaded to install a
//  * package.
//  * @param newpkg the new package to upgrade to
//  * @return the size of the download
//
// off pkg_download_size(Package *newpkg);
//
// list *pkg_unused_deltas(Package *pkg);
//
// /// Set install reason for a package in the local database.
//  * The provided package object must be from the local database or this method
//  * will fail. The write to the local database is performed immediately.
//  * @param pkg the package to update
//  * @param reason the new install reason
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int pkg_set_reason(Package *pkg, PackageReason reason);
//
//
// /* End of pkg
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
// file *filelist_contains(filelist *filelist, const char *path);
//
// /*
//  * Signatures
//
//
// int pkg_check_pgp_signature(Package *pkg, siglist *siglist);
//
// int db_check_pgp_signature(Database *db, siglist *siglist);
//
// int siglist_cleanup(siglist *siglist);
//
// int decode_signature(const char *base64_data,
// 		unsigned char **data, size *data_len);
//
// int extract_keyid(Handle *handle, const char *identifier,
// 		const unsigned char *sig, const size len, list **keys);
//
// /*
//  * Groups
//
//
// list *find_group_pkgs(list *dbs, const char *name);
//
// /*
//  * Sync
//
//
// Package *sync_newversion(Package *pkg, list *dbs_sync);
//
// /// @addtogroup apirans Transaction Functions
//  * Functions to manipulate libalpm transactions
//  * @{
//
//

// /// Returns the bitfield of flags for the current transaction.
//  * @param handle the context handle
//  * @return the bitfield of transaction flags
// int trans_get_flags(Handle *handle);
//
// /// Returns a list of packages added by the transaction.
//  * @param handle the context handle
//  * @return a list of Package structures
//
// list *trans_get_add(Handle *handle);
//
// /// Returns the list of packages removed by the transaction.
//  * @param handle the context handle
//  * @return a list of Package structures
//
// list *trans_get_remove(Handle *handle);
//
// /// Initialize the transaction.
//  * @param handle the context handle
//  * @param flags flags of the transaction (like nodeps, etc; see transflag)
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int trans_init(Handle *handle, int flags);
//
// /// Prepare a transaction.
//  * @param handle the context handle
//  * @param data the address of an list where a list
//  * of depmissing objects is dumped (conflicting packages)
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int trans_prepare(Handle *handle, list **data);
//
// /// Commit a transaction.
//  * @param handle the context handle
//  * @param data the address of an list where detailed description
//  * of an error can be dumped (i.e. list of conflicting files)
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int trans_commit(Handle *handle, list **data);
//
// /// Interrupt a transaction.
//  * @param handle the context handle
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int trans_interrupt(Handle *handle);
//
// /// Release a transaction.
//  * @param handle the context handle
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int trans_release(Handle *handle);
// /// @}
//
// /// @name Common Transactions
// /// @{
//
//
// /// Add a package to the transaction.
//  * If the package was loaded by pkg_load(), it will be freed upon
//  * trans_release() invocation.
//  * @param handle the context handle
//  * @param pkg the package to add
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int add_pkg(Handle *handle, Package *pkg);
//
// /// Add a package removal action to the transaction.
//  * @param handle the context handle
//  * @param pkg the package to uninstall
//  * @return 0 on success, -1 on error (pm_errno is set accordingly)
//
// int remove_pkg(Handle *handle, Package *pkg);
//
// /// @}
//
// /// @addtogroup api_depends Dependency Functions
//  * Functions dealing with libalpm representation of dependency
//  * information.
//  * @{
//
//
// list *checkdeps(Handle *handle, list *pkglist,
// 		list *remove, list *upgrade, int reversedeps);
// Package *find_satisfier(list *pkgs, const char *depstring);
// Package *find_dbs_satisfier(Handle *handle,
// 		list *dbs, const char *depstring);
//
// list *checkconflicts(Handle *handle, list *pkglist);
//
// /// Returns a newly allocated string representing the dependency information.
//  * @param dep a dependency info structure
//  * @return a formatted string, e.g. "glibc>=2.12"
//
// char *dep_compute_string(const Dependency *dep);
//

#[derive(Default)]
pub struct Capabilities {
    pub nls: bool,
    pub downloader: bool,
    pub signatures: bool,
}

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

/// Release the library.
/// Disconnects from the database, removes handle and lockfile
/// This should be the last alpm call you make.
/// After this returns, handle should be considered invalid and cannot be reused
/// in any way.
/// returns 0 on success, -1 on error
pub fn release(myhandle: Handle) -> i32 {
    unimplemented!();
    // 	int ret = 0;
    // 	Database *db;
    // 	/* close local database */
    // 	db = myhandle->db_local;
    // 	if(db) {
    // 		db->ops->unregister(db);
    // 		myhandle->db_local = NULL;
    // 	}
    // 	if(unregister_all_syncdbs(myhandle) == -1) {
    // 		ret = -1;
    // 	}
    // 	return ret;
}

/// Get the version of library.
pub fn version() -> String {
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
