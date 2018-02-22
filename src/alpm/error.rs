/*
 *  error.c
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *
 *  This program is free software, you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY, without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http=>//www.gnu.org/licenses/>.
 */

// impl Default for Error {
//     fn default() -> Self {
//         Error::ALPM_ERR_OK
//     }
// }
use std::fmt;
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.alpm_strerror())
    }
}

/// Error Codes
#[derive(Debug, Copy, Clone)]
pub enum Error {
    // Ok = 0,
    Memory,
    System,
    BadPerms,
    NotAFile,
    NotADirectory,
    WrongArgs,
    DiskSpace,
    /* Interface */
    ALPM_ERR_HANDLE_NULL,
    ALPM_ERR_HANDLE_NOT_NULL,
    ALPM_ERR_HANDLE_LOCK,
    /* Databases */
    ALPM_ERR_DB_OPEN,
    ALPM_ERR_DB_CREATE,
    ALPM_ERR_DB_NULL,
    ALPM_ERR_DB_NOT_NULL,
    ALPM_ERR_DB_NOT_FOUND,
    ALPM_ERR_DB_INVALID,
    ALPM_ERR_DB_INVALID_SIG,
    ALPM_ERR_DB_VERSION,
    ALPM_ERR_DB_WRITE,
    ALPM_ERR_DB_REMOVE,
    no_db_path,
    /* Servers */
    ALPM_ERR_SERVER_BAD_URL,
    ALPM_ERR_SERVER_NONE,
    /* Transactions */
    ALPM_ERR_TRANS_NOT_NULL,
    ALPM_ERR_TRANS_NULL,
    ALPM_ERR_TRANS_DUP_TARGET,
    ALPM_ERR_TRANS_NOT_INITIALIZED,
    ALPM_ERR_TRANS_NOT_PREPARED,
    ALPM_ERR_TRANS_ABORT,
    ALPM_ERR_TRANS_TYPE,
    ALPM_ERR_TRANS_NOT_LOCKED,
    ALPM_ERR_TRANS_HOOK_FAILED,
    /* Packages */
    ALPM_ERR_PKG_NOT_FOUND,
    ALPM_ERR_PKG_IGNORED,
    ALPM_ERR_PKG_INVALID,
    ALPM_ERR_PKG_INVALID_CHECKSUM,
    ALPM_ERR_PKG_INVALID_SIG,
    ALPM_ERR_PKG_MISSING_SIG,
    ALPM_ERR_PKG_OPEN,
    ALPM_ERR_PKG_CANT_REMOVE,
    ALPM_ERR_PKG_INVALID_NAME,
    ALPM_ERR_PKG_INVALID_ARCH,
    ALPM_ERR_PKG_REPO_NOT_FOUND,
    /* Signatures */
    SigMissing,
    SigInvalid,
    /* Deltas */
    DltInvalid,
    DltPatchFailed,
    /* Dependencies */
    UnsatisfiedDeps,
    ConflictingDeps,
    FileConflicts,
    /* Misc */
    Retrive,
    InvalidRegex,
    /* External library errors */
    LibArchive,
    LibCurl,
    Download,
    GpgMe,
    GroupNotFound,
}

impl Error {
    pub fn alpm_strerror(&self) -> String {
        use self::Error::*;
        match self {
		/* System */
		 &Memory=>
			return String::from("out of memory!"),
		 &System=>
			return String::from("unexpected system error"),
		 &BadPerms=>
			return String::from("permission denied"),
		 &NotAFile=>
			return String::from("could not find or read file"),
		 &NotADirectory=>
			return String::from("could not find or read directory"),
		 &WrongArgs=>
			return String::from("wrong or NULL argument passed"),
		 &DiskSpace=>
			return String::from("not enough free disk space"),
		/* Interface */
		 &ALPM_ERR_HANDLE_NULL=>
			return String::from("library not initialized"),
		 &ALPM_ERR_HANDLE_NOT_NULL=>
			return String::from("library already initialized"),
		 &ALPM_ERR_HANDLE_LOCK=>
			return String::from("unable to lock database"),
		/* Databases */
		 &ALPM_ERR_DB_OPEN=>
			return String::from("could not open database"),
		 &ALPM_ERR_DB_CREATE=>
			return String::from("could not create database"),
		 &ALPM_ERR_DB_NULL=>
			return String::from("database not initialized"),
		 &ALPM_ERR_DB_NOT_NULL=>
			return String::from("database already registered"),
		 &ALPM_ERR_DB_NOT_FOUND=>
			return String::from("could not find database"),
		 &ALPM_ERR_DB_INVALID=>
			return String::from("invalid or corrupted database"),
		 &ALPM_ERR_DB_INVALID_SIG=>
			return String::from("invalid or corrupted database (PGP signature)"),
		 &ALPM_ERR_DB_VERSION=>
			return String::from("database is incorrect version"),
		 &ALPM_ERR_DB_WRITE=>
			return String::from("could not update database"),
		 &ALPM_ERR_DB_REMOVE=>
			return String::from("could not remove database entry"),
		/* Servers */
		 &ALPM_ERR_SERVER_BAD_URL=>
			return String::from("invalid url for server"),
		 &ALPM_ERR_SERVER_NONE=>
			return String::from("no servers configured for repository"),
		/* Transactions */
		 &ALPM_ERR_TRANS_NOT_NULL=>
			return String::from("transaction already initialized"),
		 &ALPM_ERR_TRANS_NULL=>
			return String::from("transaction not initialized"),
		 &ALPM_ERR_TRANS_DUP_TARGET=>
			return String::from("duplicate target"),
		 &ALPM_ERR_TRANS_NOT_INITIALIZED=>
			return String::from("transaction not initialized"),
		 &ALPM_ERR_TRANS_NOT_PREPARED=>
			return String::from("transaction not prepared"),
		 &ALPM_ERR_TRANS_ABORT=>
			return String::from("transaction aborted"),
		 &ALPM_ERR_TRANS_TYPE=>
			return String::from("operation not compatible with the transaction type"),
		 &ALPM_ERR_TRANS_NOT_LOCKED=>
			return String::from("transaction commit attempt when database is not locked"),
		 &ALPM_ERR_TRANS_HOOK_FAILED=>
			return String::from("failed to run transaction hooks"),
		/* Packages */
		 &ALPM_ERR_PKG_NOT_FOUND=>
			return String::from("could not find or read package"),
		 &ALPM_ERR_PKG_IGNORED=>
			return String::from("operation cancelled due to ignorepkg"),
		 &ALPM_ERR_PKG_INVALID=>
			return String::from("invalid or corrupted package"),
		 &ALPM_ERR_PKG_INVALID_CHECKSUM=>
			return String::from("invalid or corrupted package (checksum)"),
		 &ALPM_ERR_PKG_INVALID_SIG=>
			return String::from("invalid or corrupted package (PGP signature)"),
		 &ALPM_ERR_PKG_MISSING_SIG=>
			return String::from("package missing required signature"),
		 &ALPM_ERR_PKG_OPEN=>
			return String::from("cannot open package file"),
		 &ALPM_ERR_PKG_CANT_REMOVE=>
			return String::from("cannot remove all files for package"),
		 &ALPM_ERR_PKG_INVALID_NAME=>
			return String::from("package filename is not valid"),
		 &ALPM_ERR_PKG_INVALID_ARCH=>
			return String::from("package architecture is not valid"),
		 &ALPM_ERR_PKG_REPO_NOT_FOUND=>
			return String::from("could not find repository for target"),
		/* Signatures */
		 &SigMissing=>
			return String::from("missing PGP signature"),
		 &SigInvalid=>
			return String::from("invalid PGP signature"),
		/* Deltas */
		 &DltInvalid=>
			return String::from("invalid or corrupted delta"),
		 &DltPatchFailed=>
			return String::from("delta patch failed"),
		/* Dependencies */
		 &UnsatisfiedDeps=>
			return String::from("could not satisfy dependencies"),
		 &ConflictingDeps=>
			return String::from("conflicting dependencies"),
		 &FileConflicts=>
			return String::from("conflicting files"),
		/* Miscellaenous */
		 &Retrive=>
			return String::from("failed to retrieve some files"),
		 &InvalidRegex=>String::from("invalid regular expression"),
		/* Errors from external libraries- our own wrapper error */
		 &LibArchive=>
			/* it would be nice to use archive_error_string() here, but that
			 * requires the archive struct, so we can't. Just use a generic
			 * error string instead. */
			return String::from("libarchive error"),
		 &LibCurl=> String::from("download library error"),
		 &GpgMe=> String::from("gpgme error"),
		 &Download=> String::from("error invoking external downloader"),
         &Error::no_db_path => String::from("no database path"),
         &Error::GroupNotFound=>
			return String::from("could not find or read group"),
		/* Unknown error! */
		// _=> String::from("unexpected error"),
	}
    }
}
