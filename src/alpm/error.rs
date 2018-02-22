use super::*;
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

// impl alpm_handle_t {
//     pub fn alpm_errno(&self) -> Error {
//         self.pm_errno
//     }
// }


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
    ALPM_ERR_BADPERMS,
    ALPM_ERR_NOT_A_FILE,
    ALPM_ERR_NOT_A_DIR,
    ALPM_ERR_WRONG_ARGS,
    ALPM_ERR_DISK_SPACE,
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
    ALPM_ERR_SIG_MISSING,
    ALPM_ERR_SIG_INVALID,
    /* Deltas */
    ALPM_ERR_DLT_INVALID,
    ALPM_ERR_DLT_PATCHFAILED,
    /* Dependencies */
    ALPM_ERR_UNSATISFIED_DEPS,
    ALPM_ERR_CONFLICTING_DEPS,
    ALPM_ERR_FILE_CONFLICTS,
    /* Misc */
    ALPM_ERR_RETRIEVE,
    ALPM_ERR_INVALID_REGEX,
    /* External library errors */
    ALPM_ERR_LIBARCHIVE,
    ALPM_ERR_LIBCURL,
    ALPM_ERR_EXTERNAL_DOWNLOAD,
    ALPM_ERR_GPGME,
}

impl Error {
    pub fn alpm_strerror(&self) -> String {
        use self::Error::*;
        match self {
		/* System */
		 &ALPM_ERR_MEMORY=>
			return String::from("out of memory!"),
		 &ALPM_ERR_SYSTEM=>
			return String::from("unexpected system error"),
		 &ALPM_ERR_BADPERMS=>
			return String::from("permission denied"),
		 &ALPM_ERR_NOT_A_FILE=>
			return String::from("could not find or read file"),
		 &ALPM_ERR_NOT_A_DIR=>
			return String::from("could not find or read directory"),
		 &ALPM_ERR_WRONG_ARGS=>
			return String::from("wrong or NULL argument passed"),
		 &ALPM_ERR_DISK_SPACE=>
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
		 &ALPM_ERR_SIG_MISSING=>
			return String::from("missing PGP signature"),
		 &ALPM_ERR_SIG_INVALID=>
			return String::from("invalid PGP signature"),
		/* Deltas */
		 &ALPM_ERR_DLT_INVALID=>
			return String::from("invalid or corrupted delta"),
		 &ALPM_ERR_DLT_PATCHFAILED=>
			return String::from("delta patch failed"),
		/* Dependencies */
		 &ALPM_ERR_UNSATISFIED_DEPS=>
			return String::from("could not satisfy dependencies"),
		 &ALPM_ERR_CONFLICTING_DEPS=>
			return String::from("conflicting dependencies"),
		 &ALPM_ERR_FILE_CONFLICTS=>
			return String::from("conflicting files"),
		/* Miscellaenous */
		 &ALPM_ERR_RETRIEVE=>
			return String::from("failed to retrieve some files"),
		 &ALPM_ERR_INVALID_REGEX=>String::from("invalid regular expression"),
		/* Errors from external libraries- our own wrapper error */
		 &ALPM_ERR_LIBARCHIVE=>
			/* it would be nice to use archive_error_string() here, but that
			 * requires the archive struct, so we can't. Just use a generic
			 * error string instead. */
			return String::from("libarchive error"),
		 &ALPM_ERR_LIBCURL=> String::from("download library error"),
		 &ALPM_ERR_GPGME=> String::from("gpgme error"),
		 &ALPM_ERR_EXTERNAL_DOWNLOAD=> String::from("error invoking external downloader"),
		/* Unknown error! */
		_=> String::from("unexpected error"),
	}
    }
}
