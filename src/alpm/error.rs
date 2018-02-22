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
    HandleNull,
    HandleNotNull,
    HandleLock,
    /* Databases */
    DatabaseOpen,
    DatabaseCreate,
    DatabaseNull,
    DatabaseNotNull,
    DatabaseNotFound,
    DatabaseNotInvalid,
    DatabaseNotInvalidSig,
    DatabaseVersion,
    DatabaseWrite,
    DatabaseRemove,
    NoDbPath,
    /* Servers */
    ServerBadUrl,
    ServerNone,
    /* Transactions */
    TransactionNotNull,
    TransactionNull,
    TransactionDupTarget,
    TransactionNotInitialized,
    TransactionNotPrepared,
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
    PkgOpen,
    PkgCantRemove,
    PkgInvalidName,
    PkgInvalidArch,
    RepoNotFound,
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
        match self {
		/* System */
		 &Error::Memory=>
			return String::from("out of memory!"),
		 &Error::System=>
			return String::from("unexpected system error"),
		 &Error::BadPerms=>
			return String::from("permission denied"),
		 &Error::NotAFile=>
			return String::from("could not find or read file"),
		 &Error::NotADirectory=>
			return String::from("could not find or read directory"),
		 &Error::WrongArgs=>
			return String::from("wrong or NULL argument passed"),
		 &Error::DiskSpace=>
			return String::from("not enough free disk space"),
		/* Interface */
		 &Error::HandleNull=>
			return String::from("library not initialized"),
		 &Error::HandleNotNull=>
			return String::from("library already initialized"),
		 &Error::HandleLock=>
			return String::from("unable to lock database"),
		/* Databases */
		 &Error::DatabaseOpen=>
			return String::from("could not open database"),
		 &Error::DatabaseCreate=>
			return String::from("could not create database"),
		 &Error::DatabaseNull=>
			return String::from("database not initialized"),
		 &Error::DatabaseNotNull=>
			return String::from("database already registered"),
		 &Error::DatabaseNotFound=>
			return String::from("could not find database"),
		 &Error::DatabaseNotInvalid=>
			return String::from("invalid or corrupted database"),
		 &Error::DatabaseNotInvalidSig=>
			return String::from("invalid or corrupted database (PGP signature)"),
		 &Error::DatabaseVersion=>
			return String::from("database is incorrect version"),
		 &Error::DatabaseWrite=>
			return String::from("could not update database"),
		 &Error::DatabaseRemove=>
			return String::from("could not remove database entry"),
		/* Servers */
		 &Error::ServerBadUrl=>
			return String::from("invalid url for server"),
		 &Error::ServerNone=>
			return String::from("no servers configured for repository"),
		/* Transactions */
		 &Error::TransactionNotNull=>
			return String::from("transaction already initialized"),
		 &Error::TransactionNull=>
			return String::from("transaction not initialized"),
		 &Error::TransactionDupTarget=>
			return String::from("duplicate target"),
		 &Error::TransactionNotInitialized=>
			return String::from("transaction not initialized"),
		 &Error::TransactionNotPrepared=>
			return String::from("transaction not prepared"),
		 &Error::ALPM_ERR_TRANS_ABORT=>
			return String::from("transaction aborted"),
		 &Error::ALPM_ERR_TRANS_TYPE=>
			return String::from("operation not compatible with the transaction type"),
		 &Error::ALPM_ERR_TRANS_NOT_LOCKED=>
			return String::from("transaction commit attempt when database is not locked"),
		 &Error::ALPM_ERR_TRANS_HOOK_FAILED=>
			return String::from("failed to run transaction hooks"),
		/* Packages */
		 &Error::ALPM_ERR_PKG_NOT_FOUND=>
			return String::from("could not find or read package"),
		 &Error::ALPM_ERR_PKG_IGNORED=>
			return String::from("operation cancelled due to ignorepkg"),
		 &Error::ALPM_ERR_PKG_INVALID=>
			return String::from("invalid or corrupted package"),
		 &Error::ALPM_ERR_PKG_INVALID_CHECKSUM=>
			return String::from("invalid or corrupted package (checksum)"),
		 &Error::ALPM_ERR_PKG_INVALID_SIG=>
			return String::from("invalid or corrupted package (PGP signature)"),
		 &Error::ALPM_ERR_PKG_MISSING_SIG=>
			return String::from("package missing required signature"),
		 &Error::PkgOpen=>
			return String::from("cannot open package file"),
		 &Error::PkgCantRemove=>
			return String::from("cannot remove all files for package"),
		 &Error::PkgInvalidName=>
			return String::from("package filename is not valid"),
		 &Error::PkgInvalidArch=>
			return String::from("package architecture is not valid"),
		 &Error::RepoNotFound=>
			return String::from("could not find repository for target"),
		/* Signatures */
		 &Error::SigMissing=>
			return String::from("missing PGP signature"),
		 &Error::SigInvalid=>
			return String::from("invalid PGP signature"),
		/* Deltas */
		 &Error::DltInvalid=>
			return String::from("invalid or corrupted delta"),
		 &Error::DltPatchFailed=>
			return String::from("delta patch failed"),
		/* Dependencies */
		 &Error::UnsatisfiedDeps=>
			return String::from("could not satisfy dependencies"),
		 &Error::ConflictingDeps=>
			return String::from("conflicting dependencies"),
		 &Error::FileConflicts=>
			return String::from("conflicting files"),
		/* Miscellaenous */
		 &Error::Retrive=>
			return String::from("failed to retrieve some files"),
		 &Error::InvalidRegex=>String::from("invalid regular expression"),
		/* Errors from external libraries- our own wrapper error */
		 &Error::LibArchive=>
			/* it would be nice to use archive_error_string() here, but that
			 * requires the archive struct, so we can't. Just use a generic
			 * error string instead. */
			return String::from("libarchive error"),
		 &Error::LibCurl=> String::from("download library error"),
		 &Error::GpgMe=> String::from("gpgme error"),
		 &Error::Download=> String::from("error invoking external downloader"),
         &Error::NoDbPath => String::from("no database path"),
         &Error::GroupNotFound=>
			return String::from("could not find or read group"),
		/* Unknown error! */
		// _=> String::from("unexpected error"),
	}
    }
}
