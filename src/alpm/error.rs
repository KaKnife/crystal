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
    DatabaseInvalid,
    DatabaseInvalidSig,
    DatabaseVersion,
    DatabaseWrite,
    DatabaseRemove,
    NoDbPath,
    PkgCacheNotLoaded,
    /* Servers */
    ServerBadUrl,
    ServerNone,
    /* Transactions */
    TransactionNotNull,
    TransactionNull,
    TransactionDupTarget,
    TransactionNotInitialized,
    TransactionNotPrepared,
    TransactionAbort,
    TransactionType,
    TransactionNotLocked,
    TransactionHookFailed,
    /* Packages */
    PkgNotLoaded,
    PkgNotFound,
    PkgIgnored,
    PkgInvalid,
    PkgInvalidChecksum,
    PkgInvalidSig,
    PkgMissingSig,
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
		 &Error::DatabaseInvalid=>
			return String::from("invalid or corrupted database"),
		 &Error::DatabaseInvalidSig=>
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
		 &Error::TransactionAbort=>
			return String::from("transaction aborted"),
		 &Error::TransactionType=>
			return String::from("operation not compatible with the transaction type"),
		 &Error::TransactionNotLocked=>
			return String::from("transaction commit attempt when database is not locked"),
		 &Error::TransactionHookFailed=>
			return String::from("failed to run transaction hooks"),
		/* Packages */
		 &Error::PkgNotFound=>
			return String::from("could not find or read package"),
		 &Error::PkgIgnored=>
			return String::from("operation cancelled due to ignorepkg"),
		 &Error::PkgInvalid=>
			return String::from("invalid or corrupted package"),
		 &Error::PkgInvalidChecksum=>
			return String::from("invalid or corrupted package (checksum)"),
		 &Error::PkgInvalidSig=>
			return String::from("invalid or corrupted package (PGP signature)"),
		 &Error::PkgMissingSig=>
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
		_=> String::from("unexpected error"),
	}
    }
}
