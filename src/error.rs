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

use std::error::Error as StdError;
use std::io;
use std::ffi;
use curl::Error as CurlError;
use std::time::SystemTimeError;
use std::fmt::{Display, Formatter, Result as FmtResult};


impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.description())
    }
}

/// Error Codes
#[derive(Debug)]
pub enum Error {
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
    IO(io::Error),
    OsStr(ffi::OsString),
    Other,
    CurlError(CurlError),
    SystemTimeError(SystemTimeError),
}

impl From<SystemTimeError> for Error {
    fn from(err: SystemTimeError) -> Self {
        Error::SystemTimeError(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err)
    }
}

impl From<CurlError> for Error {
    fn from(err: CurlError) -> Self {
        Error::CurlError(err)
    }
}

impl From<ffi::OsString> for Error {
    fn from(err: ffi::OsString) -> Self {
        Error::OsStr(err)
    }
}
impl StdError for Error {
    fn description(&self) -> &str {
        match self {
            &Error::Memory => "out of memory!",
            &Error::System => "unexpected system error",
            &Error::BadPerms => "permission denied",
            &Error::NotAFile => "could not find or read file",
            &Error::NotADirectory => "could not find or read directory",
            &Error::WrongArgs => "wrong or NULL argument passed",
            &Error::DiskSpace => "not enough free disk space",
            &Error::HandleNull => "library not initialized",
            &Error::HandleNotNull => "library already initialized",
            &Error::HandleLock => "unable to lock database",
            &Error::DatabaseOpen => "could not open database",
            &Error::DatabaseCreate => "could not create database",
            &Error::DatabaseNull => "database not initialized",
            &Error::DatabaseNotNull => "database already registered",
            &Error::DatabaseNotFound => "could not find database",
            &Error::DatabaseInvalid => "invalid or corrupted database",
            &Error::DatabaseInvalidSig => "invalid or corrupted database (PGP signature)",
            &Error::DatabaseVersion => "database is incorrect version",
            &Error::DatabaseWrite => "could not update database",
            &Error::DatabaseRemove => "could not remove database entry",
            &Error::ServerBadUrl => "invalid url for server",
            &Error::ServerNone => "no servers configured for repository",
            &Error::TransactionNotNull => "transaction already initialized",
            &Error::TransactionNull => "transaction not initialized",
            &Error::TransactionDupTarget => "duplicate target",
            &Error::TransactionNotInitialized => "transaction not initialized",
            &Error::TransactionNotPrepared => "transaction not prepared",
            &Error::TransactionAbort => "transaction aborted",
            &Error::TransactionType => "operation not compatible with the transaction type",
            &Error::TransactionNotLocked => {
                "transaction commit attempt when database is not locked"
            }
            &Error::TransactionHookFailed => "failed to run transaction hooks",
            &Error::PkgNotFound => "could not find or read package",
            &Error::PkgIgnored => "operation cancelled due to ignorepkg",
            &Error::PkgInvalid => "invalid or corrupted package",
            &Error::PkgInvalidChecksum => "invalid or corrupted package (checksum)",
            &Error::PkgInvalidSig => "invalid or corrupted package (PGP signature)",
            &Error::PkgMissingSig => "package missing required signature",
            &Error::PkgOpen => "cannot open package file",
            &Error::PkgCantRemove => "cannot remove all files for package",
            &Error::PkgInvalidName => "package filename is not valid",
            &Error::PkgInvalidArch => "package architecture is not valid",
            &Error::RepoNotFound => "could not find repository for target",
            &Error::SigMissing => "missing PGP signature",
            &Error::SigInvalid => "invalid PGP signature",
            &Error::DltInvalid => "invalid or corrupted delta",
            &Error::DltPatchFailed => "delta patch failed",
            &Error::UnsatisfiedDeps => "could not satisfy dependencies",
            &Error::ConflictingDeps => "conflicting dependencies",
            &Error::FileConflicts => "conflicting files",
            &Error::Retrive => "failed to retrieve some files",
            &Error::InvalidRegex => "invalid regular expression",
            &Error::LibArchive => "libarchive error",
            &Error::LibCurl => "download library error",
            &Error::GpgMe => "gpgme error",
            &Error::Download => "error invoking external downloader",
            &Error::NoDbPath => "no database path",
            &Error::GroupNotFound => "could not find or read group",
            &Error::PkgCacheNotLoaded => "package cache was not loaded",
            &Error::PkgNotLoaded => "package was not loaded",
            &Error::OsStr(_) => "error translating from OsString",
            &Error::IO(ref err) => err.description(),
            &Error::CurlError(ref err) => err.description(),
            &Error::SystemTimeError(ref err) => err.description(),
            &Error::Other => "unknown error",
            // _ => "Unnkown error",
        }
    }
}
