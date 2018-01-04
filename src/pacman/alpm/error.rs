use super::*;
// /*
//  *  error.c
//  *
//  *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
//  *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
//  *
//  *  This program is free software, you can redistribute it and/or modify
//  *  it under the terms of the GNU General Public License as published by
//  *  the Free Software Foundation, either version 2 of the License, or
//  *  (at your option) any later version.
//  *
//  *  This program is distributed in the hope that it will be useful,
//  *  but WITHOUT ANY WARRANTY, without even the implied warranty of
//  *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  *  GNU General Public License for more details.
//  *
//  *  You should have received a copy of the GNU General Public License
//  *  along with this program.  If not, see <http=>//www.gnu.org/licenses/>.
//  */
//
// #ifdef HAVE_LIBCURL
// #include <curl/curl.h>
// #endif
//
// /* libalpm */
// #include "util.h"
// #include "alpm.h"
// #include "handle.h"
//
pub fn alpm_errno(handle: &alpm_handle_t) -> alpm_errno_t {
	handle.pm_errno
}

pub fn alpm_strerror(err: alpm_errno_t) -> String {
	use self::alpm_errno_t::*;
	match err {
		/* System */
		 ALPM_ERR_MEMORY=>
			return String::from("out of memory!"),
		 ALPM_ERR_SYSTEM=>
			return String::from("unexpected system error"),
		 ALPM_ERR_BADPERMS=>
			return String::from("permission denied"),
		 ALPM_ERR_NOT_A_FILE=>
			return String::from("could not find or read file"),
		 ALPM_ERR_NOT_A_DIR=>
			return String::from("could not find or read directory"),
		 ALPM_ERR_WRONG_ARGS=>
			return String::from("wrong or NULL argument passed"),
		 ALPM_ERR_DISK_SPACE=>
			return String::from("not enough free disk space"),
		/* Interface */
		 ALPM_ERR_HANDLE_NULL=>
			return String::from("library not initialized"),
		 ALPM_ERR_HANDLE_NOT_NULL=>
			return String::from("library already initialized"),
		 ALPM_ERR_HANDLE_LOCK=>
			return String::from("unable to lock database"),
		/* Databases */
		 ALPM_ERR_DB_OPEN=>
			return String::from("could not open database"),
		 ALPM_ERR_DB_CREATE=>
			return String::from("could not create database"),
		 ALPM_ERR_DB_NULL=>
			return String::from("database not initialized"),
		 ALPM_ERR_DB_NOT_NULL=>
			return String::from("database already registered"),
		 ALPM_ERR_DB_NOT_FOUND=>
			return String::from("could not find database"),
		 ALPM_ERR_DB_INVALID=>
			return String::from("invalid or corrupted database"),
		 ALPM_ERR_DB_INVALID_SIG=>
			return String::from("invalid or corrupted database (PGP signature)"),
		 ALPM_ERR_DB_VERSION=>
			return String::from("database is incorrect version"),
		 ALPM_ERR_DB_WRITE=>
			return String::from("could not update database"),
		 ALPM_ERR_DB_REMOVE=>
			return String::from("could not remove database entry"),
		/* Servers */
		 ALPM_ERR_SERVER_BAD_URL=>
			return String::from("invalid url for server"),
		 ALPM_ERR_SERVER_NONE=>
			return String::from("no servers configured for repository"),
		/* Transactions */
		 ALPM_ERR_TRANS_NOT_NULL=>
			return String::from("transaction already initialized"),
		 ALPM_ERR_TRANS_NULL=>
			return String::from("transaction not initialized"),
		 ALPM_ERR_TRANS_DUP_TARGET=>
			return String::from("duplicate target"),
		 ALPM_ERR_TRANS_NOT_INITIALIZED=>
			return String::from("transaction not initialized"),
		 ALPM_ERR_TRANS_NOT_PREPARED=>
			return String::from("transaction not prepared"),
		 ALPM_ERR_TRANS_ABORT=>
			return String::from("transaction aborted"),
		 ALPM_ERR_TRANS_TYPE=>
			return String::from("operation not compatible with the transaction type"),
		 ALPM_ERR_TRANS_NOT_LOCKED=>
			return String::from("transaction commit attempt when database is not locked"),
		 ALPM_ERR_TRANS_HOOK_FAILED=>
			return String::from("failed to run transaction hooks"),
		/* Packages */
		 ALPM_ERR_PKG_NOT_FOUND=>
			return String::from("could not find or read package"),
		 ALPM_ERR_PKG_IGNORED=>
			return String::from("operation cancelled due to ignorepkg"),
		 ALPM_ERR_PKG_INVALID=>
			return String::from("invalid or corrupted package"),
		 ALPM_ERR_PKG_INVALID_CHECKSUM=>
			return String::from("invalid or corrupted package (checksum)"),
		 ALPM_ERR_PKG_INVALID_SIG=>
			return String::from("invalid or corrupted package (PGP signature)"),
		 ALPM_ERR_PKG_MISSING_SIG=>
			return String::from("package missing required signature"),
		 ALPM_ERR_PKG_OPEN=>
			return String::from("cannot open package file"),
		 ALPM_ERR_PKG_CANT_REMOVE=>
			return String::from("cannot remove all files for package"),
		 ALPM_ERR_PKG_INVALID_NAME=>
			return String::from("package filename is not valid"),
		 ALPM_ERR_PKG_INVALID_ARCH=>
			return String::from("package architecture is not valid"),
		 ALPM_ERR_PKG_REPO_NOT_FOUND=>
			return String::from("could not find repository for target"),
		/* Signatures */
		 ALPM_ERR_SIG_MISSING=>
			return String::from("missing PGP signature"),
		 ALPM_ERR_SIG_INVALID=>
			return String::from("invalid PGP signature"),
		/* Deltas */
		 ALPM_ERR_DLT_INVALID=>
			return String::from("invalid or corrupted delta"),
		 ALPM_ERR_DLT_PATCHFAILED=>
			return String::from("delta patch failed"),
		/* Dependencies */
		 ALPM_ERR_UNSATISFIED_DEPS=>
			return String::from("could not satisfy dependencies"),
		 ALPM_ERR_CONFLICTING_DEPS=>
			return String::from("conflicting dependencies"),
		 ALPM_ERR_FILE_CONFLICTS=>
			return String::from("conflicting files"),
		/* Miscellaenous */
		 ALPM_ERR_RETRIEVE=>
			return String::from("failed to retrieve some files"),
		 ALPM_ERR_INVALID_REGEX=>
			return String::from("invalid regular expression"),
		/* Errors from external libraries- our own wrapper error */
		 ALPM_ERR_LIBARCHIVE=>
			/* it would be nice to use archive_error_string() here, but that
			 * requires the archive struct, so we can't. Just use a generic
			 * error string instead. */
			return String::from("libarchive error"),
		 ALPM_ERR_LIBCURL=>
			return String::from("download library error"),
		 ALPM_ERR_GPGME=>
			return String::from("gpgme error"),
		 ALPM_ERR_EXTERNAL_DOWNLOAD=>
			return String::from("error invoking external downloader"),
		/* Unknown error! */
		_=>
			return String::from("unexpected error"),
	}
}

/* vim=> set noet=> */
