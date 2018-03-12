/*
 *  trans.h
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
 *  Copyright (c) 2005 by Christian Hamar <krics@linuxforum.hu>
 *  Copyright (c) 2006 by Miklos Vajna <vmiklos@frugalware.org>
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

use alpm::TransactionFlag;
use {Package, Result};

#[derive(Debug, Clone)]
pub enum AlpmTransState {
    Idle = 0,
    Initialized,
    Prepared,
    Downloading,
    Commiting,
    Commited,
    Interrupted,
}
impl Default for AlpmTransState {
    fn default() -> Self {
        AlpmTransState::Idle
    }
}

#[derive(Default, Debug, Clone)]
/* Transaction */
pub struct Transaction {
    /* bitfield of TransactionFlag flags */
    pub flags: TransactionFlag,
    pub state: AlpmTransState,
    pub unresolvable: Vec<Package>,
    pub add: Vec<Package>,
    pub remove: Vec<Package>,
    pub skip_remove: Vec<String>,
}

impl Transaction {
    /// Add a package removal action to the transaction.
    pub fn remove_pkg(&mut self, pkg: &Package) -> Result<()> {
        // if trans.remove.contains(alpm::DepPkg:Pkg(&pkg)) {
        //     return Err(Error::TransactionDupTarget);
        // }
        debug!(
            "adding package {} to the transaction remove list",
            pkg.get_name()
        );
        self.remove.push(pkg.clone());
        return Ok(());
    }
}

// /* A cheap grep for text files, returns 1 if a substring
//  * was found in the text file fn, 0 if it wasn't
//  */
// static int grep(const char *fn, const char *needle)
// {
// 	FILE *fp;
// 	char *ptr;
//
// 	if((fp = fopen(fn, "r")) == NULL) {
// 		return 0;
// 	}
// 	while(!feof(fp)) {
// 		char line[1024];
// 		if(safe_fgets(line, sizeof(line), fp) == NULL) {
// 			continue;
// 		}
// 		if((ptr = strchr(line, '#')) != NULL) {
// 			*ptr = '\0';
// 		}
// 		/* TODO: this will not work if the search string
// 		 * ends up being split across line reads */
// 		if(strstr(line, needle)) {
// 			fclose(fp);
// 			return 1;
// 		}
// 	}
// 	fclose(fp);
// 	return 0;
// }

// int _runscriptlet(handle_t *handle, const char *filepath,
// 		const char *script, const char *ver, const char *oldver, int is_archive)
// {
// 	char arg0[64], arg1[3], cmdline[PATH_MAX];
// 	char *argv[] = { arg0, arg1, cmdline, NULL };
// 	char *tmpdir, *scriptfn = NULL, *scriptpath;
// 	int retval = 0;
// 	size_t len;
//
// 	if(_access(handle, NULL, filepath, R_OK) != 0) {
// 		_log(handle, ALPM_LOG_DEBUG, "scriptlet '%s' not found\n", filepath);
// 		return 0;
// 	}
//
// 	if(!is_archive && !grep(filepath, script)) {
// 		/* script not found in scriptlet file; we can only short-circuit this early
// 		 * if it is an actual scriptlet file and not an archive. */
// 		return 0;
// 	}
//
// 	strcpy(arg0, SCRIPTLET_SHELL);
// 	strcpy(arg1, "-c");
//
// 	/* create a directory in $root/tmp/ for copying/extracting the scriptlet */
// 	len = strlen(handle->root) + strlen("tmp/XXXXXX") + 1;
// 	MALLOC(tmpdir, len, RET_ERR(handle, ALPM_ERR_MEMORY, -1));
// 	snprintf(tmpdir, len, "%stmp/", handle->root);
// 	if(access(tmpdir, F_OK) != 0) {
// 		_makepath_mode(tmpdir, 01777);
// 	}
// 	snprintf(tmpdir, len, "%stmp/XXXXXX", handle->root);
// 	if(mkdtemp(tmpdir) == NULL) {
// 		_log(handle, ALPM_LOG_ERROR, _("could not create temp directory\n"));
// 		free(tmpdir);
// 		return 1;
// 	}
//
// 	/* either extract or copy the scriptlet */
// 	len += strlen("/.INSTALL");
// 	MALLOC(scriptfn, len, free(tmpdir); RET_ERR(handle, ALPM_ERR_MEMORY, -1));
// 	snprintf(scriptfn, len, "%s/.INSTALL", tmpdir);
// 	if(is_archive) {
// 		if(_unpack_single(handle, filepath, tmpdir, ".INSTALL")) {
// 			retval = 1;
// 		}
// 	} else {
// 		if(_copyfile(filepath, scriptfn)) {
// 			_log(handle, ALPM_LOG_ERROR,
//_("could not copy tempfile to %s (%s)\n"), scriptfn, strerror(errno));
// 			retval = 1;
// 		}
// 	}
// 	if(retval == 1) {
// 		goto cleanup;
// 	}
//
// 	if(is_archive && !grep(scriptfn, script)) {
// 		/* script not found in extracted scriptlet file */
// 		goto cleanup;
// 	}
//
// 	/* chop off the root so we can find the tmpdir in the chroot */
// 	scriptpath = scriptfn + strlen(handle->root) - 1;
//
// 	if(oldver) {
// 		snprintf(cmdline, PATH_MAX, ". %s; %s %s %s",
// 				scriptpath, script, ver, oldver);
// 	} else {
// 		snprintf(cmdline, PATH_MAX, ". %s; %s %s",
// 				scriptpath, script, ver);
// 	}
//
// 	_log(handle, ALPM_LOG_DEBUG, "executing \"%s\"\n", cmdline);
//
// 	retval = _run_chroot(handle, SCRIPTLET_SHELL, argv, NULL, NULL);
//
// cleanup:
// 	if(scriptfn && unlink(scriptfn)) {
// 		_log(handle, ALPM_LOG_WARNING,
// 				_("could not remove %s\n"), scriptfn);
// 	}
// 	if(rmdir(tmpdir)) {
// 		_log(handle, ALPM_LOG_WARNING,
// 				_("could not remove tmpdir %s\n"), tmpdir);
// 	}
//
// 	free(scriptfn);
// 	free(tmpdir);
// 	return retval;
// }

// int SYMEXPORT trans_get_flags(handle_t *handle)
// {
// 	/* Sanity checks */
// 	CHECK_HANDLE(handle, return -1);
// 	ASSERT(handle->trans != NULL, RET_ERR(handle, ALPM_ERR_TRANS_NULL, -1));
//
// 	return handle->trans->flags;
// }

// list_t SYMEXPORT *trans_get_add(handle_t *handle)
// {
// 	/* Sanity checks */
// 	CHECK_HANDLE(handle, return NULL);
// 	ASSERT(handle->trans != NULL, RET_ERR(handle, ALPM_ERR_TRANS_NULL, NULL));
//
// 	return handle->trans->add;
// }
//
