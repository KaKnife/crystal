use Package;
use Result;

#[derive(Debug, Clone)]
pub enum TransState {
    Idle = 0,
    Initialized,
    Prepared,
    Downloading,
    Commiting,
    Commited,
    Interrupted,
}
impl Default for TransState {
    fn default() -> Self {
        TransState::Idle
    }
}

#[derive(Default, Debug, Clone)]
/* Transaction */
pub struct Transaction {
    /* bitfield of TransactionFlag flags */
    pub flags: TransactionFlag,
    pub state: TransState,
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
