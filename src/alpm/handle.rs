/*
 *  handle.c
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
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
// #[macro_use]
// mod util;
use super::*;
use std;
// use std::error::Error;
use std::fs::File;
// use std::io::Result;
// use std::ffi::OsString;
use std::fs;
use super::deps::find_dep_satisfier;
use super::deps::find_dep_satisfier_ref;
const LDCONFIG: &str = "/sbin/ldconfig";

// alpm_cb_log SYMEXPORT alpm_get_logcb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->logcb;
// }

// alpm_cb_download SYMEXPORT alpm_get_dlcb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->dlcb;
// }

// alpm_cb_fetch SYMEXPORT alpm_get_fetchcb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->fetchcb;
// }

// alpm_cb_totaldl SYMEXPORT alpm_get_totaldlcb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->totaldlcb;
// }

// alpm_cb_event SYMEXPORT alpm_get_eventcb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->eventcb;
// }

// alpm_cb_question SYMEXPORT alpm_get_questioncb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->questioncb;
// }

// alpm_cb_progress SYMEXPORT alpm_get_progresscb(Handle *handle)
// {
// 	CHECK_HANDLE(handle, return NULL);
// 	return handle->progresscb;
// }

// #[derive(Default, Debug)]
///TODO: Implement this
// pub type alpm_list_t<T> = Vec<T>;
pub struct Archive {}
pub struct ArchiveEntry {}

impl Handle {
    /// Run ldconfig in a chroot. Returns 0 on success, 1 on error
    fn ldconfig(&self) -> i32 {
        use std::fs::metadata;
        let mut line: String;

        debug!("running ldconfig");

        if metadata(format!("{}etc/ld.so.conf", self.root)).is_ok() {
            line = format!("{}{}", self.root, LDCONFIG);
            if metadata(line).is_ok() {
                let argv: Vec<String> = vec!["ldconfig".to_string()];
                return self.run_chroot(&LDCONFIG.to_string(), argv /*NULL, NULL*/);
            }
        }

        return 0;
    }

    /// Execute a command with arguments in a chroot.
    /// * @param handle the context handle
    /// * @param cmd command to execute
    /// * @param argv arguments to pass to cmd
    /// * @param stdin_cb callback to provide input to the chroot on stdin
    /// * @param stdin_ctx context to be passed to @a stdin_cb
    /// * @return 0 on success, 1 on error
    fn run_chroot(
        &self,
        cmd: &String,
        argv: Vec<String>,
        /*_alpm_cb_io stdin_cb, void *stdin_ctx*/
    ) -> i32 {
        unimplemented!();
        // 	pid_t pid;
        // 	int child2parent_pipefd[2], parent2child_pipefd[2];
        // 	int cwdfd;
        // 	int retval = 0;
        //
        // #define HEAD 1
        // #define TAIL 0
        //
        // 	/* save the cwd so we can restore it later */
        // 	OPEN(cwdfd, ".", O_RDONLY | O_CLOEXEC);
        // 	if(cwdfd < 0) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not get current working directory\n"));
        // 	}
        //
        // 	/* just in case our cwd was removed in the upgrade operation */
        // 	if(chdir(handle->root) != 0) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not change directory to %s (%s)\n"),
        // 				handle->root, strerror(errno));
        // 		goto cleanup;
        // 	}
        //
        // 	_alpm_log(handle, ALPM_LOG_DEBUG, "executing \"%s\" under chroot \"%s\"\n",
        // 			cmd, handle->root);
        //
        // 	/* Flush open fds before fork() to avoid cloning buffers */
        // 	fflush(NULL);
        //
        // 	if(socketpair(AF_UNIX, SOCK_STREAM, 0, child2parent_pipefd) == -1) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not create pipe (%s)\n"), strerror(errno));
        // 		retval = 1;
        // 		goto cleanup;
        // 	}
        //
        // 	if(socketpair(AF_UNIX, SOCK_STREAM, 0, parent2child_pipefd) == -1) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not create pipe (%s)\n"), strerror(errno));
        // 		retval = 1;
        // 		goto cleanup;
        // 	}
        //
        // 	/* fork- parent and child each have separate code blocks below */
        // 	pid = fork();
        // 	if(pid == -1) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not fork a new process (%s)\n"), strerror(errno));
        // 		retval = 1;
        // 		goto cleanup;
        // 	}
        //
        // 	if(pid == 0) {
        // 		/* this code runs for the child only (the actual chroot/exec) */
        // 		close(0);
        // 		close(1);
        // 		close(2);
        // 		while(dup2(child2parent_pipefd[HEAD], 1) == -1 && errno == EINTR);
        // 		while(dup2(child2parent_pipefd[HEAD], 2) == -1 && errno == EINTR);
        // 		while(dup2(parent2child_pipefd[TAIL], 0) == -1 && errno == EINTR);
        // 		close(parent2child_pipefd[TAIL]);
        // 		close(parent2child_pipefd[HEAD]);
        // 		close(child2parent_pipefd[TAIL]);
        // 		close(child2parent_pipefd[HEAD]);
        // 		if(cwdfd >= 0) {
        // 			close(cwdfd);
        // 		}
        //
        // 		/* use fprintf instead of _alpm_log to send output through the parent */
        // 		if(chroot(handle->root) != 0) {
        // 			fprintf(stderr, _("could not change the root directory (%s)\n"), strerror(errno));
        // 			exit(1);
        // 		}
        // 		if(chdir("/") != 0) {
        // 			fprintf(stderr, _("could not change directory to %s (%s)\n"),
        // 					"/", strerror(errno));
        // 			exit(1);
        // 		}
        // 		umask(0022);
        // 		execv(cmd, argv);
        // 		/* execv only returns if there was an error */
        // 		fprintf(stderr, _("call to execv failed (%s)\n"), strerror(errno));
        // 		exit(1);
        // 	} else {
        // 		/* this code runs for the parent only (wait on the child) */
        // 		int status;
        // 		char obuf[PIPE_BUF]; /* writes <= PIPE_BUF are guaranteed atomic */
        // 		char ibuf[LINE_MAX];
        // 		ssize_t olen = 0, ilen = 0;
        // 		nfds_t nfds = 2;
        // 		struct pollfd fds[2], *child2parent = &(fds[0]), *parent2child = &(fds[1]);
        //
        // 		child2parent->fd = child2parent_pipefd[TAIL];
        // 		child2parent->events = POLLIN;
        // 		fcntl(child2parent->fd, F_SETFL, O_NONBLOCK);
        // 		close(child2parent_pipefd[HEAD]);
        // 		close(parent2child_pipefd[TAIL]);
        //
        // 		if(stdin_cb) {
        // 			parent2child->fd = parent2child_pipefd[HEAD];
        // 			parent2child->events = POLLOUT;
        // 			fcntl(parent2child->fd, F_SETFL, O_NONBLOCK);
        // 		} else {
        // 			parent2child->fd = -1;
        // 			parent2child->events = 0;
        // 			close(parent2child_pipefd[HEAD]);
        // 		}
        //
        // #define STOP_POLLING(p) do { close(p->fd); p->fd = -1; } while(0)
        //
        // 		while((child2parent->fd != -1 || parent2child->fd != -1)
        // 				&& poll(fds, nfds, -1) > 0) {
        // 			if(child2parent->revents & POLLIN) {
        // 				if(_alpm_chroot_read_from_child(handle, child2parent->fd,
        // 							ibuf, &ilen, sizeof(ibuf)) != 0) {
        // 					/* we encountered end-of-file or an error */
        // 					STOP_POLLING(child2parent);
        // 				}
        // 			} else if(child2parent->revents) {
        // 				/* anything but POLLIN indicates an error */
        // 				STOP_POLLING(child2parent);
        // 			}
        // 			if(parent2child->revents & POLLOUT) {
        // 				if(_alpm_chroot_write_to_child(handle, parent2child->fd, obuf, &olen,
        // 							sizeof(obuf), stdin_cb, stdin_ctx) != 0) {
        // 					STOP_POLLING(parent2child);
        // 				}
        // 			} else if(parent2child->revents) {
        // 				/* anything but POLLOUT indicates an error */
        // 				STOP_POLLING(parent2child);
        // 			}
        // 		}
        // 		/* process anything left in the input buffer */
        // 		if(ilen) {
        // 			/* buffer would have already been flushed if it had a newline */
        // 			strcpy(ibuf + ilen, "\n");
        // 			_alpm_chroot_process_output(handle, ibuf);
        // 		}
        //
        // #undef STOP_POLLING
        // #undef HEAD
        // #undef TAIL
        //
        // 		if(parent2child->fd != -1) {
        // 			close(parent2child->fd);
        // 		}
        // 		if(child2parent->fd != -1) {
        // 			close(child2parent->fd);
        // 		}
        //
        // 		while(waitpid(pid, &status, 0) == -1) {
        // 			if(errno != EINTR) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("call to waitpid failed (%s)\n"), strerror(errno));
        // 				retval = 1;
        // 				goto cleanup;
        // 			}
        // 		}
        //
        // 		/* check the return status, make sure it is 0 (success) */
        // 		if(WIFEXITED(status)) {
        // 			_alpm_log(handle, ALPM_LOG_DEBUG, "call to waitpid succeeded\n");
        // 			if(WEXITSTATUS(status) != 0) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("command failed to execute correctly\n"));
        // 				retval = 1;
        // 			}
        // 		} else if(WIFSIGNALED(status) != 0) {
        // 			char *signal_description = strsignal(WTERMSIG(status));
        // 			/* strsignal can return NULL on some (non-Linux) platforms */
        // 			if(signal_description == NULL) {
        // 				signal_description = _("Unknown signal");
        // 			}
        // 			_alpm_log(handle, ALPM_LOG_ERROR, _("command terminated by signal %d: %s\n"),
        // 						WTERMSIG(status), signal_description);
        // 			retval = 1;
        // 		}
        // 	}
        //
        // cleanup:
        // 	if(cwdfd >= 0) {
        // 		if(fchdir(cwdfd) != 0) {
        // 			_alpm_log(handle, ALPM_LOG_ERROR,
        // 					_("could not restore working directory (%s)\n"), strerror(errno));
        // 		}
        // 		close(cwdfd);
        // 	}
        //
        // 	return retval;
    }

    /// Initialize the transaction.
    pub fn trans_init(&mut self, flags: &TransactionFlag) -> Result<()> {
        let mut trans: Transaction = Transaction::default();

        /* lock db */
        if !flags.no_lock {
            if self.handle_lock().is_err() {
                return Err(Error::HandleLock);
            }
        }

        trans.flags = flags.clone();
        trans.state = AlpmTransState::Initialized;

        self.trans = trans;

        Ok(())
    }

    fn check_arch(&mut self, pkgs: &mut Vec<Package>) -> Result<Vec<String>> {
        let mut invalid: Vec<String> = Vec::new();
        let arch: &str = &self.arch;
        for pkg in pkgs {
            let pkgarch = pkg.get_arch()?;
            if pkgarch != "" && pkgarch == arch && pkgarch == "any" {
                let string;
                string = format!("{}-{}-{}", pkg.get_name(), pkg.get_version(), pkgarch);
                invalid.push(string);
            }
        }
        return Ok(invalid);
    }

    /// Prepare a transaction.
    pub fn trans_prepare(&mut self, data: &mut Vec<String>) -> Result<i32> {
        unimplemented!();
        // 	alpm_trans_t *trans;

        let mut trans = self.trans.clone();
        //
        // 	ASSERT(trans != NULL, RET_ERR(handle, ALPM_ERR_TRANS_NULL, -1));
        // 	ASSERT(trans->state == STATE_INITIALIZED, RET_ERR(handle, ALPM_ERR_TRANS_NOT_INITIALIZED, -1));

        /* If there's nothing to do, return without complaining */
        if trans.add.is_empty() && trans.remove.is_empty() {
            return Ok(0);
        }

        // 	alpm_list_t *invalid = check_arch(handle, trans->add);
        *data = match self.check_arch(&mut trans.add) {
            Ok(ref data) if !data.is_empty() => data.clone(),
            _ => return Err(Error::PkgInvalidArch),
        };

        if trans.add.is_empty() {
            self.remove_prepare(data)?;
        } else {
            if self.sync_prepare(data) == -1 {
                /* pm_errno is set by _alpm_sync_prepare() */
                // return -1;
                unimplemented!();
            }
        }

        if !trans.flags.no_deps {
            debug!("sorting by dependencies");
            if !trans.add.is_empty() {
                unimplemented!();
                // let add_orig = trans.add;
                // trans.add = _alpm_sortbydeps(handle, add_orig, trans->remove, 0);
                // alpm_list_free(add_orig);
            }
            if !trans.remove.is_empty() {
                unimplemented!();
                // let rem_orig = trans.remove;
                // trans->remove = _alpm_sortbydeps(handle, rem_orig, NULL, 1);
                // alpm_list_free(rem_orig);
            }
        }

        trans.state = AlpmTransState::PREPARED;

        return Ok(0);
    }

    /// Commit a transaction.
    pub fn trans_commit<T>(&self, data: &Vec<T>) -> i32 {
        // 	alpm_trans_t *trans;
        // 	alpm_event_any_t event;

        let trans = &self.trans;

        // 	ASSERT(trans != NULL, RET_ERR(handle, ALPM_ERR_TRANS_NULL, -1));
        // 	ASSERT(trans->state == STATE_PREPARED, RET_ERR(handle, ALPM_ERR_TRANS_NOT_PREPARED, -1));

        //ASSERT(!(trans->flags & ALPM_TRANS_FLAG_NOLOCK), RET_ERR(handle, ALPM_ERR_TRANS_NOT_LOCKED, -1));

        /* If there's nothing to do, return without complaining */
        if trans.add.is_empty() && trans.remove.is_empty() {
            return 0;
        }

        // 	if(trans->add) {
        // 		if(_alpm_sync_load(handle, data) != 0) {
        // 			/* pm_errno is set by _alpm_sync_load() */
        // 			return -1;
        // 		}
        // 		if(trans->flags & ALPM_TRANS_FLAG_DOWNLOADONLY) {
        // 			return 0;
        // 		}
        // 		if(_alpm_sync_check(handle, data) != 0) {
        // 			/* pm_errno is set by _alpm_sync_check() */
        // 			return -1;
        // 		}
        // 	}
        //
        // 	if(_alpm_hook_run(handle, ALPM_HOOK_PRE_TRANSACTION) != 0) {
        // 		RET_ERR(handle, ALPM_ERR_TRANS_HOOK_FAILED, -1);
        // 	}
        //
        // 	trans->state = STATE_COMMITING;
        //
        // 	alpm_logaction(handle, ALPM_CALLER_PREFIX, "transaction started\n");
        // 	event.type = ALPM_EVENT_TRANSACTION_START;
        // 	EVENT(handle, (void *)&event);
        //
        // 	if(trans->add == NULL) {
        // 		if(_alpm_remove_packages(handle, 1) == -1) {
        // 			/* pm_errno is set by _alpm_remove_packages() */
        // 			Error save = handle->pm_errno;
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "transaction failed\n");
        // 			handle->pm_errno = save;
        // 			return -1;
        // 		}
        // 	} else {
        // 		if(_alpm_sync_commit(handle) == -1) {
        // 			/* pm_errno is set by _alpm_sync_commit() */
        // 			Error save = handle->pm_errno;
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "transaction failed\n");
        // 			handle->pm_errno = save;
        // 			return -1;
        // 		}
        // 	}
        //
        // 	if(trans->state == STATE_INTERRUPTED) {
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX, "transaction interrupted\n");
        // 	} else {
        // 		event.type = ALPM_EVENT_TRANSACTION_DONE;
        // 		EVENT(handle, (void *)&event);
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX, "transaction completed\n");
        // 		_alpm_hook_run(handle, ALPM_HOOK_POST_TRANSACTION);
        // 	}

        //self.trans.state = AlpmTransState::Commited;

        // 	return 0;
        unimplemented!();
    }

    /// Interrupt a transaction.
    /// note: Safe to call from inside signal handlers.
    pub fn trans_interrupt(&self) {
        unimplemented!();
        // 	alpm_trans_t *trans;
        //
        // 	/* Sanity checks */
        // 	CHECK_HANDLE(handle, return -1);
        //
        // 	trans = handle->trans;
        // 	ASSERT(trans != NULL, RET_ERR_ASYNC_SAFE(handle, ALPM_ERR_TRANS_NULL, -1));
        // 	ASSERT(trans->state == STATE_COMMITING || trans->state == STATE_INTERRUPTED,
        // 			RET_ERR_ASYNC_SAFE(handle, ALPM_ERR_TRANS_TYPE, -1));
        //
        // 	trans->state = STATE_INTERRUPTED;
        //
        // 	return 0;
    }

    ///Remove packages in the current transaction.
    ///@param handle the context handle
    ///@param run_ldconfig whether to run ld_config after removing the packages
    ///@return 0 on success, -1 if errors occurred while removing files
    pub fn remove_packages(&self, run_ldconfig: i32) -> i32 {
        unimplemented!();
        // 	alpm_list_t *targ;
        // 	size_t pkg_count, targ_count;
        // 	alpm_trans_t *trans = handle->trans;
        // 	int ret = 0;
        //
        // 	pkg_count = alpm_list_count(trans->remove);
        // 	targ_count = 1;
        //
        // 	for(targ = trans->remove; targ; targ = targ->next) {
        // 		Package *pkg = targ->data;
        //
        // 		if(trans->state == STATE_INTERRUPTED) {
        // 			return ret;
        // 		}
        //
        // 		if(_alpm_remove_single_package(handle, pkg, NULL,
        // 					targ_count, pkg_count) == -1) {
        // 			handle->pm_errno = TransactionAbort;
        // 			/* running ldconfig at this point could possibly screw system */
        // 			run_ldconfig = 0;
        // 			ret = -1;
        // 		}
        //
        // 		targ_count++;
        // 	}
        //
        // 	if(run_ldconfig) {
        // 		/* run ldconfig if it exists */
        // 		_alpm_ldconfig(handle);
        // 	}
        //
        // 	return ret;
    }

    /// Release a transaction.
    pub fn trans_release(&mut self) -> Result<i32> {
        match self.trans.state {
            AlpmTransState::Idle => {}
            _ => return Err(Error::TransactionNull),
        }

        /* unlock db */
        if !self.trans.flags.no_lock {
            self.unlock()?;
        }

        return Ok(0);
    }

    ///Form a signature path given a file path.
    ///Caller must free the result.
    ///`path` - the full path to a file.
    pub fn sigpath(&self, path: &Option<String>) -> Option<String> {
        match path {
            &None => None,
            &Some(ref path) => Some(format!("{}.sig", path)),
        }
    }

    fn no_dep_version(&self) -> bool {
        self.trans.flags.no_depversion
    }

    ///Checks dependencies and returns missing ones in a list.
    ///Dependencies can include versions with depmod operators.
    /// * `pkglist` the list of local packages
    /// * `remove` an alpm_list_t* of packages to be removed
    /// * `upgrade` an alpm_list_t* of packages to be upgraded (remove-then-upgrade)
    /// * `reversedeps` handles the backward dependencies
    /// * returns an alpm_list_t* of depmissing_t pointers.
    pub fn checkdeps(
        &self,
        pkglist: Option<Vec<Package>>,
        remw: Option<Vec<&Package>>,
        upgrade: &Vec<&Package>,
        reversedeps: i32,
    ) -> Result<Vec<DepMissing>> {
        unimplemented!();
        // 	alpm_list_t *i, *j;
        // 	alpm_list_t *dblist = NULL, *modified = NULL;
        let mut dblist: Vec<Package> = Vec::new();
        let mut modified = Vec::new();
        let mut baddeps = Vec::new(); // 	alpm_list_t *baddeps = NULL;
        let nodepversion; // 	int nodepversion;
        let mut rem; //

        rem = match remw {
            Some(r) => r,
            None => Vec::new(),
        };
        match pkglist {
            Some(pkglist) => {
                for pkg in pkglist {
                    // Package *pkg = i->data;
                    if upgrade.contains(&&pkg) || rem.contains(&&pkg) {
                        modified.push(pkg);
                    } else {
                        dblist.push(pkg);
                    }
                }
            }
            None => {}
        }

        nodepversion = self.no_dep_version();

        /* look for unsatisfied dependencies of the upgrade list */
        for ref mut tp in &*upgrade {
            // Package *tp = i->data;
            // _alpm_log(
            //     handle,
            //     ALPM_LOG_DEBUG,
            //     "checkdeps: package %s-%s\n",
            //     tp.name,
            //     tp.version,
            // );

            for mut depend in tp.get_depends()? {
                // Dependency *depend = j->data;
                let orig_mod = depend.depmod.clone();
                // if (nodepversion) {
                //     depend.depmod = alpm_depmod_t::ALPM_DEP_MOD_ANY;
                // }
                /* 1. we check the upgrade list */
                /* 2. we check database for untouched satisfying packages */
                /* 3. we check the dependency ignore list */
                if find_dep_satisfier_ref(upgrade, &depend).is_none()
                    && find_dep_satisfier(&dblist, &depend).is_none()
                    && depend.provides(&self.assumeinstalled)
                {
                    unimplemented!();
                    /* Unsatisfied dependency in the upgrade list */
                    // depmissing_t *miss;
                    // let missdepstring = alpm_dep_compute_string(depend);
                    // _alpm_log(handle, ALPM_LOG_DEBUG,
                    //"checkdeps: missing dependency '%s' for package '%s'\n",
                    // 		missdepstring, tp->name);
                    // free(missdepstring);
                    // miss = depmiss_new(tp->name, depend, NULL);
                    // baddeps = alpm_list_add(baddeps, miss);
                }
                // depend.depmod = orig_mod;
            }
        }

        if reversedeps != 0 {
            unimplemented!();
            // 		/* reversedeps handles the backwards dependencies, ie,
            // 		 * the packages listed in the requiredby field. */
            // 		for(i = dblist; i; i = i->next) {
            // 			Package *lp = i->data;
            // 			for(j = alpm_pkg_get_depends(lp); j; j = j->next) {
            // 				Dependency *depend = j->data;
            // 				alpm_depmod_t orig_mod = depend->mod;
            // 				if(nodepversion) {
            // 					depend->mod = ALPM_DEP_MOD_ANY;
            // 				}
            // 				Package *causingpkg = find_dep_satisfier(modified, depend);
            // 				/* we won't break this depend, if it is already broken, we ignore it */
            // 				/* 1. check upgrade list for satisfiers */
            // 				/* 2. check dblist for satisfiers */
            // 				/* 3. we check the dependency ignore list */
            // 				if(causingpkg &&
            // 						!find_dep_satisfier(upgrade, depend) &&
            // 						!find_dep_satisfier(dblist, depend) &&
            // 						!_alpm_depcmp_provides(depend, handle->assumeinstalled)) {
            // 					depmissing_t *miss;
            // 					char *missdepstring = alpm_dep_compute_string(depend);
            //_alpm_log(handle, ALPM_LOG_DEBUG,
            //"checkdeps: transaction would break '%s' dependency of '%s'\n",
            // 							missdepstring, lp->name);
            // 					free(missdepstring);
            // 					miss = depmiss_new(lp->name, depend, causingpkg->name);
            // 					baddeps = alpm_list_add(baddeps, miss);
            // 				}
            // 				depend->mod = orig_mod;
            // 			}
            // 		}
        }

        Ok(baddeps)
    }

    /// Find a package satisfying a specified dependency.
    /// First look for a literal, going through each db one by one. Then look for
    /// providers. The first satisfier found is returned.
    /// The dependency can include versions with depmod operators.
    ///* `handle` the context handle
    ///* `dbs` an alpm_list_t* of Database where the satisfier will be searched
    ///* `depstring` package or provision name, versioned or not
    ///* returns a Package* satisfying depstring
    pub fn find_dbs_satisfier<T>(&self, dbs: &Vec<T>, depstring: &String) -> Option<Package> {
        unimplemented!();
        // 	Dependency *dep;
        // 	Package *pkg;
        //
        // 	CHECK_HANDLE(handle, return NULL);
        // 	ASSERT(dbs, RET_ERR(handle, WrongArgs, NULL));
        //
        // 	dep = alpm_dep_from_string(depstring);
        // 	ASSERT(dep, return NULL);
        // 	pkg = resolvedep(handle, dep, dbs, NULL, 1);
        // 	alpm_dep_free(dep);
        // 	return pkg;
    }

    ///Check the package conflicts in a database
    ///* `pkglist` the list of packages to check
    ///* returns an alpm_list_t of conflict_t
    pub fn checkconflicts(&self, pkglist: &Vec<&Package>) -> Vec<Conflict> {
        unimplemented!();
        // CHECK_HANDLE(handle, return NULL);
        // return _alpm_innerconflicts(handle, pkglist);
    }

    pub fn db_register_sync(&mut self, treename: &String, level: SigLevel) -> Result<Database> {
        // 	_alpm_log(handle, ALPM_LOG_DEBUG, "registering sync database '%s'\n", treename);

        // #ifndef HAVE_LIBGPGME
        // 	if(level != ALPM_SIG_USE_DEFAULT) {
        // 		RET_ERR(handle, WrongArgs, NULL);
        // 	}
        // #endif

        let mut db = Database::new(treename, false, DbOpsType::Sync);
        // db->ops = &sync_db_ops;
        // db.handle = handle;
        db.set_siglevel(level);
        db.create_path(&self.dbpath, &self.dbext)?;
        db.sync_db_validate(self)?;

        // handle.dbs_sync.push(db);
        return Ok(db);
    }

    pub fn get_sync_dir(&self) -> Result<String> {
        let syncpath = format!("{}/{}", self.dbpath, "sync/");
        match std::fs::metadata(&syncpath) {
            Err(_e) => {
                debug!("database dir '{}' does not exist, creating it", syncpath);
                if fs::create_dir_all(&syncpath).is_err() {
                    return Err(Error::System);
                }
            }
            Ok(m) => {
                if !m.is_dir() {
                    warn!("removing invalid file: {}", syncpath);
                    if std::fs::remove_file(&syncpath).is_err()
                        || fs::create_dir_all(&syncpath).is_err()
                    {
                        return Err(Error::System);
                    }
                }
            }
        }
        return Ok(syncpath);
    }

    /// Load a package and create the corresponding Package struct.
    ///* `pkgfile` path to the package file
    ///* `full` whether to stop the load after metadata is read or continue
    ///through the full archive
    fn pkg_load_internal(&self, pkgfile: &String, full: i32) -> Package {
        unimplemented!();
        // 	int ret, fd;
        // 	int config = 0;
        // 	int hit_mtree = 0;
        // 	struct archive *archive;
        // 	struct archive_entry *entry;
        // 	Package *newpkg;
        // 	struct stat st;
        // 	size_t files_size = 0;
        //
        // 	if(pkgfile == NULL || strlen(pkgfile) == 0) {
        // 		RET_ERR(handle, WrongArgs, NULL);
        // 	}
        //
        // 	fd = _alpm_open_archive(handle, pkgfile, &st, &archive, ALPM_ERR_PKG_OPEN);
        // 	if(fd < 0) {
        // 		if(errno == ENOENT) {
        // 			handle->pm_errno = ALPM_ERR_PKG_NOT_FOUND;
        // 		} else if(errno == EACCES) {
        // 			handle->pm_errno = ALPM_ERR_BADPERMS;
        // 		} else {
        // 			handle->pm_errno = ALPM_ERR_PKG_OPEN;
        // 		}
        // 		return NULL;
        // 	}
        //
        // 	newpkg = _alpm_pkg_new();
        // 	if(newpkg == NULL) {
        // 		handle->pm_errno = ALPM_ERR_MEMORY;
        // 		goto error;
        // 	}
        // 	STRDUP(newpkg->filename, pkgfile,
        // 			handle->pm_errno = ALPM_ERR_MEMORY; goto error);
        // 	newpkg->size = st.st_size;
        //
        // 	_alpm_log(handle, ALPM_LOG_DEBUG, "starting package load for %s\n", pkgfile);
        //
        // 	/* If full is false, only read through the archive until we find our needed
        // 	 * metadata. If it is true, read through the entire archive, which serves
        // 	 * as a verification of integrity and allows us to create the filelist. */
        // 	while((ret = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        // 		const char *entry_name = archive_entry_pathname(entry);
        //
        // 		if(strcmp(entry_name, ".PKGINFO") == 0) {
        // 			/* parse the info file */
        // 			if(parse_descfile(handle, archive, newpkg) != 0) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("could not parse package description file in %s\n"),
        // 						pkgfile);
        // 				goto pkg_invalid;
        // 			}
        // 			if(newpkg->name == NULL || strlen(newpkg->name) == 0) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("missing package name in %s\n"), pkgfile);
        // 				goto pkg_invalid;
        // 			}
        // 			if(newpkg->version == NULL || strlen(newpkg->version) == 0) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("missing package version in %s\n"), pkgfile);
        // 				goto pkg_invalid;
        // 			}
        // 			if(strchr(newpkg->version, '-') == NULL) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("invalid package version in %s\n"), pkgfile);
        // 				goto pkg_invalid;
        // 			}
        // 			config = 1;
        // 			continue;
        // 		} else if(full && strcmp(entry_name, ".MTREE") == 0) {
        // 			/* building the file list: cheap way
        // 			 * get the filelist from the mtree file rather than scanning
        // 			 * the whole archive  */
        // 			hit_mtree = build_filelist_from_mtree(handle, newpkg, archive) == 0;
        // 			continue;
        // 		} else if(handle_simple_path(newpkg, entry_name)) {
        // 			continue;
        // 		} else if(full && !hit_mtree) {
        // 			/* building the file list: expensive way */
        // 			if(add_entry_to_files_list(&newpkg->files, &files_size, entry, entry_name) < 0) {
        // 				goto error;
        // 			}
        // 		}
        //
        // 		if(archive_read_data_skip(archive)) {
        // 			_alpm_log(handle, ALPM_LOG_ERROR, _("error while reading package %s: %s\n"),
        // 					pkgfile, archive_error_string(archive));
        // 			handle->pm_errno = ALPM_ERR_LIBARCHIVE;
        // 			goto error;
        // 		}
        //
        // 		/* if we are not doing a full read, see if we have all we need */
        // 		if((!full || hit_mtree) && config) {
        // 			break;
        // 		}
        // 	}
        //
        // 	if(ret != ARCHIVE_EOF && ret != ARCHIVE_OK) { /* An error occurred */
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("error while reading package %s: %s\n"),
        // 				pkgfile, archive_error_string(archive));
        // 		handle->pm_errno = ALPM_ERR_LIBARCHIVE;
        // 		goto error;
        // 	}
        //
        // 	if(!config) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("missing package metadata in %s\n"), pkgfile);
        // 		goto pkg_invalid;
        // 	}
        //
        // 	_alpm_archive_read_free(archive);
        // 	close(fd);
        //
        // 	/* internal fields for package struct */
        // 	newpkg->origin = ALPM_PKG_FROM_FILE;
        // 	newpkg->origin_data.file = strdup(pkgfile);
        // 	newpkg->ops = get_file_pkg_ops();
        // 	newpkg->handle = handle;
        // 	newpkg->infolevel = INFRQ_BASE | INFRQ_DESC | INFRQ_SCRIPTLET;
        // 	newpkg->validation = ALPM_PKG_VALIDATION_NONE;
        //
        // 	if(full) {
        // 		if(newpkg->files.files) {
        // 			/* attempt to hand back any memory we don't need */
        // 			newpkg->files.files = realloc(newpkg->files.files,
        // 					sizeof(alpm_file_t) * newpkg->files.count);
        // 			/* "checking for conflicts" requires a sorted list, ensure that here */
        // 			_alpm_log(handle, ALPM_LOG_DEBUG,
        // 					"sorting package filelist for %s\n", pkgfile);
        //
        // 			_alpm_filelist_sort(&newpkg->files);
        // 		}
        // 		newpkg->infolevel |= INFRQ_FILES;
        // 	}
        //
        // 	return newpkg;
        //
        // pkg_invalid:
        // 	handle->pm_errno = ALPM_ERR_PKG_INVALID;
        // error:
        // 	_alpm_pkg_free(newpkg);
        // 	_alpm_archive_read_free(archive);
        // 	if(fd >= 0) {
        // 		close(fd);
        // 	}
        //
        // 	return NULL;
    }

    ///adopted limit from repo-add
    const MAX_SIGFILE_SIZE: i16 = 16384;

    pub fn read_sigfile(sigpath: &String, sig: &mut String) -> i32 {
        unimplemented!();
        // 	struct stat st;
        // 	FILE *fp;
        //
        // 	if((fp = fopen(sigpath, "rb")) == NULL) {
        // 		return -1;
        // 	}
        //
        // 	if(fstat(fileno(fp), &st) != 0 || st.st_size > MAX_SIGFILE_SIZE) {
        // 		fclose(fp);
        // 		return -1;
        // 	}
        //
        // 	MALLOC(*sig, st.st_size, fclose(fp); return -1);
        //
        // 	if(fread(*sig, st.st_size, 1, fp) != 1) {
        // 		free(*sig);
        // 		fclose(fp);
        // 		return -1;
        // 	}
        //
        // 	fclose(fp);
        // 	return st.st_size;
    }

    pub fn pkg_load(
        &self,
        filename: &String,
        full: i32,
        level: &SigLevel,
        // pkg: &Package,
    ) -> Result<&Package> {
        unimplemented!();
        // 	int validation = 0;
        // 	char *sigpath;
        //
        // 	CHECK_HANDLE(handle, return -1);
        // 	ASSERT(pkg != NULL, RET_ERR(handle, WrongArgs, -1));
        //
        // 	sigpath = _alpm_sigpath(handle, filename);
        // 	if(sigpath && !_alpm_access(handle, NULL, sigpath, R_OK)) {
        // 		if(level & ALPM_SIG_PACKAGE) {
        // 			alpm_list_t *keys = NULL;
        // 			int fail = 0;
        // 			unsigned char *sig = NULL;
        // 			int len = read_sigfile(sigpath, &sig);
        //
        // 			if(len == -1) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR,
        // 					_("failed to read signature file: %s\n"), sigpath);
        // 				free(sigpath);
        // 				return -1;
        // 			}
        //
        // 			if(alpm_extract_keyid(handle, filename, sig, len, &keys) == 0) {
        // 				alpm_list_t *k;
        // 				for(k = keys; k; k = k->next) {
        // 					char *key = k->data;
        // 					if(_alpm_key_in_keychain(handle, key) == 0) {
        // 						if(_alpm_key_import(handle, key) == -1) {
        // 							fail = 1;
        // 						}
        // 					}
        // 				}
        // 				FREELIST(keys);
        // 			}
        //
        // 			free(sig);
        //
        // 			if(fail) {
        // 				_alpm_log(handle, ALPM_LOG_ERROR, _("required key missing from keyring\n"));
        // 				free(sigpath);
        // 				return -1;
        // 			}
        // 		}
        // 	}
        // 	free(sigpath);
        //
        // 	if(_alpm_pkg_validate_internal(handle, filename, NULL, level, NULL,
        // 				&validation) == -1) {
        // 		/* pm_errno is set by pkg_validate */
        // 		return -1;
        // 	}
        // 	*pkg = _alpm_pkg_load_internal(handle, filename, full);
        // 	if(*pkg == NULL) {
        // 		/* pm_errno is set by pkg_load */
        // 		return -1;
        // 	}
        // 	(*pkg)->validation = validation;
        //
        // 	return 0;
    }

    ///Test if a package should be ignored.
    ///Checks if the package is ignored via IgnorePkg, or if the package is
    ///in a group ignored via IgnoreGroup.
    pub fn pkg_should_ignore(&self, pkg: &Package) -> bool {
        unimplemented!();
        // 	alpm_list_t *groups = NULL;
        //
        // 	/* first see if the package is ignored */
        // if alpm_list_find(self.ignorepkg, pkg.name, _alpm_fnmatch) {
        //     return true;
        // }
        //
        // /* next see if the package is in a group that is ignored */
        // for grp in pkg.alpm_pkg_get_groups() {
        //     // char *grp = groups->data;
        //     if alpm_list_find(self.ignoregroup, grp, _alpm_fnmatch) {
        //         return true;
        //     }
        // }
        //
        // return false;
    }

    /// Unregister all package databases.
    pub fn unregister_all_syncdbs(&self) -> i32 {
        unimplemented!();
        // 	alpm_list_t *i;
        // 	Database *db;
        //
        // 	/* Sanity checks */
        // 	CHECK_HANDLE(handle, return -1);
        // 	/* Do not unregister a database if a transaction is on-going */
        // 	ASSERT(handle->trans == NULL, RET_ERR(handle, ALPM_ERR_TRANS_NOT_NULL, -1));
        //
        // 	/* unregister all sync dbs */
        // 	for(i = handle->dbs_sync; i; i = i->next) {
        // 		db = i->data;
        // 		db->ops->unregister(db);
        // 		i->data = NULL;
        // 	}
        // 	FREELIST(handle->dbs_sync);
        // 	return 0;
    }

    /// Register a sync database of packages.
    pub fn register_syncdb(&mut self, treename: &String, siglevel: SigLevel) -> Result<Database> {
        /* ensure database name is unique */
        if treename == "local" {
            return Err(Error::DatabaseNotNull);
        }
        for d in &self.dbs_sync {
            if treename == d.get_name() {
                return Err(Error::DatabaseNotNull);
            }
        }

        self.db_register_sync(&treename, siglevel)
    }

    pub fn db_register_local(&mut self) -> Result<&Database> {
        let mut db;
        debug!("registering local database");

        db = Database::new(&String::from("local"), true, DbOpsType::Local);
        // db.ops = &local_db_ops;
        db.get_usage_mut().set_all();
        db.create_path(&self.dbpath, &self.dbext)?;
        db.local_db_validate()?;

        self.db_local = db;
        return Ok(&self.db_local);
    }

    /// Add a package to the transaction.
    pub fn add_pkg(&mut self, pkg: &mut Package) -> Result<()> {
        let trans: &mut Transaction = &mut self.trans;
        let pkgname: String = pkg.get_name().clone();
        let pkgver: String = pkg.get_version().clone();

        debug!("adding package '{}'", pkgname);

        if trans.add.contains(&pkg) {
            return Err(Error::TransactionDupTarget);
        }

        let local = self.db_local.get_pkgfromcache(&pkgname)?;
        let localpkgname: &String = local.get_name();
        let localpkgver: &String = &local.get_version();
        let cmp: i8 = pkg.compare_versions(&local);

        if cmp == 0 {
            if trans.flags.needed {
                /* with the NEEDED flag, packages up to date are not reinstalled */
                warn!(
                    "{}-{} is up to date -- skipping\n",
                    localpkgname, localpkgver
                );
                return Ok(());
            } else if !trans.flags.download_only {
                warn!(
                    "{}-{} is up to date -- reinstalling\n",
                    localpkgname, localpkgver
                );
            }
        } else if cmp < 0 && !trans.flags.download_only {
            /* local version is newer */
            warn!(
                "downgrading package {} ({} => {})\n",
                localpkgname, localpkgver, pkgver
            );
        }

        /* add the package to the transaction */
        pkg.set_reason(PackageReason::Explicit);
        debug!(
            "adding package {}-{} to the transaction add list\n",
            pkgname, pkgver
        );
        trans.add.push(pkg.clone());
        Ok(())
    }

    pub fn perform_extraction(
        &self,
        archive: &Archive,
        entry: &ArchiveEntry,
        filename: &String,
    ) -> i32 {
        unimplemented!();
        // 	int ret;
        // 	struct archive *archive_writer;
        // 	const int archive_flags = ARCHIVE_EXTRACT_OWNER |
        // 	                          ARCHIVE_EXTRACT_PERM |
        // 	                          ARCHIVE_EXTRACT_TIME |
        // 	                          ARCHIVE_EXTRACT_UNLINK |
        // 	                          ARCHIVE_EXTRACT_SECURE_SYMLINKS;
        //
        // 	archive_entry_set_pathname(entry, filename);
        //
        // 	archive_writer = archive_write_disk_new();
        // 	if (archive_writer == NULL) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("cannot allocate disk archive object"));
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 				"error: cannot allocate disk archive object");
        // 		return 1;
        // 	}
        //
        // 	archive_write_disk_set_options(archive_writer, archive_flags);
        //
        // 	ret = archive_read_extract2(archive, entry, archive_writer);
        //
        // 	archive_write_free(archive_writer);
        //
        // 	if(ret == ARCHIVE_WARN && archive_errno(archive) != ENOSPC) {
        // 		/* operation succeeded but a "non-critical" error was encountered */
        // 		_alpm_log(handle, ALPM_LOG_WARNING, _("warning given when extracting {} ({})\n"),
        // 				filename, archive_error_string(archive));
        // 	} else if(ret != ARCHIVE_OK) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not extract {} ({})\n"),
        // 				filename, archive_error_string(archive));
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 				"error: could not extract {} ({})\n",
        // 				filename, archive_error_string(archive));
        // 		return 1;
        // 	}
        // 	return 0;
    }

    pub fn upgrade_packages(&mut self) -> Result<()> {
        let mut skip_ldconfig: bool = false;
        let mut ret: Result<()> = Ok(());
        let pkg_count: usize;
        let mut pkg_current: usize;

        if self.trans.add.is_empty() {
            return Ok(());
        }

        pkg_count = self.trans.add.len();
        pkg_current = 1;

        /* loop through our package list adding/upgrading one at a time */
        for newpkg in &self.trans.add {
            match &self.trans.state {
                &AlpmTransState::Initialized => {
                    return ret;
                }
                _ => {}
            }

            if self.commit_single_pkg(&newpkg, pkg_current, pkg_count) != 0 {
                /* something screwed up on the commit, abort the trans */
                self.trans.state = AlpmTransState::Initialized;
                /* running ldconfig at this point could possibly screw system */
                skip_ldconfig = true;
                ret = Err(Error::TransactionAbort);
            }

            pkg_current += 1;
        }

        if !skip_ldconfig {
            /* run ldconfig if it exists */
            self.ldconfig();
        }

        ret
    }

    pub fn try_rename(&self, src: &String, dest: &String) -> i32 {
        match std::fs::rename(src, dest) {
            Err(e) => {
                error!("could not rename {} to {} ({})\n", src, dest, e);
                return 1;
            }
            Ok(()) => {}
        }
        return 0;
    }

    pub fn extract_db_file(
        &self,
        archive: &Archive,
        entry: &ArchiveEntry,
        newpkg: &Package,
        entryname: &String,
    ) -> i32 {
        unimplemented!();
        // 	char filename[PATH_MAX]; /* the actual file we're extracting */
        // 	const char *dbfile = NULL;
        // 	if(strcmp(entryname, ".INSTALL") == 0) {
        // 		dbfile = "install";
        // 	} else if(strcmp(entryname, ".CHANGELOG") == 0) {
        // 		dbfile = "changelog";
        // 	} else if(strcmp(entryname, ".MTREE") == 0) {
        // 		dbfile = "mtree";
        // 	} else if(*entryname == '.') {
        // 		/* reserve all files starting with '.' for future possibilities */
        // 		debug!("skipping extraction of '{}'\n", entryname);
        // 		archive_read_data_skip(archive);
        // 		return 0;
        // 	}
        // 	archive_entry_set_perm(entry, 0644);
        // 	snprintf(filename, PATH_MAX, "{}{}-{}/{}",
        // 			_alpm_db_path(handle->db_local), newpkg->name, newpkg->version, dbfile);
        // 	return perform_extraction(handle, archive, entry, filename);
    }

    pub fn extract_single_file(
        &self,
        archive: &Archive,
        entry: &ArchiveEntry,
        newpkg: &Package,
        oldpkg: &Package,
    ) -> i32 {
        unimplemented!();
        // 	const char *entryname = archive_entry_pathname(entry);
        // 	mode_t entrymode = archive_entry_mode(entry);
        // 	alpm_backup_t *backup = _alpm_needbackup(entryname, newpkg);
        // 	char filename[PATH_MAX]; /* the actual file we're extracting */
        // 	int needbackup = 0, notouch = 0;
        // 	const char *hash_orig = NULL;
        // 	int isnewfile = 0, errors = 0;
        // 	struct stat lsbuf;
        // 	size_t filename_len;
        //
        // 	if(*entryname == '.') {
        // 		return extract_db_file(handle, archive, entry, newpkg, entryname);
        // 	}
        //
        // 	if (!alpm_filelist_contains(&newpkg->files, entryname)) {
        // 		_alpm_log(handle, ALPM_LOG_WARNING,
        // 				_("file not found in file list for package {}. skipping extraction of {}\n"),
        // 				newpkg->name, entryname);
        // 		return 0;
        // 	}
        //
        // 	/* build the new entryname relative to handle->root */
        // 	filename_len = snprintf(filename, PATH_MAX, "{}{}", handle->root, entryname);
        // 	if(filename_len >= PATH_MAX) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR,
        // 				_("unable to extract {}{}: path too long"), handle->root, entryname);
        // 		return 1;
        // 	}
        //
        // 	/* if a file is in NoExtract then we never extract it */
        // 	if(_alpm_fnmatch_patterns(handle->noextract, entryname) == 0) {
        // 		debug!("{} is in NoExtract,"
        // 				" skipping extraction of {}\n",
        // 				entryname, filename);
        // 		archive_read_data_skip(archive);
        // 		return 0;
        // 	}
        //
        // 	/* Check for file existence. This is one of the more crucial parts
        // 	 * to get 'right'. Here are the possibilities, with the filesystem
        // 	 * on the left and the package on the top:
        // 	 * (F=file, N=node, S=symlink, D=dir)
        // 	 *               |  F/N  |   D
        // 	 *  non-existent |   1   |   2
        // 	 *  F/N          |   3   |   4
        // 	 *  D            |   5   |   6
        // 	 *
        // 	 *  1,2- extract, no magic necessary. lstat (llstat) will fail here.
        // 	 *  3,4- conflict checks should have caught this. either overwrite
        // 	 *      or backup the file.
        // 	 *  5- file replacing directory- don't allow it.
        // 	 *  6- skip extraction, dir already exists.
        // 	 */
        //
        // 	isnewfile = llstat(filename, &lsbuf) != 0;
        // 	if(isnewfile) {
        // 		/* cases 1,2: file doesn't exist, skip all backup checks */
        // 	} else if(S_ISDIR(lsbuf.st_mode) && S_ISDIR(entrymode)) {
        // #if 0
        // 		uid_t entryuid = archive_entry_uid(entry);
        // 		gid_t entrygid = archive_entry_gid(entry);
        // #endif
        //
        // 		/* case 6: existing dir, ignore it */
        // 		if(lsbuf.st_mode != entrymode) {
        // 			/* if filesystem perms are different than pkg perms, warn user */
        // 			mode_t mask = 07777;
        // 			_alpm_log(handle, ALPM_LOG_WARNING, _("directory permissions differ on {}\n"
        // 					"filesystem: %o  package: %o\n"), filename, lsbuf.st_mode & mask,
        // 					entrymode & mask);
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 					"warning: directory permissions differ on {}\n"
        // 					"filesystem: %o  package: %o\n", filename, lsbuf.st_mode & mask,
        // 					entrymode & mask);
        // 		}
        //
        // #if 0
        // 		/* Disable this warning until our user management in packages has improved.
        // 		   Currently many packages have to create users in post_install and chown the
        // 		   directories. These all resulted in "false-positive" warnings. */
        //
        // 		if((entryuid != lsbuf.st_uid) || (entrygid != lsbuf.st_gid)) {
        // 			_alpm_log(handle, ALPM_LOG_WARNING, _("directory ownership differs on {}\n"
        // 					"filesystem: %u:%u  package: %u:%u\n"), filename,
        // 					lsbuf.st_uid, lsbuf.st_gid, entryuid, entrygid);
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 					"warning: directory ownership differs on {}\n"
        // 					"filesystem: %u:%u  package: %u:%u\n", filename,
        // 					lsbuf.st_uid, lsbuf.st_gid, entryuid, entrygid);
        // 		}
        // #endif
        //
        // 		debug!("extract: skipping dir extraction of {}\n",
        // 				filename);
        // 		archive_read_data_skip(archive);
        // 		return 0;
        // 	} else if(S_ISDIR(lsbuf.st_mode)) {
        // 		/* case 5: trying to overwrite dir with file, don't allow it */
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("extract: not overwriting dir with file {}\n"),
        // 				filename);
        // 		archive_read_data_skip(archive);
        // 		return 1;
        // 	} else if(S_ISDIR(entrymode)) {
        // 		/* case 4: trying to overwrite file with dir */
        // 		debug!("extract: overwriting file with dir {}\n",
        // 				filename);
        // 	} else {
        // 		/* case 3: trying to overwrite file with file */
        // 		/* if file is in NoUpgrade, don't touch it */
        // 		if(_alpm_fnmatch_patterns(handle->noupgrade, entryname) == 0) {
        // 			notouch = 1;
        // 		} else {
        // 			alpm_backup_t *oldbackup;
        // 			if(oldpkg && (oldbackup = _alpm_needbackup(entryname, oldpkg))) {
        // 				hash_orig = oldbackup->hash;
        // 				needbackup = 1;
        // 			} else if(backup) {
        // 				/* allow adding backup files retroactively */
        // 				needbackup = 1;
        // 			}
        // 		}
        // 	}
        //
        // 	if(notouch || needbackup) {
        // 		if(filename_len + strlen(".pacnew") >= PATH_MAX) {
        // 			_alpm_log(handle, ALPM_LOG_ERROR,
        // 					_("unable to extract {}.pacnew: path too long"), filename);
        // 			return 1;
        // 		}
        // 		strcpy(filename + filename_len, ".pacnew");
        // 		isnewfile = (llstat(filename, &lsbuf) != 0 && errno == ENOENT);
        // 	}
        //
        // 	debug!("extracting {}\n", filename);
        // 	if(perform_extraction(handle, archive, entry, filename)) {
        // 		errors++;
        // 		return errors;
        // 	}
        //
        // 	if(backup) {
        // 		FREE(backup->hash);
        // 		backup->hash = alpm_compute_md5sum(filename);
        // 	}
        //
        // 	if(notouch) {
        // 		alpm_event_pacnew_created_t event = {
        // 			.type = ALPM_EVENT_PACNEW_CREATED,
        // 			.from_noupgrade = 1,
        // 			.oldpkg = oldpkg,
        // 			.newpkg = newpkg,
        // 			.file = filename
        // 		};
        // 		/* "remove" the .pacnew suffix */
        // 		filename[filename_len] = '\0';
        // 		EVENT(handle, &event);
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 				"warning: {} installed as {}.pacnew\n", filename, filename);
        // 	} else if(needbackup) {
        // 		char *hash_local = NULL, *hash_pkg = NULL;
        // 		char origfile[PATH_MAX] = "";
        //
        // 		strncat(origfile, filename, filename_len);
        //
        // 		hash_local = alpm_compute_md5sum(origfile);
        // 		hash_pkg = backup ? backup->hash : alpm_compute_md5sum(filename);
        //
        // 		debug!("checking hashes for {}\n", origfile);
        // 		debug!("current:  {}\n", hash_local);
        // 		debug!("new:      {}\n", hash_pkg);
        // 		debug!("original: {}\n", hash_orig);
        //
        // 		if(hash_local && hash_pkg && strcmp(hash_local, hash_pkg) == 0) {
        // 			/* local and new files are the same, updating anyway to get
        // 			 * correct timestamps */
        // 			debug!("action: installing new file: {}\n",
        // 					origfile);
        // 			if(try_rename(handle, filename, origfile)) {
        // 				errors++;
        // 			}
        // 		} else if(hash_orig && hash_pkg && strcmp(hash_orig, hash_pkg) == 0) {
        // 			/* original and new files are the same, leave the local version alone,
        // 			 * including any user changes */
        // 			debug!(
        // 					"action: leaving existing file in place\n");
        // 			if(isnewfile) {
        // 				unlink(filename);
        // 			}
        // 		} else if(hash_orig && hash_local && strcmp(hash_orig, hash_local) == 0) {
        // 			/* installed file has NOT been changed by user,
        // 			 * update to the new version */
        // 		debug!(action: installing new file: {}\n",
        // 					origfile);
        // 			if(try_rename(handle, filename, origfile)) {
        // 				errors++;
        // 			}
        // 		} else {
        // 			/* none of the three files matched another,  leave the unpacked
        // 			 * file alongside the local file */
        // 			alpm_event_pacnew_created_t event = {
        // 				.type = ALPM_EVENT_PACNEW_CREATED,
        // 				.from_noupgrade = 0,
        // 				.oldpkg = oldpkg,
        // 				.newpkg = newpkg,
        // 				.file = origfile
        // 			};
        // 			debug!(
        // 					"action: keeping current file and installing"
        // 					" new one with .pacnew ending\n");
        // 			EVENT(handle, &event);
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 					"warning: {} installed as {}\n", origfile, filename);
        // 		}
        //
        // 		free(hash_local);
        // 		if(!backup) {
        // 			free(hash_pkg);
        // 		}
        // 	}
        // 	return errors;
    }

    pub fn commit_single_pkg(&self, newpkg: &Package, pkg_current: usize, pkg_count: usize) -> i32 {
        unimplemented!();
        // 	int i, ret = 0, errors = 0;
        // 	int is_upgrade = 0;
        let oldpkg: &Option<Package>;
        // 	Package *oldpkg = NULL;
        // 	Database *db = handle->db_local;
        // 	alpm_trans_t *trans = handle->trans;
        // 	alpm_progress_t progress = ALPM_PROGRESS_ADD_START;
        // 	alpm_event_package_operation_t event;
        // 	const char *log_msg = "adding";
        // 	const char *pkgfile;
        // 	struct archive *archive;
        // 	struct archive_entry *entry;
        // 	int fd, cwdfd;
        // 	struct stat buf;
        //
        // 	ASSERT(trans != NULL, return -1);

        /* see if this is an upgrade. if so, remove the old package first */
        // match newpkg.oldpkg {
        //     Some(ref oldpkg) => {
        //         // int cmp = _alpm_pkg_compare_versions(newpkg, oldpkg);
        //         let cpm = newpkg._alpm_pkg_compare_versions(oldpkg);
        //         // 		if(cmp < 0) {
        //         // 			log_msg = "downgrading";
        //         // 			progress = ALPM_PROGRESS_DOWNGRADE_START;
        //         // 			event.operation = ALPM_PACKAGE_DOWNGRADE;
        //         // 		} else if(cmp == 0) {
        //         // 			log_msg = "reinstalling";
        //         // 			progress = ALPM_PROGRESS_REINSTALL_START;
        //         // 			event.operation = ALPM_PACKAGE_REINSTALL;
        //         // 		} else {
        //         // 			log_msg = "upgrading";
        //         // 			progress = ALPM_PROGRESS_UPGRADE_START;
        //         // 			event.operation = ALPM_PACKAGE_UPGRADE;
        //         // 		}
        //         // 		is_upgrade = 1;
        //         //
        //         // 		/* copy over the install reason */
        //         // 		newpkg->reason = alpm_pkg_get_reason(oldpkg);
        //     }
        //     None => {
        //         // event.operation = ALPM_PACKAGE_INSTALL;
        //     }
        // };

        // 	event.type = ALPM_EVENT_PACKAGE_OPERATION_START;
        // 	event.oldpkg = oldpkg;
        // 	event.newpkg = newpkg;
        // 	EVENT(handle, &event);
        //
        // 	pkgfile = newpkg->origin_data.file;
        //
        // 	debug!("{} package {}-{}\n",
        // 			log_msg, newpkg->name, newpkg->version);
        /* pre_install/pre_upgrade scriptlet */
        // 	if(alpm_pkg_has_scriptlet(newpkg) &&
        // 			!(trans->flags & ALPM_TRANS_FLAG_NOSCRIPTLET)) {
        // 		const char *scriptlet_name = is_upgrade ? "pre_upgrade" : "pre_install";
        //
        // 		_alpm_runscriptlet(handle, pkgfile, scriptlet_name,
        // 				newpkg->version, oldpkg ? oldpkg->version : NULL, 1);
        // 	}

        /* we override any pre-set reason if we have alldeps or allexplicit set */
        // 	if(trans->flags & ALPM_TRANS_FLAG_ALLDEPS) {
        // 		newpkg->reason = ALPM_PKG_REASON_DEPEND;*
        // 	} else if(trans->flags & ALPM_TRANS_FLAG_ALLEXPLICIT) {
        // 		newpkg->reason = Explicit;
        // 	}

        // 	if(oldpkg) {
        // 		/* set up fake remove transaction */
        // 		if(_alpm_remove_single_package(handle, oldpkg, newpkg, 0, 0) == -1) {
        // 			handle->pm_errno = TransactionAbort;
        // 			ret = -1;
        // 			goto cleanup;
        // 		}
        // 	}

        /* prepare directory for database entries so permissions are correct after
        	   changelog/install script installation */
        // 	if(_alpm_local_db_prepare(db, newpkg)) {
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 				"error: could not create database entry {}-{}\n",
        // 				newpkg->name, newpkg->version);
        // 		handle->pm_errno = ALPM_ERR_DB_WRITE;
        // 		ret = -1;
        // 		goto cleanup;
        // 	}
        //
        // 	fd = _alpm_open_archive(db->handle, pkgfile, &buf,
        // 			&archive, ALPM_ERR_PKG_OPEN);
        // 	if(fd < 0) {
        // 		ret = -1;
        // 		goto cleanup;
        // 	}
        //
        // 	/* save the cwd so we can restore it later */
        // 	OPEN(cwdfd, ".", O_RDONLY | O_CLOEXEC);
        // 	if(cwdfd < 0) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not get current working directory\n"));
        // 	}
        //
        // 	/* libarchive requires this for extracting hard links */
        // 	if(chdir(handle->root) != 0) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not change directory to {} ({})\n"),
        // 				handle->root, strerror(errno));
        // 		_alpm_archive_read_free(archive);
        // 		if(cwdfd >= 0) {
        // 			close(cwdfd);
        // 		}
        // 		close(fd);
        // 		ret = -1;
        // 		goto cleanup;
        // 	}
        //
        // 	if(trans->flags & ALPM_TRANS_FLAG_DBONLY) {
        // 		debug!("extracting db files\n");
        // 		while(archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
        // 			const char *entryname = archive_entry_pathname(entry);
        // 			if(entryname[0] == '.') {
        // 				errors += extract_db_file(handle, archive, entry, newpkg, entryname);
        // 			} else {
        // 				archive_read_data_skip(archive);
        // 			}
        // 		}
        // 	} else {
        // 		debug!("extracting files\n");
        //
        // 		/* call PROGRESS once with 0 percent, as we sort-of skip that here */
        // 		PROGRESS(handle, progress, newpkg->name, 0, pkg_count, pkg_current);
        //
        // 		for(i = 0; archive_read_next_header(archive, &entry) == ARCHIVE_OK; i++) {
        // 			int percent;
        //
        // 			if(newpkg->size != 0) {
        // 				/* Using compressed size for calculations here, as newpkg->isize is not
        // 				 * exact when it comes to comparing to the ACTUAL uncompressed size
        // 				 * (missing metadata sizes) */
        // 				int64_t pos = _alpm_archive_compressed_ftell(archive);
        // 				percent = (pos * 100) / newpkg->size;
        // 				if(percent >= 100) {
        // 					percent = 100;
        // 				}
        // 			} else {
        // 				percent = 0;
        // 			}
        //
        // 			PROGRESS(handle, progress, newpkg->name, percent, pkg_count, pkg_current);
        //
        // 			/* extract the next file from the archive */
        // 			errors += extract_single_file(handle, archive, entry, newpkg, oldpkg);
        // 		}
        // 	}
        //
        // 	_alpm_archive_read_free(archive);
        // 	close(fd);
        //
        // 	/* restore the old cwd if we have it */
        // 	if(cwdfd >= 0) {
        // 		if(fchdir(cwdfd) != 0) {
        // 			_alpm_log(handle, ALPM_LOG_ERROR,
        // 					_("could not restore working directory ({})\n"), strerror(errno));
        // 		}
        // 		close(cwdfd);
        // 	}
        //
        // 	if(errors) {
        // 		ret = -1;
        // 		if(is_upgrade) {
        // 			_alpm_log(handle, ALPM_LOG_ERROR, _("problem occurred while upgrading {}\n"),
        // 					newpkg->name);
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 					"error: problem occurred while upgrading {}\n",
        // 					newpkg->name);
        // 		} else {
        // 			_alpm_log(handle, ALPM_LOG_ERROR, _("problem occurred while installing {}\n"),
        // 					newpkg->name);
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 					"error: problem occurred while installing {}\n",
        // 					newpkg->name);
        // 		}
        // 	}
        //
        // 	/* make an install date (in UTC) */
        // 	newpkg->installdate = time(NULL);
        //
        // 	debug!("updating database\n");
        // 	debug!("adding database entry '{}'\n", newpkg->name);
        //
        // 	if(_alpm_local_db_write(db, newpkg, INFRQ_ALL)) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not update database entry {}-{}\n"),
        // 				newpkg->name, newpkg->version);
        // 		alpm_logaction(handle, ALPM_CALLER_PREFIX,
        // 				"error: could not update database entry {}-{}\n",
        // 				newpkg->name, newpkg->version);
        // 		handle->pm_errno = ALPM_ERR_DB_WRITE;
        // 		ret = -1;
        // 		goto cleanup;
        // 	}
        //
        // 	if(_alpm_db_add_pkgincache(db, newpkg) == -1) {
        // 		_alpm_log(handle, ALPM_LOG_ERROR, _("could not add entry '{}' in cache\n"),
        // 				newpkg->name);
        // 	}
        //
        // 	PROGRESS(handle, progress, newpkg->name, 100, pkg_count, pkg_current);
        //
        // 	switch(event.operation) {
        // 		case ALPM_PACKAGE_INSTALL:
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "installed {} ({})\n",
        // 					newpkg->name, newpkg->version);
        // 			break;
        // 		case ALPM_PACKAGE_DOWNGRADE:
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "downgraded {} ({} -> {})\n",
        // 					newpkg->name, oldpkg->version, newpkg->version);
        // 			break;
        // 		case ALPM_PACKAGE_REINSTALL:
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "reinstalled {} ({})\n",
        // 					newpkg->name, newpkg->version);
        // 			break;
        // 		case ALPM_PACKAGE_UPGRADE:
        // 			alpm_logaction(handle, ALPM_CALLER_PREFIX, "upgraded {} ({} -> {})\n",
        // 					newpkg->name, oldpkg->version, newpkg->version);
        // 			break;
        // 		default:
        // 			/* we should never reach here */
        // 			break;
        // 	}
        //
        // 	/* run the post-install script if it exists */
        // 	if(alpm_pkg_has_scriptlet(newpkg)
        // 			&& !(trans->flags & ALPM_TRANS_FLAG_NOSCRIPTLET)) {
        // 		char *scriptlet = _alpm_local_db_pkgpath(db, newpkg, "install");
        // 		const char *scriptlet_name = is_upgrade ? "post_upgrade" : "post_install";
        //
        // 		_alpm_runscriptlet(handle, scriptlet, scriptlet_name,
        // 				newpkg->version, oldpkg ? oldpkg->version : NULL, 0);
        // 		free(scriptlet);
        // 	}
        //
        // 	event.type = ALPM_EVENT_PACKAGE_OPERATION_DONE;
        // 	EVENT(handle, &event);
        //
        // cleanup:
        // 	return ret;
    }

    pub fn get_root(&self) -> &String {
        &self.root
    }

    pub fn get_root_mut(&mut self) -> &mut String {
        &mut self.root
    }

    pub fn get_hookdirs(&self) -> &Vec<String> {
        &self.hookdirs
    }

    pub fn get_hookdirs_mut(&mut self) -> &mut Vec<String> {
        &mut self.hookdirs
    }

    pub fn get_dbpath(&self) -> &String {
        return &self.dbpath;
    }

    pub fn get_dbpath_mut(&mut self) -> &mut String {
        return &mut self.dbpath;
    }

    pub fn get_cachedirs(&self) -> Vec<String> {
        return self.cachedirs.clone();
    }

    pub fn get_logfile(&self) -> &String {
        &self.logfile
    }

    pub fn get_lockfile(&self) -> &String {
        &self.lockfile
    }

    pub fn get_lockfile_mut(&mut self) -> &mut String {
        &mut self.lockfile
    }

    pub fn get_gpgdir(&self) -> String {
        self.gpgdir.clone()
    }

    pub fn get_usesyslog(&self) -> i32 {
        return self.usesyslog;
    }

    pub fn get_noupgrades(&self) -> &Vec<String> {
        &self.noupgrade
    }

    pub fn get_noextracts(&self) -> &Vec<String> {
        &self.noextract
    }

    pub fn get_ignorepkgs(&self) -> &Vec<String> {
        &self.ignorepkg
    }

    pub fn get_ignoregroups(&self) -> &Vec<String> {
        &self.ignoregroup
    }

    pub fn get_overwrite_files(&self) -> &Vec<String> {
        &self.overwrite_files
    }

    // alpm_list_t SYMEXPORT *alpm_get_assumeinstalled(&self)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->assumeinstalled;
    // }

    // const char SYMEXPORT *alpm_get_arch(&self)
    // {
    // 	CHECK_HANDLE(handle, return NULL);
    // 	return handle->arch;
    // }

    // double SYMEXPORT alpm_get_deltaratio(&self)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	return handle->deltaratio;
    // }

    // int SYMEXPORT alpm_get_checkspace(&self)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	return handle->checkspace;
    // }

    pub fn get_dbext(&self) -> &String {
        &self.dbext
    }

    // pub fn alpm_set_logcb(&mut self,  cb: alpm_cb_log)
    // {
    // 	self.logcb = cb;
    // }

    // int SYMEXPORT alpm_set_dlcb(&self, alpm_cb_download cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->dlcb = cb;
    // 	return 0;
    // }

    // fn alpm_set_fetchcb(&mut self, cb: alpm_cb_fetch) {
    //     self.fetchcb = cb;
    // }

    // int SYMEXPORT alpm_set_totaldlcb(&self, alpm_cb_totaldl cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->totaldlcb = cb;
    // 	return 0;
    // }

    // int SYMEXPORT alpm_set_eventcb(Handle *handle, alpm_cb_event cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->eventcb = cb;
    // 	return 0;
    // }

    // int SYMEXPORT alpm_set_questioncb(Handle *handle, alpm_cb_question cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->questioncb = cb;
    // 	return 0;
    // }

    // int SYMEXPORT alpm_set_progresscb(Handle *handle, alpm_cb_progress cb)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	handle->progresscb = cb;
    // 	return 0;
    // }

    pub fn add_hookdir(&mut self, hookdir: &String) -> Result<()> {
        let newhookdir = match std::fs::canonicalize(hookdir) {
            Err(e) => return Err(Error::from(e)),
            Ok(h) => h.into_os_string().into_string()?,
        };
        debug!("option 'hookdir' = {}", newhookdir);
        self.hookdirs.push(newhookdir);
        return Ok(());
    }

    // int SYMEXPORT alpm_set_hookdirs(Handle *handle, alpm_list_t *hookdirs)
    // {
    // 	alpm_list_t *i;
    // 	CHECK_HANDLE(handle, return -1);
    // 	if(handle->hookdirs) {
    // 		FREELIST(handle->hookdirs);
    // 	}
    // 	for(i = hookdirs; i; i = i->next) {
    // 		int ret = alpm_add_hookdir(handle, i->data);
    // 		if(ret) {
    // 			return ret;
    // 		}
    // 	}
    // 	return 0;
    // }
    //
    // int SYMEXPORT alpm_remove_hookdir(Handle *handle, const char *hookdir)
    // {
    // 	char *vdata = NULL;
    // 	char *newhookdir;
    // 	CHECK_HANDLE(handle, return -1);
    // 	ASSERT(hookdir != NULL, RET_ERR(handle, WrongArgs, -1));
    //
    // 	newhookdir = canonicalize_path(hookdir);
    // 	if(!newhookdir) {
    // 		RET_ERR(handle, ALPM_ERR_MEMORY, -1);
    // 	}
    // 	handle->hookdirs = alpm_list_remove_str(handle->hookdirs, newhookdir, &vdata);
    // 	FREE(newhookdir);
    // 	if(vdata != NULL) {
    // 		FREE(vdata);
    // 		return 1;
    // 	}
    // 	return 0;
    // }

    pub fn add_cachedir(&mut self, cachedir: &String) -> Result<i32> {
        /* don't stat the cachedir yet, as it may not even be needed. we can
         * fail later if it is needed and the path is invalid. */
        let newcachedir = match std::fs::canonicalize(cachedir) {
            Err(_) => {
                return Err(Error::Memory);
            }
            Ok(n) => n.into_os_string().into_string()?,
        };
        debug!("option 'cachedir' = {}", newcachedir);
        self.cachedirs.push(newcachedir);
        return Ok(0);
    }

    pub fn set_cachedirs(&mut self, cachedirs: &Vec<String>) -> Result<i32> {
        for dir in cachedirs {
            self.add_cachedir(&dir)?;
        }
        return Ok(0);
    }

    // int SYMEXPORT alpm_remove_cachedir(Handle *handle, const char *cachedir)
    // {
    // 	char *vdata = NULL;
    // 	char *newcachedir;
    // 	CHECK_HANDLE(handle, return -1);
    // 	ASSERT(cachedir != NULL, RET_ERR(handle, WrongArgs, -1));
    //
    // 	newcachedir = canonicalize_path(cachedir);
    // 	if(!newcachedir) {
    // 		RET_ERR(handle, ALPM_ERR_MEMORY, -1);
    // 	}
    // 	handle->cachedirs = alpm_list_remove_str(handle->cachedirs, newcachedir, &vdata);
    // 	FREE(newcachedir);
    // 	if(vdata != NULL) {
    // 		FREE(vdata);
    // 		return 1;
    // 	}
    // 	return 0;
    // }

    pub fn set_logfile(&mut self, logfile: &String) -> Result<i32> {
        if logfile == "" {
            return Err(Error::WrongArgs);
        }

        self.logfile = logfile.clone();

        /* close the stream so logaction
         * will reopen a new stream on the new logfile */
        // if handle.logstream {
        // 	fclose(handle->logstream);
        // 	handle.logstream = NULL;
        // }
        // _alpm_log(handle, ALPM_LOG_DEBUG, "option 'logfile' = %s\n", handle->logfile);
        return Ok(0);
    }

    pub fn set_gpgdir(&mut self, gpgdir: &String) -> Result<()> {
        self.gpgdir = _alpm_set_directory_option(gpgdir, false)?;
        debug!("option 'gpgdir' = {}", self.gpgdir);
        Ok(())
    }

    pub fn set_usesyslog(&mut self, usesyslog: i32) {
        self.usesyslog = usesyslog;
    }

    // static int _alpm_strlist_add(Handle *handle, alpm_list_t **list, const char *str)
    // {
    // 	char *dup;
    // 	CHECK_HANDLE(handle, return -1);
    // 	STRDUP(dup, str, RET_ERR(handle, ALPM_ERR_MEMORY, -1));
    // 	*list = alpm_list_add(*list, dup);
    // 	return 0;
    // }

    fn strlist_set(&self, list: &mut Vec<String>, newlist: &Vec<String>) {
        *list = newlist.clone();
    }

    // static int _alpm_strlist_rem(Handle *handle, alpm_list_t **list, const char *str)
    // {
    // 	char *vdata = NULL;
    // 	CHECK_HANDLE(handle, return -1);
    // 	*list = alpm_list_remove_str(*list, str, &vdata);
    // 	if(vdata != NULL) {
    // 		FREE(vdata);
    // 		return 1;
    // 	}
    // 	return 0;
    // }
    //
    // int SYMEXPORT alpm_add_noupgrade(Handle *handle, const char *pkg)
    // {
    // 	return _alpm_strlist_add(handle, &(handle->noupgrade), pkg);
    // }

    pub fn set_noupgrades(&mut self, noupgrade: &Vec<String>) {
        self.noupgrade = noupgrade.clone()
    }

    // int SYMEXPORT alpm_remove_noupgrade(Handle *handle, const char *pkg)
    // {
    // 	return _alpm_strlist_rem(handle, &(handle->noupgrade), pkg);
    // }
    //
    // int SYMEXPORT alpm_match_noupgrade(Handle *handle, const char *path)
    // {
    // 	return _alpm_fnmatch_patterns(handle->noupgrade, path);
    // }
    //
    // int SYMEXPORT alpm_add_noextract(Handle *handle, const char *path)
    // {
    // 	return _alpm_strlist_add(handle, &(handle->noextract), path);
    // }

    pub fn set_noextracts(&mut self, noextract: &Vec<String>) {
        self.noextract = noextract.clone();
    }

    // int SYMEXPORT alpm_remove_noextract(Handle *handle, const char *path)
    // {
    // 	return _alpm_strlist_rem(handle, &(handle->noextract), path);
    // }
    //
    // int SYMEXPORT alpm_match_noextract(Handle *handle, const char *path)
    // {
    // 	return _alpm_fnmatch_patterns(handle->noextract, path);
    // }
    //
    // int SYMEXPORT alpm_add_ignorepkg(Handle *handle, const char *pkg)
    // {
    // 	return _alpm_strlist_add(handle, &(handle->ignorepkg), pkg);
    // }

    pub fn set_ignorepkgs(&mut self, ignorepkgs: &Vec<String>) {
        self.ignorepkg = ignorepkgs.clone();
    }

    // int SYMEXPORT alpm_remove_ignorepkg(Handle *handle, const char *pkg)
    // {
    // 	return _alpm_strlist_rem(handle, &(handle->ignorepkg), pkg);
    // }
    //
    // int SYMEXPORT alpm_add_ignoregroup(Handle *handle, const char *grp)
    // {
    // 	return _alpm_strlist_add(handle, &(handle->ignoregroup), grp);
    // }

    pub fn set_ignoregroups(&mut self, ignoregrps: &Vec<String>) {
        self.ignoregroup = ignoregrps.clone();
    }

    // int SYMEXPORT alpm_remove_ignoregroup(Handle *handle, const char *grp)
    // {
    // 	return _alpm_strlist_rem(handle, &(handle->ignoregroup), grp);
    // }
    //
    // int SYMEXPORT alpm_add_overwrite_file(Handle *handle, const char *glob)
    // {
    // 	return _alpm_strlist_add(handle, &(handle->overwrite_files), glob);
    // }

    pub fn set_overwrite_files(&mut self, globs: &Vec<String>) {
        self.overwrite_files = globs.clone();
    }

    // int SYMEXPORT alpm_remove_overwrite_file(Handle *handle, const char *glob)
    // {
    // 	return _alpm_strlist_rem(handle, &(handle->overwrite_files), glob);
    // }

    pub fn add_assumeinstalled(&mut self, dep: Dependency) {
        self.assumeinstalled.push(dep);
    }

    // int SYMEXPORT alpm_set_assumeinstalled(Handle *handle, alpm_list_t *deps)
    // {
    // 	CHECK_HANDLE(handle, return -1);
    // 	if(handle->assumeinstalled) {
    // 		alpm_list_free_inner(handle->assumeinstalled, (alpm_list_fn_free)alpm_dep_free);
    // 		alpm_list_free(handle->assumeinstalled);
    // 	}
    // 	while(deps) {
    // 		if(alpm_add_assumeinstalled(handle, deps->data) != 0) {
    // 			return -1;
    // 		}
    // 		deps = deps->next;
    // 	}
    // 	return 0;
    // }
    //
    // static int assumeinstalled_cmp(const void *d1, const void *d2)
    // {
    // 	const Dependency *dep1 = d1;
    // 	const Dependency *dep2 = d2;
    //
    // 	if(dep1->name_hash != dep2->name_hash
    // 			|| strcmp(dep1->name, dep2->name) != 0) {
    // 		return -1;
    // 	}
    //
    // 	if(dep1->version && dep2->version
    // 			&& strcmp(dep1->version, dep2->version) == 0) {
    // 		return 0;
    // 	}
    //
    // 	if(dep1->version == NULL && dep2->version == NULL) {
    // 		return 0;
    // 	}
    //
    //
    // 	return -1;
    // }

    pub fn remove_assumeinstalled(&self, dep: &Dependency) -> i32 {
        unimplemented!();
        // Dependency *vdata = NULL;

        // self.assumeinstalled = alpm_list_remove(handle->assumeinstalled, dep,
        // &assumeinstalled_cmp, (void **)&vdata);
        // if(vdata != NULL) {
        // 	alpm_dep_free(vdata);
        // 	return 1;
        // }

        // return 0;
    }

    pub fn set_arch(&mut self, arch: &String) {
        self.arch = arch.clone();
    }

    pub fn set_deltaratio(&mut self, ratio: f64) -> Result<()> {
        if ratio < 0.0 || ratio > 2.0 {
            return Err(Error::WrongArgs);
        }
        self.deltaratio = ratio;
        Ok(())
    }

    pub fn get_localdb(&self) -> &Database {
        return &self.db_local;
    }

    pub fn get_localdb_mut(&mut self) -> &mut Database {
        return &mut self.db_local;
    }

    pub fn get_syncdbs(&self) -> &Vec<Database> {
        return &self.dbs_sync;
    }

    pub fn alpm_get_syncdbs_mut(&mut self) -> &mut Vec<Database> {
        return &mut self.dbs_sync;
    }

    pub fn alpm_set_checkspace(&mut self, checkspace: i32) {
        self.checkspace = checkspace;
    }

    pub fn set_dbext(&mut self, dbext: &String) {
        self.dbext = dbext.clone();

        // _alpm_log(handle, ALPM_LOG_DEBUG, "option 'dbext' = %s\n", handle->dbext);
    }

    pub fn alpm_set_default_siglevel(&mut self, level: &SigLevel) -> i32 {
        // #ifdef HAVE_LIBGPGME
        self.siglevel = level.clone();
        // #else
        // 	if(level != 0 && level != ALPM_SIG_USE_DEFAULT) {
        // 		RET_ERR(handle, WrongArgs, -1);
        // 	}
        // #endif
        return 0;
    }

    fn alpm_get_default_siglevel(&self) -> SigLevel {
        // CHECK_HANDLE(handle, return -1);
        return self.siglevel;
    }

    pub fn alpm_set_local_file_siglevel(&mut self, level: SigLevel) -> Result<i32> {
        // CHECK_HANDLE(handle, return -1);
        if cfg!(HAVE_LIBGPGME) {
            self.localfilesiglevel = level;
        } else if
        /*level != 0 &&*/
        level.use_default {
            // RET_ERR!(self, WrongArgs, -1);
            return Err(Error::WrongArgs);
        }

        return Ok(0);
    }

    pub fn alpm_get_local_file_siglevel(&self) -> SigLevel {
        // CHECK_HANDLE(handle, return -1);
        if self.localfilesiglevel.use_default {
            return self.siglevel;
        } else {
            return self.localfilesiglevel;
        }
    }

    pub fn alpm_set_remote_file_siglevel(&mut self, level: SigLevel) {
        // unimplemented!();
        // #ifdef HAVE_LIBGPGME
        self.remotefilesiglevel = level;
        // #else
        // 	if(level != 0 && level != ALPM_SIG_USE_DEFAULT) {
        // 		RET_ERR(handle, WrongArgs, -1);
        // 	}
        // #endif
        // 	return 0;
    }

    pub fn alpm_get_remote_file_siglevel(&self) -> SigLevel {
        // CHECK_HANDLE(handle, return -1);
        if self.remotefilesiglevel.use_default {
            return self.siglevel;
        } else {
            return self.remotefilesiglevel;
        }
    }

    pub fn set_disable_dl_timeout(&mut self, disable_dl_timeout: bool) {
        self.disable_dl_timeout = disable_dl_timeout;
    }

    pub fn disable_dl_timeout(&self) -> bool {
        self.disable_dl_timeout
    }

    pub fn handle_new() -> Handle {
        let mut handle = Handle::default();
        handle.deltaratio = 0.0;
        handle.lockfd = None;

        return handle;
    }

    /// Lock the database
    pub fn handle_lock(&mut self) -> std::io::Result<()> {
        assert!(self.lockfile != "");
        assert!(self.lockfd.is_none());

        /* create the dir of the lockfile first */
        match File::create(&self.lockfile) {
            Ok(f) => self.lockfd = Some(f),
            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// Remove the database lock file
    pub fn unlock(&mut self) -> std::io::Result<()> {
        // ASSERT(handle->lockfile != NULL, return 0);
        // ASSERT(handle->lockfd >= 0, return 0);

        // handle.lockfd.close();
        self.lockfd = None;

        if std::fs::remove_file(&self.lockfile).is_err() {
            unimplemented!();
            // RET_ERR_ASYNC_SAFE(handle, ALPM_ERR_SYSTEM, -1);
        }
        return Ok(());
    }

    pub fn handle_unlock(&mut self) -> std::io::Result<()> {
        match self.unlock() {
            Err(e) => {
                eprint!("{}\n", e);
                return Err(e);
                // if(errno == ENOENT) {
                // 	_alpm_log(handle, ALPM_LOG_WARNING,
                // 			_("lock file missing %s\n"), handle->lockfile);
                // 	alpm_logaction(handle, ALPM_CALLER_PREFIX,
                // 			"warning: lock file missing %s\n", handle->lockfile);
                // 	return 0;
                // } else {
                // 	_alpm_log(handle, ALPM_LOG_WARNING,
                // 			_("could not remove lock file %s\n"), handle->lockfile);
                // 	alpm_logaction(handle, ALPM_CALLER_PREFIX,
                // 			"warning: could not remove lock file %s\n", handle->lockfile);
                // 	return -1;
                // }
            }
            _ => {}
        }

        return Ok(());
    }

    /// Transaction preparation for remove actions.
    /// This functions takes a pointer to a alpm_list_t which will be
    /// filled with a list of depmissing_t* objects representing
    /// the packages blocking the transaction.
    /// * `handle` the context handle
    /// *`data` a pointer to an alpm_list_t* to fill
    /// * return 0 on success, -1 on error
    fn remove_prepare(&self, data: &Vec<String>) -> Result<i32> {
        unimplemented!();
        // 	alpm_list_t *lp;
        // 	alpm_trans_t *trans = handle->trans;
        // 	Database *db = handle->db_local;
        // 	alpm_event_t event;
        //
        // 	if((trans->flags & ALPM_TRANS_FLAG_RECURSE)
        // 			&& !(trans->flags & ALPM_TRANS_FLAG_CASCADE)) {
        // 		_alpm_log(handle, ALPM_LOG_DEBUG, "finding removable dependencies\n");
        // 		if(_alpm_recursedeps(db, &trans->remove,
        // 				trans->flags & ALPM_TRANS_FLAG_RECURSEALL)) {
        // 			return -1;
        // 		}
        // 	}
        //
        // 	if(!(trans->flags & ALPM_TRANS_FLAG_NODEPS)) {
        // 		event.type = ALPM_EVENT_CHECKDEPS_START;
        // 		EVENT(handle, &event);
        //
        // 		_alpm_log(handle, ALPM_LOG_DEBUG, "looking for unsatisfied dependencies\n");
        // 		lp = alpm_checkdeps(handle, _get_pkgcache(db), trans->remove, NULL, 1);
        // 		if(lp != NULL) {
        //
        // 			if(trans->flags & ALPM_TRANS_FLAG_CASCADE) {
        // 				if(remove_prepare_cascade(handle, lp)) {
        // 					return -1;
        // 				}
        // 			} else if(trans->flags & ALPM_TRANS_FLAG_UNNEEDED) {
        // 				/* Remove needed packages (which would break dependencies)
        // 				 * from target list */
        // 				remove_prepare_keep_needed(handle, lp);
        // 			} else {
        // 				if(data) {
        // 					*data = lp;
        // 				} else {
        // 					alpm_list_free_inner(lp,
        // 							(alpm_list_fn_free)alpm_depmissing_free);
        // 					alpm_list_free(lp);
        // 				}
        // 				RET_ERR(handle, ALPM_ERR_UNSATISFIED_DEPS, -1);
        // 			}
        // 		}
        // 	}
        //
        // 	/* -Rcs == -Rc then -Rs */
        // 	if((trans->flags & ALPM_TRANS_FLAG_CASCADE)
        // 			&& (trans->flags & ALPM_TRANS_FLAG_RECURSE)) {
        // 		_alpm_log(handle, ALPM_LOG_DEBUG, "finding removable dependencies\n");
        // 		if(_alpm_recursedeps(db, &trans->remove,
        // 					trans->flags & ALPM_TRANS_FLAG_RECURSEALL)) {
        // 			return -1;
        // 		}
        // 	}
        //
        // 	/* Note packages being removed that are optdepends for installed packages */
        // 	if(!(trans->flags & ALPM_TRANS_FLAG_NODEPS)) {
        // 		remove_notify_needed_optdepends(handle, trans->remove);
        // 	}
        //
        // 	if(!(trans->flags & ALPM_TRANS_FLAG_NODEPS)) {
        // 		event.type = ALPM_EVENT_CHECKDEPS_DONE;
        // 		EVENT(handle, &event);
        // 	}
        //
        // 	return 0;
    }

    fn sync_prepare(&self, data: &Vec<String>) -> i32 {
        // 	alpm_list_t *i, *j;
        // 	alpm_list_t *deps = NULL;
        // 	alpm_list_t *unresolvable = NULL;
        let mut from_sync = false;
        let ret = 0;
        let trans = &self.trans;
        // 	alpm_event_t event;

        // 	if(data) {
        // 		*data = NULL;
        // 	}

        for spkg in &trans.add {
            match spkg.get_origin() {
                PackageFrom::SyncDatabase => {
                    from_sync = true;
                    break;
                }
                _ => {}
            }
        }

        /* ensure all sync database are valid if we will be using them */
        for db in &self.dbs_sync {
            if db.status.invalid {
                unimplemented!();
                // RET_ERR(handle, ALPM_ERR_DB_INVALID, -1);
            }
            /* missing databases are not allowed if we have sync targets */
            if from_sync && db.status.missing {
                unimplemented!();
                // RET_ERR(handle, ALPM_ERR_DB_NOT_FOUND, -1);
            }
        }

        if !trans.flags.no_deps {
            unimplemented!();
            // 		alpm_list_t *resolved = NULL;
            // 		alpm_list_t *remove = alpm_list_copy(trans.remove);
            // 		alpm_list_t *localpkgs;
            
            /* Build up list by repeatedly resolving each transaction package */
            /* Resolve targets dependencies */
            // 		event.type = ALPM_EVENT_RESOLVEDEPS_START;
            // 		EVENT(handle, &event);
            debug!("resolving target's dependencies");

            /* build remove list for resolvedeps */
            for spkg in &trans.add {
                unimplemented!();
                // for pkg in spkg.removes {
                //     remove.push(pkg);
                // }
            }

            /* Compute the fake local database for resolvedeps (partial fix for the
             * phonon/qt issue) */
            // 		localpkgs = alpm_list_diff(_get_pkgcache(handle->db_local),
            // 				trans->add, _alpm_pkg_cmp);

            /* Resolve packages in the transaction one at a time, in addition
             * building up a list of packages which could not be resolved. */
            // 		for(i = trans->add; i; i = i->next) {
            // 			Package *pkg = i->data;
            // 			if(_alpm_resolvedeps(handle, localpkgs, pkg, trans->add,
            // 						&resolved, remove, data) == -1) {
            // 				unresolvable = alpm_list_add(unresolvable, pkg);
            // 			}
            // 			/* Else, [resolved] now additionally contains [pkg] and all of its
            // 			   dependencies not already on the list */
            // 		}

            /* If there were unresolvable top-level packages, prompt the user to
             * see if they'd like to ignore them rather than failing the sync */
            // 		if(unresolvable != NULL) {
            // 			alpm_question_remove_pkgs_t question = {
            // 				.type = ALPM_QUESTION_REMOVE_PKGS,
            // 				.skip = 0,
            // 				.packages = unresolvable
            // 			};
            // 			QUESTION(handle, &question);
            // 			if(question.skip) {
            // 				/* User wants to remove the unresolvable packages from the
            // 				   transaction. The packages will be removed from the actual
            // 				   transaction when the transaction packages are replaced with a
            // 				   dependency-reordered list below */
            // 				handle->pm_errno = ALPM_ERR_OK;
            // 				if(data) {
            // 					alpm_list_free_inner(*data,
            // 							(alpm_list_fn_free)alpm_depmissing_free);
            // 					alpm_list_free(*data);
            // 					*data = NULL;
            // 				}
            // 			} else {
            // 				/* pm_errno was set by resolvedeps, callback may have overwrote it */
            // 				handle->pm_errno = ALPM_ERR_UNSATISFIED_DEPS;
            // 				alpm_list_free(resolved);
            // 				alpm_list_free(unresolvable);
            // 				ret = -1;
            // 				goto cleanup;
            // 			}
            // 		}

            /* Set DEPEND reason for pulled packages */
            // 		for(i = resolved; i; i = i->next) {
            // 			Package *pkg = i->data;
            // 			if(!alpm_pkg_find(trans->add, pkg->name)) {
            // 				pkg->reason = ALPM_PKG_REASON_DEPEND;
            // 			}
            // 		}

            /* Unresolvable packages will be removed from the target list; set these
             * aside in the transaction as a list we won't operate on. If we free them
             * before the end of the transaction, we may kill pointers the frontend
             * holds to package objects. */
            // 		trans->unresolvable = unresolvable;

            // 		trans->add = resolved;

            // 		event.type = ALPM_EVENT_RESOLVEDEPS_DONE;
            // 		EVENT(handle, &event);
        }

        if !trans.flags.no_conflicts {
            unimplemented!();
            // 		/* check for inter-conflicts and whatnot */
            // 		event.type = ALPM_EVENT_INTERCONFLICTS_START;
            // 		EVENT(handle, &event);
            //
            // 		debug!("looking for conflicts\n");
            //
            // 		/* 1. check for conflicts in the target list */
            // 		debug!("check targets vs targets\n");
            // 		deps = _alpm_innerconflicts(handle, trans->add);
            //
            // 		for(i = deps; i; i = i->next) {
            // 			conflict_t *conflict = i->data;
            // 			Package *rsync, *sync, *sync1, *sync2;
            //
            // 			/* have we already removed one of the conflicting targets? */
            // 			sync1 = alpm_pkg_find(trans->add, conflict->package1);
            // 			sync2 = alpm_pkg_find(trans->add, conflict->package2);
            // 			if(!sync1 || !sync2) {
            // 				continue;
            // 			}
            //
            // 			debug!("conflicting packages in the sync list: '{}' <-> '{}'\n",
            // 					conflict->package1, conflict->package2);
            //
            // 			/* if sync1 provides sync2, we remove sync2 from the targets, and vice versa */
            // 			alpm_Dependency *dep1 = alpm_dep_from_string(conflict->package1);
            // 			alpm_Dependency *dep2 = alpm_dep_from_string(conflict->package2);
            // 			if(_alpm_depcmp(sync1, dep2)) {
            // 				rsync = sync2;
            // 				sync = sync1;
            // 			} else if(_alpm_depcmp(sync2, dep1)) {
            // 				rsync = sync1;
            // 				sync = sync2;
            // 			} else {
            // 				_alpm_log(handle, ALPM_LOG_ERROR, _("unresolvable package conflicts detected\n"));
            // 				handle->pm_errno = ALPM_ERR_CONFLICTING_DEPS;
            // 				ret = -1;
            // 				if(data) {
            // 					conflict_t *newconflict = _alpm_conflict_dup(conflict);
            // 					if(newconflict) {
            // 						*data = alpm_list_add(*data, newconflict);
            // 					}
            // 				}
            // 				alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
            // 				alpm_list_free(deps);
            // 				alpm_dep_free(dep1);
            // 				alpm_dep_free(dep2);
            // 				goto cleanup;
            // 			}
            // 			alpm_dep_free(dep1);
            // 			alpm_dep_free(dep2);
            //
            // 			/* Prints warning */
            // 			_alpm_log(handle, ALPM_LOG_WARNING,
            // 					_("removing '{}' from target list because it conflicts with '{}'\n"),
            // 					rsync->name, sync->name);
            // 			trans->add = alpm_list_remove(trans->add, rsync, _alpm_pkg_cmp, NULL);
            // 			/* rsync is not a transaction target anymore */
            // 			trans->unresolvable = alpm_list_add(trans->unresolvable, rsync);
            // 		}
            //
            // 		alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
            // 		alpm_list_free(deps);
            // 		deps = NULL;
            //
            // 		/* 2. we check for target vs db conflicts (and resolve)*/
            // 		debug!("check targets vs db and db vs targets\n");
            // 		deps = _alpm_outerconflicts(handle->db_local, trans->add);
            //
            // 		for(i = deps; i; i = i->next) {
            // 			alpm_question_conflict_t question = {
            // 				.type = ALPM_QUESTION_CONFLICT_PKG,
            // 				.remove = 0,
            // 				.conflict = i->data
            // 			};
            // 			conflict_t *conflict = i->data;
            // 			int found = 0;
            //
            // 			/* if conflict->package2 (the local package) is not elected for removal,
            // 			   we ask the user */
            // 			if(alpm_pkg_find(trans->remove, conflict->package2)) {
            // 				found = 1;
            // 			}
            // 			for(j = trans->add; j && !found; j = j->next) {
            // 				Package *spkg = j->data;
            // 				if(alpm_pkg_find(spkg->removes, conflict->package2)) {
            // 					found = 1;
            // 				}
            // 			}
            // 			if(found) {
            // 				continue;
            // 			}
            //
            // 			debug!("package '{}' conflicts with '{}'\n",
            // 					conflict->package1, conflict->package2);
            //
            // 			QUESTION(handle, &question);
            // 			if(question.remove) {
            // 				/* append to the removes list */
            // 				Package *sync = alpm_pkg_find(trans->add, conflict->package1);
            // 				Package *local = _get_pkgfromcache(handle->db_local, conflict->package2);
            // 				debug!("electing '{}' for removal\n", conflict->package2);
            // 				sync->removes = alpm_list_add(sync->removes, local);
            // 			} else { /* abort */
            // 				_alpm_log(handle, ALPM_LOG_ERROR, _("unresolvable package conflicts detected\n"));
            // 				handle->pm_errno = ALPM_ERR_CONFLICTING_DEPS;
            // 				ret = -1;
            // 				if(data) {
            // 					conflict_t *newconflict = _alpm_conflict_dup(conflict);
            // 					if(newconflict) {
            // 						*data = alpm_list_add(*data, newconflict);
            // 					}
            // 				}
            // 				alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
            // 				alpm_list_free(deps);
            // 				goto cleanup;
            // 			}
            // 		}
            // 		event.type = ALPM_EVENT_INTERCONFLICTS_DONE;
            // 		EVENT(handle, &event);
            // 		alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
            // 		alpm_list_free(deps);
        }

        /* Build trans->remove list */
        // 	for(i = trans->add; i; i = i->next) {
        // 		Package *spkg = i->data;
        // 		for(j = spkg->removes; j; j = j->next) {
        // 			Package *rpkg = j->data;
        // 			if(!alpm_pkg_find(trans->remove, rpkg->name)) {
        // 				Package *copy;
        // 				debug!("adding '{}' to remove list\n", rpkg->name);
        // 				if(_alpm_pkg_dup(rpkg, &copy) == -1) {
        // 					return -1;
        // 				}
        // 				trans->remove = alpm_list_add(trans->remove, copy);
        // 			}
        // 		}
        // 	}

        if !trans.flags.no_deps {
            debug!("checking dependencies");
            unimplemented!();
            // 		deps = alpm_checkdeps(handle, _get_pkgcache(handle->db_local),
            // 				trans->remove, trans->add, 1);
            // 		if(deps) {
            // 			handle->pm_errno = ALPM_ERR_UNSATISFIED_DEPS;
            // 			ret = -1;
            // 			if(data) {
            // 				*data = deps;
            // 			} else {
            // 				alpm_list_free_inner(deps,
            // 						(alpm_list_fn_free)alpm_depmissing_free);
            // 				alpm_list_free(deps);
            // 			}
            // 			goto cleanup;
            // 		}
        }

        for spkg in &trans.add {
            /* update download size field */
            let lpkg = self.db_local.get_pkg(spkg.get_name());
            if spkg.compute_download_size() < 0 {
                return -1;
            }
            match lpkg {
                Ok(lpkg) => {
                    unimplemented!();
                    // spkg.oldpkg = match lpkg._alpm_pkg_dup() {
                    //     Some(pkg) => pkg,
                    //     None => return -1,
                    // };
                }
                Err(_) => {}
            }
        }

        // cleanup:
        ret
    }

    fn check_replacers<'a>(&self, lpkg: &Package, sdb: &'a Database) -> Result<Vec<&'a Package>> {
        /* 2. search for replacers in sdb */
        let mut replacers = Vec::new();
        debug!(
            "searching for replacements for {} in {}",
            lpkg.get_name(),
            sdb.get_name()
        );
        for mut spkg in sdb.get_pkgcache()? {
            let mut found = false;
            for replace in spkg.get_replaces()? {
                /* we only want to consider literal matches at this point. */
                if lpkg.depcmp_literal(replace) {
                    found = true;
                    break;
                }
            }
            if found {
                let question = QuestionReplace {
                    qtype: QuestionType::ReplacePkg,
                    replace: false,
                    oldpkg: lpkg,
                    newpkg: spkg,
                    newdb: sdb,
                };
                let tpkg: Package;
                /* check IgnorePkg/IgnoreGroup */
                if self.pkg_should_ignore(spkg) || self.pkg_should_ignore(lpkg) {
                    warn!(
                        "ignoring package replacement ({}-{} => {}-{})",
                        lpkg.get_name(),
                        lpkg.get_version(),
                        spkg.get_name(),
                        spkg.get_version()
                    );
                    continue;
                }

                // 			QUESTION(handle, &question);
                // 			if(!question.replace) {
                // 				continue;
                // 			}

                /* If spkg is already in the target list, we append lpkg to spkg's
                 * removes list */
                if let Some(tpkg) = alpm_pkg_find(&self.trans.add, spkg.get_name()) {
                    debug!(
                        "appending {} to the removes list of {}",
                        lpkg.get_name(),
                        tpkg.get_name()
                    );
                // 				tpkg->removes = alpm_list_add(tpkg->removes, lpkg);

                /* check the to-be-replaced package's reason field */
                // 				if(alpm_pkg_get_reason(lpkg) == ALPM_PKG_REASON_EXPLICIT) {
                // 					tpkg->reason = ALPM_PKG_REASON_EXPLICIT;
                // 				}
                } else {
                    /* add spkg to the target list */
                    /* copy over reason */
                    // spkg.set_reason(lpkg.get_reason()?.clone());
                    // 				spkg->removes = alpm_list_add(NULL, lpkg);
                    debug!(
                        "adding package {}-{} to the transaction targets",
                        spkg.get_name(),
                        spkg.get_version()
                    );
                    replacers.push(spkg);
                }
            }
        }
        return Ok(replacers);
    }

    fn check_literal(&self, lpkg: &Package, spkg: &Package, enable_downgrade: bool) -> i32 {
        // 	/* 1. literal was found in sdb */
        // 	int cmp = _alpm_pkg_compare_versions(spkg, lpkg);
        // 	if(cmp > 0) {
        // 		debug!("new version of '{}' found ({} => {})\n",
        // 				lpkg->name, lpkg->version, spkg->version);
        // 		/* check IgnorePkg/IgnoreGroup */
        // 		if(alpm_pkg_should_ignore(handle, spkg)
        // 				|| alpm_pkg_should_ignore(handle, lpkg)) {
        // 			_alpm_log(handle, ALPM_LOG_WARNING, _("{}: ignoring package upgrade ({} => {})\n"),
        // 					lpkg->name, lpkg->version, spkg->version);
        // 		} else {
        // 			debug!("adding package {}-{} to the transaction targets\n",
        // 					spkg->name, spkg->version);
        // 			return 1;
        // 		}
        // 	} else if(cmp < 0) {
        // 		if(enable_downgrade) {
        // 			/* check IgnorePkg/IgnoreGroup */
        // 			if(alpm_pkg_should_ignore(handle, spkg)
        // 					|| alpm_pkg_should_ignore(handle, lpkg)) {
        // 				_alpm_log(handle, ALPM_LOG_WARNING, _("{}: ignoring package downgrade ({} => {})\n"),
        // 						lpkg->name, lpkg->version, spkg->version);
        // 			} else {
        // 				_alpm_log(handle, ALPM_LOG_WARNING, _("{}: downgrading from version {} to version {}\n"),
        // 						lpkg->name, lpkg->version, spkg->version);
        // 				return 1;
        // 			}
        // 		} else {
        // 			Database *sdb = alpm_pkg_get_db(spkg);
        // 			_alpm_log(handle, ALPM_LOG_WARNING, _("{}: local ({}) is newer than {} ({})\n"),
        // 					lpkg->name, lpkg->version, sdb->treename, spkg->version);
        // 		}
        // 	}
        // 	return 0;
        unimplemented!();
    }

    /// Search for packages to upgrade and add them to the transaction.
    pub fn alpm_sync_sysupgrade(&mut self, enable_downgrade: bool) -> Result<i32> {
        self.get_localdb_mut().load_pkgcache();
        // let trans = &mut self.trans;

        debug!("checking for package upgrades");
        for lpkg in self.db_local.get_pkgcache()? {
            if self.trans.remove.contains(&&lpkg) {
                debug!("{} is marked for removal -- skipping", lpkg.get_name());
                continue;
            }

            if self.trans.add.contains(&&lpkg) {
                debug!(
                    "{} is already in the target list -- skipping",
                    lpkg.get_name()
                );
                continue;
            }
            /* Search for replacers then literal (if no replacer) in each sync database. */
            for sdb in &self.dbs_sync {
                // Database *sdb = j.data;
                // alpm_list_t *replacers;

                debug!("TEPM: {}", sdb.get_usage().upgrade);
                if !sdb.get_usage().upgrade {
                    continue;
                }
                /* Check sdb */
                if let Ok(replacers) = self.check_replacers(lpkg, sdb) {
                    self.trans
                        .add
                        .append(&mut replacers.iter().map(|p| p.clone().clone()).collect());
                    /* jump to next local package */
                    break;
                } else {
                    if let Ok(spkg) = sdb.get_pkgfromcache(lpkg.get_name()) {
                        if self.check_literal(lpkg, spkg, enable_downgrade) != 0 {
                            self.trans.add.push(spkg.clone());
                        }
                        /* jump to next local package */
                        break;
                    }
                }
            }
        }

        Ok(0)
    }
}

pub fn canonicalize_path(path: &String) -> String {
    let mut new_path = path.clone();
    /* verify path ends in a '/' */
    if !path.ends_with('/') {
        new_path.push('/');
    }
    return new_path;
}

pub fn _alpm_set_directory_option(
    value: &String,
    //storage: &mut String,
    must_exist: bool,
) -> Result<String> {
    // let mut path = value.clone();

    if must_exist {
        match std::fs::metadata(value) {
            Ok(ref f) if f.is_dir() => {}
            _ => return Err(Error::NotADirectory),
        }
        Ok(std::fs::canonicalize(value)?
            .into_os_string()
            .into_string()?)
    } else {
        Ok(canonicalize_path(value))
    }
    // return Ok(());
}

// #ifdef HAVE_LIBCURL
// #include <curl/curl.h>
// #endif

// #define EVENT(h, e) \
// do { \
// 	if((h)->eventcb) { \
// 		(h)->eventcb((alpm_event_t *) (e)); \
// 	} \
// } while(0)

// #define QUESTION(h, q) \
// do { \
// 	if((h)->questioncb) { \
// 		(h)->questioncb((alpm_question_t *) (q)); \
// 	} \
// } while(0)

// #define PROGRESS(h, e, p, per, n, r) \
// do { \
// 	if((h)->progresscb) { \
// 		(h)->progresscb(e, p, per, n, r); \
// 	} \
// } while(0)

#[derive(Default, Debug)]
pub struct Handle {
    /* internal usage */
    /// local db pointer
    pub db_local: Database,
    /// List of Databases
    pub dbs_sync: Vec<Database>,
    // 	FILE *logstream;        /* log file stream pointer */
    pub trans: Transaction,
    //
    // #ifdef HAVE_LIBCURL
    // 	/* libcurl handle */
    // 	CURL *curl;             /* reusable curl_easy handle */
    disable_dl_timeout: bool,
    // #endif
    //
    // #ifdef HAVE_LIBGPGME
    // 	alpm_list_t *known_keys;  /* keys verified to be in our keychain */
    // #endif
    //
    // 	/* callback functions */
    // 	alpm_cb_log logcb;          /* Log callback function */
    // 	alpm_cb_download dlcb;      /* Download callback function */
    // 	alpm_cb_totaldl totaldlcb;  /* Total download callback function */
    // fetchcb: alpm_cb_fetch, /* Download file callback function */
    // 	alpm_cb_event eventcb;
    // 	alpm_cb_question questioncb;
    // 	alpm_cb_progress progresscb;

    	/* filesystem paths */
    root: String,                 /* Root path, default '/' */
    dbpath: String,               /* Base path to pacman's DBs */
    logfile: String,              /* Name of the log file */
    lockfile: String,             /* Name of the lock file */
    gpgdir: String,               /* Directory where GnuPG files are stored */
    cachedirs: Vec<String>,       /* Paths to pacman cache directories */
    hookdirs: Vec<String>,        /* Paths to hook directories */
    overwrite_files: Vec<String>, /* Paths that may be overwritten */

    /* package lists */
    /// List of packages NOT to be upgraded */
    noupgrade: Vec<String>,
    /// List of files NOT to extract */
    noextract: Vec<String>,
    /// List of packages to ignore */
    ignorepkg: Vec<String>,
    /// List of groups to ignore */
    ignoregroup: Vec<String>,
    ///List of virtual packages used to satisfy dependencies
    assumeinstalled: Vec<Dependency>,

    /* options */
    /// Architecture of packages we should allow
    arch: String,
    /// Download deltas if possible; a ratio value
    deltaratio: f64,
    /// Use syslog instead of logfile?
    usesyslog: i32,
    /* TODO move to frontend */
    /// Check disk space before installing
    checkspace: i32,
    /// Sync DB extension
    dbext: String,
    /// Default signature verification level
    siglevel: SigLevel,
    /// Signature verification level for local file upgrade operations
    localfilesiglevel: SigLevel,
    /// Signature verification level for remote file upgrade operations */
    remotefilesiglevel: SigLevel,

    /* lock file descriptor */
    lockfd: Option<File>,
    //
    // 	/* for delta parsing efficiency */
    // 	int delta_regex_compiled;
    // 	regex_t delta_regex;
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        Handle {
            db_local: self.db_local.clone(),
            dbs_sync: self.dbs_sync.clone(),
            // 	FILE *logstream;
            trans: self.trans.clone(),
            // 	CURL *curl;             /* reusable curl_easy handle */
            disable_dl_timeout: self.disable_dl_timeout,
            // #endif
            //
            // #ifdef HAVE_LIBGPGME
            // 	alpm_list_t *known_keys;  /* keys verified to be in our keychain */
            // #endif
            //
            // 	/* callback functions */
            // 	alpm_cb_log logcb;          /* Log callback function */
            // 	alpm_cb_download dlcb;      /* Download callback function */
            // 	alpm_cb_totaldl totaldlcb;  /* Total download callback function */
            // fetchcb: alpm_cb_fetch, /* Download file callback function */
            // 	alpm_cb_event eventcb;
            // 	alpm_cb_question questioncb;
            // 	alpm_cb_progress progresscb;
            //
            // 	/* filesystem paths */
            root: self.root.clone(),
            dbpath: self.dbpath.clone(),
            logfile: self.logfile.clone(),
            lockfile: self.lockfile.clone(),
            gpgdir: self.gpgdir.clone(),
            cachedirs: self.cachedirs.clone(),
            hookdirs: self.hookdirs.clone(),
            overwrite_files: self.overwrite_files.clone(),
            noupgrade: self.noupgrade.clone(),
            noextract: self.noextract.clone(),
            ignorepkg: self.ignorepkg.clone(),
            ignoregroup: self.ignoregroup.clone(),
            assumeinstalled: self.assumeinstalled.clone(),
            arch: self.arch.clone(),
            deltaratio: self.deltaratio,
            usesyslog: self.usesyslog,
            checkspace: self.checkspace,
            dbext: self.dbext.clone(),
            siglevel: self.siglevel,
            localfilesiglevel: self.localfilesiglevel,
            remotefilesiglevel: self.remotefilesiglevel,
            // pub pm_errno: Error,
            lockfd: None,
            // 	int delta_regex_compiled;
            // 	regex_t delta_regex;
        }
    }
}

/* Test for existence of a package in a alpm_list_t*
 * of alpm_pkg_t*
 */
fn alpm_pkg_find<'a>(haystack: &'a Vec<Package>, needle: &str) -> Option<&'a Package> {
    for info in haystack {
        if info.get_name() == needle {
            return Some(&info);
        }
    }
    return None;
}
