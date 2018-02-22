use super::*;
use super::be_local::ALPM_LOCAL_DB_VERSION;
/*
 *  db.h
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
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
 *
 *  db.c
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
 *  Copyright (c) 2005 by Christian Hamar <krics@linuxforum.hu>
 *  Copyright (c) 2006 by David Kimpe <dnaku@frugalware.org>
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

// #ifndef ALPM_DB_H
// #define ALPM_DB_H
//
// /* libarchive */
// #include <archive.h>
// #include <archive_entry.h>
//
// #include "alpm.h"
// #include "pkghash.h"
// #include "signing.h"
//
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <regex.h>
//
// /* libalpm */
// #include "db.h"
// #include "alpm_list.h"
// #include "log.h"
// #include "util.h"
// #include "handle.h"
// #include "alpm.h"
// #include "package.h"
// #include "group.h"

/// Database entries
pub const INFRQ_BASE: i32 = (1 << 0);
pub const INFRQ_DESC: i32 = (1 << 1);
pub const INFRQ_FILES: i32 = (1 << 2);
pub const INFRQ_SCRIPTLET: i32 = (1 << 3);
pub const INFRQ_DSIZE: i32 = (1 << 4);
/// ALL should be info stored in the package or database
pub const INFRQ_ALL: i32 = INFRQ_BASE | INFRQ_DESC | INFRQ_FILES | INFRQ_SCRIPTLET | INFRQ_DSIZE;
pub const INFRQ_ERROR: i32 = (1 << 30);

/// Database status. Bitflags. */
#[derive(Debug, Clone, Default)]
pub struct dbstatus_t {
    pub valid: bool,
    pub invalid: bool,
    pub exists: bool,
    pub missing: bool,

    pub local: bool,
    pub pkgcache: bool,
    pub grpcache: bool,
}

// impl Default for dbstatus_t {
//     fn default() -> Self {
//         dbstatus_t::VALID
//     }
// }

// struct db_operations {
//     validate: &Fn(&Database) -> i32,
//     populate: Fn(&Database) -> i32,
//     unregister: Fn(&Database),
// }

/// Database
#[derive(Debug, Default, Clone)]
pub struct Database {
    // handle: Handle,
    pub treename: String,
    /// do not access directly, use _alpm_db_path(db) for lazy access
    pub _path: String,
    pub pkgcache: PackageHash,
    grpcache: Vec<Group>,
    pub servers: Vec<String>,
    // ops: db_operations,
    pub ops_type: db_ops_type, //I created this to deturmine if it is local or other stuff

    /* bitfields for validity, local, loaded caches, etc. */
    pub status: dbstatus_t,
    pub siglevel: SigLevel,
    pub usage: DatabaseUsage,
}

#[derive(Debug, Clone)]
pub enum db_ops_type {
    unknown,
    local,
    sync,
}
impl Default for db_ops_type {
    fn default() -> Self {
        db_ops_type::unknown
    }
}

impl Database {
    pub fn sync_db_validate(&mut self, handle: &Handle) -> Result<bool> {
        if self.status.valid || self.status.missing {
            return Ok(true);
        }
        if self.status.invalid {
            return Err(Error::ALPM_ERR_DB_INVALID_SIG);
        }

        let dbpath = match self._alpm_db_path() {
            Ok(d) => d,
            Err(e) => {
                return Err(e);
            }
        };
        /* we can skip any validation if the database doesn't exist */
        match std::fs::metadata(&dbpath) {
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => {
                    // unimplemented!("DB NOT Found: {}", dbpath);
                    // let event = alpm_event_database_missing_t {
                    // 	etype: alpm_event_type_t::ALPM_EVENT_DATABASE_MISSING,
                    // 	dbname: self.treename.clone(),
                    // };
                    self.status.exists = false;
                    self.status.missing = true;
                    // EVENT!(handle, &alpm_event_t::database_missing(event));
                    self.status.valid = true;
                    self.status.invalid = false;
                    return Ok(true);
                }
                _ => {}
            },
            _ => {}
        }

        self.status.exists = true;
        self.status.missing = false;

        /* this takes into account the default verification level if UNKNOWN
         * was assigned to this db */
        let siglevel = self.alpm_db_get_siglevel();

        if siglevel.database {
            let mut ret = 0;
            let mut retry = 1;
            while retry != 0 {
                retry = 0;
                let siglist = SignatureList::default();
                ret = _alpm_check_pgp_helper(
                    handle,
                    &dbpath,
                    None,
                    siglevel.database_optional,
                    siglevel.database_marginal_ok,
                    siglevel.database_unknown_ok,
                    &siglist,
                );
                if ret != 0 {
                    retry = _alpm_process_siglist(
                        &handle,
                        &self.treename,
                        &siglist,
                        siglevel.database_optional,
                        siglevel.database_marginal_ok,
                        siglevel.database_unknown_ok,
                    );
                }
            }

            if ret != 0 {
                self.status.valid = false;
                self.status.invalid = true;
                return Err(Error::ALPM_ERR_DB_INVALID_SIG);
            }
        }

        /* valid: */
        self.status.valid = true;
        self.status.invalid = false;
        return Ok(true);
    }

    pub fn local_db_read(&mut self, info: &mut Package, inforeq: i32) -> i32 {
        enum NextLineType {
            None,
            Name,
            Version,
            Base,
            Desc,
            Groups,
            Url,
            License,
            Arch,
            BuildDate,
            InstallDate,
            Packager,
            Reason,
            Validation,
            Size,
            Replaces,
            Depends,
            OptDepends,
            Confilcts,
            Provides,
            Files,
            Backup,
        }

        /* bitmask logic here:
         * infolevel: 00001111
         * inforeq:   00010100
         * & result:  00000100
         * == to inforeq? nope, we need to load more info. */
        if (info.infolevel & inforeq) == inforeq {
            /* already loaded all of this info, do nothing */
            return 0;
        }

        if info.infolevel & INFRQ_ERROR != 0 {
            /* We've encountered an error loading this package before. Don't attempt
             * repeated reloads, just give up. */
            return -1;
        }

        info!(
            "loading package data for {} : level=0x{:x}",
            info.name, inforeq
        );

        /* DESC */
        if inforeq & INFRQ_DESC != 0 && (info.infolevel & INFRQ_DESC) == 0 {
            let path = self._alpm_local_db_pkgpath(info, &String::from("desc"));
            let mut fp = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    error!("could not open file {}: {}", path, e);
                    info.infolevel |= INFRQ_ERROR;
                    return -1;
                }
            };
            use std::io::prelude::*;
            let mut lines: String = String::new();
            match fp.read_to_string(&mut lines) {
                Ok(_) => {}
                Err(_) => {
                    return -1;
                }
            }

            let lines_iter = lines.lines();
            let mut next_line_type = NextLineType::None;
            for mut line in lines_iter {
                if String::from(line).trim().len() == 0 {
                    /* length of stripped line was zero */
                    continue;
                }

                match next_line_type {
                    NextLineType::None => {}
                    NextLineType::Name => {
                        if line != info.name {
                            error!(
                                "{} database is inconsistent: name mismatch on package {}",
                                self.treename, info.name
                            );
                        }
                    }
                    NextLineType::Version => {
                        if line != info.version {
                            error!(
                                "{} database is inconsistent: version mismatch on package {}",
                                self.treename, info.name
                            );
                        }
                    }
                    NextLineType::Base => {
                        info.base = String::from(line);
                    }
                    NextLineType::Desc => {
                        info.desc = String::from(line);
                    }
                    NextLineType::Groups => {
                        if line != "" {
                            info.groups.push(String::from(line));
                            continue;
                        }
                    }
                    NextLineType::Url => {
                        info.url = String::from(line);
                    }
                    NextLineType::License => {
                        if line != "" {
                            info.licenses.push(String::from(line));
                            continue;
                        }
                    }
                    NextLineType::Arch => {
                        info.arch = String::from(line);
                    }
                    NextLineType::BuildDate => {
                        info.builddate = _alpm_parsedate(line);
                    }
                    NextLineType::InstallDate => {
                        info.installdate = _alpm_parsedate(line);
                    }
                    NextLineType::Packager => {
                        info.packager = String::from(line);
                    }
                    NextLineType::Reason => {
                        info.reason = PackageReason::from(u8::from_str_radix(line, 10).unwrap());
                    }
                    NextLineType::Validation => {
                        unimplemented!();
                        // // alpm_list_t *i, *v = NULL;
                        // READ_AND_STORE_ALL(v);
                        // // for(i = v; i; i = alpm_list_next(i))
                        // {
                        //     if (strcmp(i.data, "none") == 0) {
                        //         info.validation |= ALPM_PKG_VALIDATION_NONE;
                        //     } else if (strcmp(i.data, "md5") == 0) {
                        //         info.validation |= ALPM_PKG_VALIDATION_MD5SUM;
                        //     } else if (strcmp(i.data, "sha256") == 0) {
                        //         info.validation |= ALPM_PKG_VALIDATION_SHA256SUM;
                        //     } else if (strcmp(i.data, "pgp") == 0) {
                        //         info.validation |= ALPM_PKG_VALIDATION_SIGNATURE;
                        //     } else {
                        //         info!(
                        //             "unknown validation type for package {}: {}",
                        //             info.name, i.data
                        //         );
                        //     }
                        // }
                        // FREELIST(v);
                    }
                    NextLineType::Size => {
                        info.isize = _alpm_strtoofft(&String::from(line));
                    }
                    NextLineType::Replaces => {
                        if line != "" {
                            info.replaces
                                .push(alpm_dep_from_string(&String::from(line)));
                            continue;
                        };
                    }
                    NextLineType::Depends => {
                        if line != "" {
                            info.depends.push(alpm_dep_from_string(&String::from(line)));
                            continue;
                        };
                    }
                    NextLineType::OptDepends => {
                        if line != "" {
                            info.optdepends
                                .push(alpm_dep_from_string(&String::from(line)));
                            continue;
                        };
                    }
                    NextLineType::Confilcts => {
                        if line != "" {
                            info.conflicts
                                .push(alpm_dep_from_string(&String::from(line)));
                            continue;
                        };
                    }
                    NextLineType::Provides => {
                        if line != "" {
                            info.provides
                                .push(alpm_dep_from_string(&String::from(line)));
                            continue;
                        };
                    }
                    _ => {}
                }

                next_line_type = NextLineType::None;

                if line == "%NAME%" {
                    next_line_type = NextLineType::Name;
                } else if line == "%VERSION%" {
                    next_line_type = NextLineType::Version;
                } else if line == "%BASE%" {
                    next_line_type = NextLineType::Base;
                } else if line == "%DESC%" {
                    next_line_type = NextLineType::Desc;
                } else if line == "%GROUPS%" {
                    next_line_type = NextLineType::Groups;
                } else if line == "%URL%" {
                    next_line_type = NextLineType::Url;
                } else if line == "%LICENSE%" {
                    next_line_type = NextLineType::License;
                } else if line == "%ARCH%" {
                    next_line_type = NextLineType::Arch;
                } else if line == "%BUILDDATE%" {
                    next_line_type = NextLineType::BuildDate;
                } else if line == "%INSTALLDATE%" {
                    next_line_type = NextLineType::InstallDate;
                } else if line == "%PACKAGER%" {
                    next_line_type = NextLineType::Packager;
                } else if line == "%REASON%" {
                    next_line_type = NextLineType::Reason;
                } else if line == "%VALIDATION%" {
                    next_line_type = NextLineType::Validation;
                } else if line == "%SIZE%" {
                    next_line_type = NextLineType::Size;
                } else if line == "%REPLACES%" {
                    next_line_type = NextLineType::Replaces;
                } else if line == "%DEPENDS%" {
                    next_line_type = NextLineType::Depends;
                } else if line == "%OPTDEPENDS%" {
                    next_line_type = NextLineType::OptDepends;
                } else if line == "%CONFLICTS%" {
                    next_line_type = NextLineType::Confilcts;
                } else if line == "%PROVIDES%" {
                    next_line_type = NextLineType::Provides;
                }
            }
            info.infolevel |= INFRQ_DESC;
        }

        /* FILES */
        if inforeq & INFRQ_FILES != 0 && (info.infolevel & INFRQ_FILES) == 0 {
            unimplemented!();
            let path = self._alpm_local_db_pkgpath(info, &String::from("desc"));
            let mut fp = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    error!("could not open file {}: {}", path, e);
                    info.infolevel |= INFRQ_ERROR;
                    return -1;
                }
            };
            use std::io::prelude::*;
            let mut lines: String = String::new();
            match fp.read_to_string(&mut lines) {
                Ok(_) => {}
                Err(e) => {
                    return -1;
                }
            }

            let lines_iter = lines.lines();
            let mut next_line_type = NextLineType::None;
            let mut files_count = 0;
            let mut files_size = 0;
            let mut len = 0;
            let mut files = Vec::new();
            for mut line in lines_iter {
                match next_line_type {
                    NextLineType::Files => {
                        if line == "" {
                            next_line_type = NextLineType::None;
                            // info.files.count = files_count;
                            // info.files.files = files;
                            // _alpm_filelist_sort(&info.files);
                            continue;
                        }
                        files.push(line);
                    }
                    NextLineType::Backup => {
                        if line == "" {
                            next_line_type = NextLineType::None;
                            continue;
                        }
                        // let backup: alpm_backup_t;
                        // if (_alpm_split_backup(line, &backup)) {
                        //     info.infolevel |= INFRQ_ERROR;
                        //     return -1;
                        // }
                        // info.backup.push(backup);
                    }
                    _ => {}
                }
                unimplemented!();
                if line == "%FILES%" {
                    next_line_type = NextLineType::Files;
                } else if line == "%BACKUP%" {
                    next_line_type = NextLineType::Backup;
                }
            }
            info.infolevel |= INFRQ_FILES;
        }

        /* INSTALL */
        if inforeq & INFRQ_SCRIPTLET != 0 && (info.infolevel & INFRQ_SCRIPTLET) == 0 {
            let path = self._alpm_local_db_pkgpath(info, &String::from("install"));
            use std::path::Path;
            let install_path = Path::new(&path);
            if install_path.exists() {
                info.scriptlet = 1;
            }
            info.infolevel |= INFRQ_SCRIPTLET;
        }

        return 0;

        // error:
        // 	info->infolevel |= INFRQ_ERROR;
        // 	if(fp) {
        // 		fclose(fp);
        // 	}
        // 	return -1;
    }

    pub fn checkdbdir(&mut self) -> Result<()> {
        let path = self._alpm_db_path().unwrap();
        match std::fs::metadata(&path) {
            Err(_) => {
                debug!("database dir '{}' does not exist, creating it", path);
                if std::fs::create_dir(&path).is_err() {
                    return Err(Error::System);
                }
            }
            Ok(p) => if !p.is_dir() {
                warn!("removing invalid database: {}", path);
                if std::fs::remove_dir_all(&path).is_err() || std::fs::create_dir(&path).is_err() {
                    return Err(Error::System);
                }
            },
        }
        return Ok(());
    }

    pub fn _alpm_local_db_prepare(&mut self, info: &Package) -> i32 {
        let pkgpath;

        if self.checkdbdir().is_err() {
            return -1;
        }

        pkgpath = self._alpm_local_db_pkgpath(info, &String::new());

        match std::fs::create_dir(&pkgpath) {
            Err(e) => {
                error!("could not create directory {}: {}", pkgpath, e);
                return -1;
            }
            _ => {}
        }
        0
    }

    pub fn _alpm_local_db_write(&self, info: &Package, inforeq: i32) -> i32 {
        unimplemented!();
        // 	FILE *fp = NULL;
        // 	mode_t oldmask;
        // 	alpm_list_t *lp;
        // 	int retval = 0;
        //
        // 	if(db == NULL || info == NULL || !(db.status & LOCAL)) {
        // 		return -1;
        // 	}
        //
        // 	/* make sure we have a sane umask */
        // 	oldmask = umask(0022);
        //
        // 	/* DESC */
        // 	if(inforeq & INFRQ_DESC) {
        // 		char *path;
        // 		_alpm_log(db.handle, ALPM_LOG_DEBUG,
        // 				"writing {}-{} DESC information back to db",
        // 				info.name, info.version);
        // 		path = _alpm_local_db_pkgpath(db, info, "desc");
        // 		if(!path || (fp = fopen(path, "w")) == NULL) {
        // 			_alpm_log(db.handle, ALPM_LOG_ERROR, _("could not open file {}: {}"),
        // 					path, strerror(errno));
        // 			retval = -1;
        // 			free(path);
        // 			goto cleanup;
        // 		}
        // 		free(path);
        // 		fprintf(fp, "%%NAME%%{}"
        // 						"%%VERSION%%{}", info.name, info.version);
        // 		if(info.base) {
        // 			fprintf(fp, "%%BASE%%"
        // 							"{}", info.base);
        // 		}
        // 		if(info.desc) {
        // 			fprintf(fp, "%%DESC%%"
        // 							"{}", info.desc);
        // 		}
        // 		if(info.url) {
        // 			fprintf(fp, "%%URL%%"
        // 							"{}", info.url);
        // 		}
        // 		if(info.arch) {
        // 			fprintf(fp, "%%ARCH%%"
        // 							"{}", info.arch);
        // 		}
        // 		if(info.builddate) {
        // 			fprintf(fp, "%%BUILDDATE%%"
        // 							"%jd", (intmax_t)info.builddate);
        // 		}
        // 		if(info.installdate) {
        // 			fprintf(fp, "%%INSTALLDATE%%"
        // 							"%jd", (intmax_t)info.installdate);
        // 		}
        // 		if(info.packager) {
        // 			fprintf(fp, "%%PACKAGER%%"
        // 							"{}", info.packager);
        // 		}
        // 		if(info.isize) {
        // 			/* only write installed size, csize is irrelevant once installed */
        // 			fprintf(fp, "%%SIZE%%"
        // 							"%jd", (intmax_t)info.isize);
        // 		}
        // 		if(info.reason) {
        // 			fprintf(fp, "%%REASON%%"
        // 							"%u", info.reason);
        // 		}
        // 		if(info.groups) {
        // 			fputs("%GROUPS%", fp);
        // 			for(lp = info.groups; lp; lp = lp.next) {
        // 				fputs(lp->data, fp);
        // 				fputc('', fp);
        // 			}
        // 			fputc('', fp);
        // 		}
        // 		if(info->licenses) {
        // 			fputs("%LICENSE%", fp);
        // 			for(lp = info->licenses; lp; lp = lp->next) {
        // 				fputs(lp->data, fp);
        // 				fputc('', fp);
        // 			}
        // 			fputc('', fp);
        // 		}
        // 		if(info->validation) {
        // 			fputs("%VALIDATION%", fp);
        // 			if(info->validation & ALPM_PKG_VALIDATION_NONE) {
        // 				fputs("none", fp);
        // 			}
        // 			if(info->validation & ALPM_PKG_VALIDATION_MD5SUM) {
        // 				fputs("md5", fp);
        // 			}
        // 			if(info->validation & ALPM_PKG_VALIDATION_SHA256SUM) {
        // 				fputs("sha256", fp);
        // 			}
        // 			if(info->validation & ALPM_PKG_VALIDATION_SIGNATURE) {
        // 				fputs("pgp", fp);
        // 			}
        // 			fputc('', fp);
        // 		}
        //
        // 		write_deps(fp, "%REPLACES%", info->replaces);
        // 		write_deps(fp, "%DEPENDS%", info->depends);
        // 		write_deps(fp, "%OPTDEPENDS%", info->optdepends);
        // 		write_deps(fp, "%CONFLICTS%", info->conflicts);
        // 		write_deps(fp, "%PROVIDES%", info->provides);
        //
        // 		fclose(fp);
        // 		fp = NULL;
        // 	}
        //
        // 	/* FILES */
        // 	if(inforeq & INFRQ_FILES) {
        // 		char *path;
        // 		_alpm_log(db->handle, ALPM_LOG_DEBUG,
        // 				"writing {}-{} FILES information back to db",
        // 				info->name, info->version);
        // 		path = _alpm_local_db_pkgpath(db, info, "files");
        // 		if(!path || (fp = fopen(path, "w")) == NULL) {
        // 			_alpm_log(db->handle, ALPM_LOG_ERROR, _("could not open file {}: {}"),
        // 					path, strerror(errno));
        // 			retval = -1;
        // 			free(path);
        // 			goto cleanup;
        // 		}
        // 		free(path);
        // 		if(info->files.count) {
        // 			size_t i;
        // 			fputs("%FILES%", fp);
        // 			for(i = 0; i < info->files.count; i++) {
        // 				const alpm_file_t *file = info->files.files + i;
        // 				fputs(file->name, fp);
        // 				fputc('', fp);
        // 			}
        // 			fputc('', fp);
        // 		}
        // 		if(info->backup) {
        // 			fputs("%BACKUP%", fp);
        // 			for(lp = info->backup; lp; lp = lp->next) {
        // 				const alpm_backup_t *backup = lp->data;
        // 				fprintf(fp, "{}\t{}", backup->name, backup->hash);
        // 			}
        // 			fputc('', fp);
        // 		}
        // 		fclose(fp);
        // 		fp = NULL;
        // 	}
        //
        // 	/* INSTALL and MTREE */
        // 	/* nothing needed here (automatically extracted) */
        //
        // cleanup:
        // 	umask(oldmask);
        // 	return retval;
    }

    fn _alpm_local_db_remove(&self, info: &Package) -> i32 {
        unimplemented!();
        // 	int ret = 0;
        // 	DIR *dirp;
        // 	struct dirent *dp;
        // 	char *pkgpath;
        // 	size_t pkgpath_len;
        //
        // 	pkgpath = _alpm_local_db_pkgpath(db, info, NULL);
        // 	if(!pkgpath) {
        // 		return -1;
        // 	}
        // 	pkgpath_len = strlen(pkgpath);
        //
        // 	dirp = opendir(pkgpath);
        // 	if(!dirp) {
        // 		free(pkgpath);
        // 		return -1;
        // 	}
        // 	/* go through the local DB entry, removing the files within, which we know
        // 	 * are not nested directories of any kind. */
        // 	for(dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
        // 		if(strcmp(dp->d_name, "..") != 0 && strcmp(dp->d_name, ".") != 0) {
        // 			char name[PATH_MAX];
        // 			if(pkgpath_len + strlen(dp->d_name) + 2 > PATH_MAX) {
        // 				/* file path is too long to remove, hmm. */
        // 				ret = -1;
        // 			} else {
        // 				sprintf(name, "{}/{}", pkgpath, dp->d_name);
        // 				if(unlink(name)) {
        // 					ret = -1;
        // 				}
        // 			}
        // 		}
        // 	}
        // 	closedir(dirp);
        //
        // 	/* after removing all enclosed files, we can remove the directory itself. */
        // 	if(rmdir(pkgpath)) {
        // 		ret = -1;
        // 	}
        // 	free(pkgpath);
        // 	return ret;
    }

    pub fn local_db_populate(&mut self) -> Result<()> {
        use std::fs;
        use self::Error::*;
        let mut count = 0;
        let dbdir;
        let dbpath;

        if self.status.invalid {
            return Err(ALPM_ERR_DB_INVALID);
        }
        if self.status.missing {
            return Err(ALPM_ERR_DB_NOT_FOUND);
        }

        dbpath = self._alpm_db_path()?;

        dbdir = match fs::read_dir(dbpath) {
            Err(_e) => return Err(ALPM_ERR_DB_OPEN),
            Ok(d) => d,
        };
        self.status.exists = true;
        self.status.missing = false;
        self.pkgcache = _alpm_pkghash_create();

        for ent in dbdir {
            match ent {
                Ok(ent) => {
                    let mut pkg;
                    let name = ent.file_name().into_string().unwrap();

                    if name == "." || name == ".." {
                        continue;
                    }
                    match fs::metadata(ent.path()) {
                        Ok(m) => if !m.is_dir() {
                            continue;
                        },
                        Err(_e) => {}
                    }

                    pkg = Package::default();
                    /* split the db entry name */
                    {
                        let (name, version, name_hash) = match _alpm_splitname(&name) {
                            Err(_) => {
                                error!("invalid name for database entry '{}'", name);
                                continue;
                            }
                            Ok(d) => d,
                        };
                        pkg.name = name;
                        pkg.version = version;
                        pkg.name_hash = name_hash;
                    }

                    /* duplicated database entries are not allowed */
                    // 		if(_alpm_pkghash_find(db->pkgcache, pkg->name)) {
                    // 			_alpm_log(db->handle, ALPM_LOG_ERROR, _("duplicated database entry '{}'"), pkg->name);
                    // 			_alpm_pkg_free(pkg);
                    // 			continue;
                    // 		}

                    pkg.origin = PackageFrom::ALPM_PKG_FROM_LOCALDB;

                    /* explicitly read with only 'BASE' data, accessors will handle the rest */
                    if self.local_db_read(&mut pkg, INFRQ_BASE) == -1 {
                        debug!("corrupted database entry '{}'", name);
                        continue;
                    }

                    /* add to the collection */
                    info!(
                        "adding '{}' to package cache for db '{}'",
                        pkg.name, self.treename
                    );
                    self.pkgcache._alpm_pkghash_add(pkg);
                    count += 1;
                }
                Err(_e) => unimplemented!(),
            }
        }

        if count > 0 {
            self.pkgcache.list.sort_by(_alpm_pkg_cmp);
        }
        debug!(
            "added {} packages to package cache for db '{}'",
            count, self.treename
        );
        Ok(())
    }

    pub fn local_db_validate(&mut self) -> Result<bool> {
        let dbpath;
        let dbdir;
        let dbverpath;
        let version: usize;
        let mut dbverfile;

        if self.status.valid {
            return Ok(true);
        }
        if self.status.invalid {
            return Ok(false);
        }

        dbpath = match self._alpm_db_path() {
            Ok(d) => d,
            Err(e) => {
                return Err(e);
            }
        };

        dbdir = match std::fs::read_dir(&dbpath) {
            Ok(d) => d,
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        /* local database dir doesn't exist yet - create it */
                        match self.local_db_create(&dbpath) {
                            Ok(_) => {
                                self.status.valid = true;
                                self.status.invalid = false;
                                self.status.exists = true;
                                self.status.missing = false;
                                return Ok(true);
                            }
                            Err(e) => {
                                self.status.exists = false;
                                self.status.missing = true;
                                return Err(e);
                            }
                        }
                    }
                    _ => {
                        return Err(Error::ALPM_ERR_DB_OPEN);
                    }
                }
            }
        };
        self.status.exists = true;
        self.status.missing = false;

        dbverpath = format!("{}ALPM_DB_VERSION", dbpath);

        dbverfile = match std::fs::File::open(&dbverpath) {
            Err(_e) => {
                /* create dbverfile if local database is empty - otherwise version error */
                for ent in dbdir {
                    match ent {
                        Ok(ent) => {
                            let name = &ent.file_name();
                            if name == "." || name == ".." {
                                continue;
                            } else {
                                self.status.valid = false;
                                self.status.invalid = true;
                                return Err(Error::ALPM_ERR_DB_VERSION);
                            }
                        }
                        Err(_e) => panic!(),
                    }
                }

                if self.local_db_add_version(&dbpath).is_err() {
                    self.status.valid = false;
                    self.status.invalid = true;
                    return Err(Error::ALPM_ERR_DB_VERSION);
                }

                self.status.valid = true;
                self.status.invalid = false;
                return Ok(true);
            }
            Ok(f) => f,
        };

        use std::io::Read;
        let mut dbverfilestr = String::new();
        dbverfile.read_to_string(&mut dbverfilestr).unwrap();
        dbverfilestr = String::from(dbverfilestr.trim());
        version = match dbverfilestr.parse() {
            Err(e) => {
                self.status.valid = false;
                self.status.invalid = true;
                return Err(Error::ALPM_ERR_DB_VERSION);
            }
            Ok(v) => v,
        };

        if version != ALPM_LOCAL_DB_VERSION {
            self.status.valid = false;
            self.status.invalid = true;
            return Err(Error::ALPM_ERR_DB_VERSION);
        }

        self.status.valid = true;
        self.status.invalid = false;
        return Ok(true);
    }

    fn local_db_create(&mut self, dbpath: &String) -> Result<i32> {
        // if (std::fs::create_dir(dbpath, 0755) != 0) {
        match std::fs::create_dir(dbpath) {
            Err(e) => {
                eprintln!("could not create directory {}: {}", dbpath, e);
                return Err(Error::ALPM_ERR_DB_CREATE);
            }
            _ => {}
        }
        if self.local_db_add_version(dbpath).is_err() {
            // return 1;
            unimplemented!();
        }

        return Ok(0);
    }

    fn local_db_add_version(&self, dbpath: &String) -> std::io::Result<usize> {
        let dbverpath = format!("{}ALPM_DB_VERSION", dbpath);
        use std::io::Write;
        let mut dbverfile = std::fs::File::create(dbverpath)?;
        let data = format!("{}", ALPM_LOCAL_DB_VERSION);
        dbverfile.write(data.as_bytes())
    }

    /* Note: the return value must be freed by the caller */
    fn _alpm_local_db_pkgpath(&mut self, info: &Package, filename: &String) -> String {
        let pkgpath: String;
        let dbpath: String;

        dbpath = self._alpm_db_path().unwrap();
        pkgpath = format!("{}{}-{}/{}", dbpath, info.name, info.version, filename);
        return pkgpath;
    }

    fn validate(&mut self, handle: &Handle) -> Result<bool> {
        match self.ops_type {
            db_ops_type::local => self.local_db_validate(),
            db_ops_type::sync => self.sync_db_validate(handle),
            db_ops_type::unknown => unimplemented!(),
        }
    }

    // /// Helper function for alpm_db_unregister{_all}
    fn _alpm_db_unregister(&self) {
        unimplemented!();
        // {
        // 	if(db == NULL) {
        // 		return;
        // 	}
        //
        // 	_alpm_log(db->handle, ALPM_LOG_DEBUG, "unregistering database '{}'", db->treename);
        // 	_alpm_db_free(db);
    }

    /// Get the serverlist of a database.
    pub fn alpm_db_get_servers(&self) -> &Vec<String> {
        &self.servers
    }

    /// Set the serverlist of a database.
    fn alpm_db_set_servers(&mut self, servers: Vec<String>) {
        self.servers = servers;
    }

    /// Add a download server to a database.
    /// db database pointer
    /// url url of the server
    /// return - 0 on success, -1 on error (pm_errno is set accordingly)
    pub fn alpm_db_add_server(&mut self, url: &String) -> Result<()> {
        let newurl;

        /* Sanity checks */
        if url.len() == 0 {
            return Err(Error::ALPM_ERR_WRONG_ARGS);
        }

        newurl = sanitize_url(&url);
        debug!(
            "adding new server URL to database '{}': {}",
            self.treename, newurl
        );
        self.servers.push(newurl);
        Ok(())
    }

    /// Remove a download server from a database.
    /// db database pointer
    /// url url of the server
    /// return - 0 on success, 1 on server not present,
    /// -1 on error (pm_errno is set accordingly)
    fn alpm_db_remove_server(&mut self, url: &String) -> i32 {
        let newurl;
        // let vdata;
        // let ret = 1;

        /* Sanity checks */
        // ASSERT(db != NULL, return -1);
        // self.handle.pm_errno = Error::ALPM_ERR_OK;
        // ASSERT(url != NULL && strlen(url) != 0, RET_ERR(db->handle, ALPM_ERR_WRONG_ARGS, -1));

        newurl = sanitize_url(url);
        // if(!newurl) {
        // 	return -1;
        // }

        let index = match self.servers.binary_search(&newurl) {
            Ok(s) => s,
            Err(_) => return 1,
        };

        self.servers.remove(index);
        //
        // if(vdata) {
        // 	debug!("removed server URL from database '{}': {}",
        // 			db.treename, newurl);
        // 	free(vdata);
        // 	ret = 0;
        // }
        //
        // free(newurl);
        // return ret;
        return 0;
    }

    /// Get a group entry from a package database.
    pub fn alpm_db_get_group(&mut self, name: &String) -> Option<&Group> {
        // if name.len() ==0{
        //     return Err(Error::ALPM_ERR_WRONG_ARGS);
        // }

        return self._alpm_db_get_groupfromcache(name);
    }

    pub fn alpm_db_get_group_mut(&mut self, name: &String) -> Option<&mut Group> {
        // if name.len() ==0{
        //     return Err(Error::ALPM_ERR_WRONG_ARGS);
        // }

        return self._alpm_db_get_groupfromcache_mut(name);
    }

    fn _alpm_db_get_groupfromcache(&mut self, target: &String) -> Option<&Group> {
        if target.len() == 0 {
            return None;
        }

        for info in self._alpm_db_get_groupcache() {
            if info.name == *target {
                return Some(info);
            }
        }

        return None;
    }

    fn _alpm_db_get_groupfromcache_mut(&mut self, target: &String) -> Option<&mut Group> {
        if target.len() == 0 {
            return None;
        }

        for info in self._alpm_db_get_groupcache() {
            if info.name == *target {
                return Some(info);
            }
        }

        return None;
    }

    fn _alpm_db_get_groupcache(&mut self) -> &mut Vec<Group> {
        if self.status.valid {
            unimplemented!();
            // RET_ERR(db->handle, ALPM_ERR_DB_INVALID, NULL);
        }

        if self.status.grpcache {
            self.load_grpcache();
        }

        return &mut self.grpcache;
    }

    /* Returns a new group cache from db.
     */
    fn load_grpcache(&self) -> i32 {
        unimplemented!();
        // alpm_list_t *lp;
        // if(db == NULL) {
        // 	return -1;
        // }
        // debug!("loading group cache for repository '{}'",
        // 		db.treename);
        //
        // for pkg in _alpm_db_get_pkgcache(&self) {
        //     // const alpm_list_t *i;
        //     // Package *pkg = lp->data;
        //
        //     for grpname in alpm_pkg_get_groups(pkg) {
        //         // const char *grpname = i->data;
        //         // alpm_list_t *j;
        //         let grp;
        //         let found = 0;
        //
        //         /* first look through the group cache for a group with this name */
        //         for grp in self.grpcache {
        //             // grp = j->data;
        //
        //             if grp.name == grpname && grp.packages.binary_search_by(|p| pkg == p).is_err() {
        //                 grp.packages.push(pkg);
        //                 found = 1;
        //                 break;
        //             }
        //         }
        //         if found != 0 {
        //             continue;
        //         }
        //         /* we didn't find the group, so create a new one with this name */
        //         let grp = _alpm_group_new(grpname);
        //         // if(!grp) {
        //         // 	free_groupcache(db);
        //         // 	return -1;
        //         // }
        //         grp.packages.push(pkg);
        //         self.grpcache.push(grp);
        //     }
        // }
        //
        // self.status = dbstatus_t::GRPCACHE;
        // return 0;
    }

    /// Get the group cache of a package database.
    pub fn alpm_db_get_groupcache(&mut self) -> &Vec<Group> {
        return self._alpm_db_get_groupcache();
    }

    /// Get the group cache of a package database.
    pub fn alpm_db_get_groupcache_mut(&mut self) -> &mut Vec<Group> {
        return self._alpm_db_get_groupcache();
    }

    pub fn _alpm_db_get_pkgfromcache(&mut self, target: &String) -> Option<Package> {
        let pkgcache = self._alpm_db_get_pkgcache_hash();
        match pkgcache {
            Err(_) => {
                return None;
            }

            Ok(pkgcache) => {
                return Some(pkgcache._alpm_pkghash_find(&target));
            }
        }
    }

    fn _alpm_db_get_pkgcache_hash(&mut self) -> Result<&PackageHash> {
        if !self.status.valid {
            // debug!(
            //     "returning error {} from {} : {}\n",
            //     ALPM_ERR_DB_INVALID,
            //     __func__,
            //     Error::ALPM_ERR_DB_INVALID
            // );
            return Err(Error::ALPM_ERR_DB_INVALID);
            // return None;
        }

        if !self.status.pkgcache {
            if self.load_pkgcache() != 0 {
                /* handle->error set in local/sync-db-populate */
                unimplemented!();
                // return None;
            }
        }
        return Ok(&self.pkgcache);
    }

    fn _alpm_db_get_pkgcache_hash_mut(&mut self) -> Result<&mut PackageHash> {
        if !self.status.valid {
            // debug!(
            //     "returning error {} from {} : {}\n",
            //     ALPM_ERR_DB_INVALID,
            //     __func__,
            //     Error::ALPM_ERR_DB_INVALID
            // );
            return Err(Error::ALPM_ERR_DB_INVALID);
            // return None;
        }

        if !self.status.pkgcache {
            if self.load_pkgcache() != 0 {
                /* handle->error set in local/sync-db-populate */
                unimplemented!();
                // return None;
            }
        }
        return Ok(&mut self.pkgcache);
    }

    /// Returns a new package cache from db.
    /// It frees the cache if it already exists.
    pub fn load_pkgcache(&mut self) -> i32 {
        // _alpm_db_free_pkgcache(db);

        debug!("loading package cache for repository '{}'", self.treename);
        if self.populate().is_err() {
            debug!(
                "failed to load package cache for repository '{}'",
                self.treename
            );
            return -1;
        }
        self.status.pkgcache = true;
        return 0;
    }

    pub fn populate(&mut self) -> Result<()> {
        match self.ops_type {
            db_ops_type::local => self.local_db_populate(),
            _ => unimplemented!(),
        }
    }

    /* Unregister a package database. */
    // int SYMEXPORT alpm_db_unregister(Database *db)
    // {
    // 	int found = 0;
    // 	Handle *handle;
    //
    // 	/* Sanity checks */
    // 	ASSERT(db != NULL, return -1);
    // 	/* Do not unregister a database if a transaction is on-going */
    // 	handle = db->handle;
    // 	handle->pm_errno = ALPM_ERR_OK;
    // 	ASSERT(handle->trans == NULL, RET_ERR(handle, ALPM_ERR_TRANS_NOT_NULL, -1));
    //
    // 	if(db == handle->db_local) {
    // 		handle->db_local = NULL;
    // 		found = 1;
    // 	} else {
    // 		/* Warning : this function shouldn't be used to unregister all sync
    // 		 * databases by walking through the list returned by
    // 		 * alpm_get_syncdbs, because the db is removed from that list here.
    // 		 */
    // 		void *data;
    // 		handle->dbs_sync = alpm_list_remove(handle->dbs_sync,
    // 				db, _alpm_db_cmp, &data);
    // 		if(data) {
    // 			found = 1;
    // 		}
    // 	}
    //
    // 	if(!found) {
    // 		RET_ERR(handle, ALPM_ERR_DB_NOT_FOUND, -1);
    // 	}
    //
    // 	db->ops->unregister(db);
    // 	return 0;
    // }

    /// Check the validity of a database.
    pub fn alpm_db_get_valid(&mut self, handle: &mut Handle) -> Result<bool> {
        self.validate(handle)
    }

    /// Get a package entry from a package database. */
    pub fn alpm_db_get_pkg(&self, name: &String) -> Option<&Package> {
        unimplemented!()
        // Package *pkg;
        // ASSERT(db != NULL, return NULL);
        // db->handle->pm_errno = ALPM_ERR_OK;
        // ASSERT(name != NULL && strlen(name) != 0,
        // 		RET_ERR(db->handle, ALPM_ERR_WRONG_ARGS, NULL));
        //
        // pkg = _alpm_db_get_pkgfromcache(db, name);
        // if(!pkg) {
        // 	RET_ERR(db->handle, ALPM_ERR_PKG_NOT_FOUND, NULL);
        // }
        // return pkg;
    }

    /// Get the package cache of a package database.
    pub fn alpm_db_get_pkgcache(&mut self) -> Result<&Vec<Package>> {
        return self._alpm_db_get_pkgcache();
    }

    /// Get the package cache of a package database.
    pub fn alpm_db_get_pkgcache_mut(&mut self) -> Result<&mut Vec<Package>> {
        return self._alpm_db_get_pkgcache_mut();
    }

    /// Get the name of a package database. */
    pub fn alpm_db_get_name(&self) -> &String {
        return &self.treename;
    }

    /// Get the signature verification level for a database. */
    pub fn alpm_db_get_siglevel(&self) -> SigLevel {
        if self.siglevel.use_default {
            unimplemented!();
        // return self.handle.SigLevel;
        } else {
            return self.siglevel;
        }
    }

    /// Searches a database. */
    // pub fn alpm_db_search(&self, needles: &Vec<Package>) -> alpm_list_t {
    pub fn alpm_db_search(&self, needles: &Vec<String>) -> &Vec<Package> {
        return self._alpm_db_search(needles);
    }

    // pub fn _alpm_db_search(&self, needles: &Vec<Package>) -> alpm_list_t {
    pub fn _alpm_db_search(&self, needles: &Vec<String>) -> &Vec<Package> {
        unimplemented!();
        // 	const alpm_list_t *i, *j, *k;
        // 	alpm_list_t *ret = NULL;
        //
        // 	if(!(db->usage & ALPM_DB_USAGE_SEARCH)) {
        // 		return NULL;
        // 	}
        //
        // 	/* copy the pkgcache- we will free the list var after each needle */
        // 	alpm_list_t *list = alpm_list_copy(_alpm_db_get_pkgcache(db));
        //
        // 	for(i = needles; i; i = i->next) {
        // 		char *targ;
        // 		regex_t reg;
        //
        // 		if(i->data == NULL) {
        // 			continue;
        // 		}
        // 		ret = NULL;
        // 		targ = i->data;
        // 		_alpm_log(db->handle, ALPM_LOG_DEBUG, "searching for target '{}'\n", targ);
        //
        // 		if(regcomp(&reg, targ, REG_EXTENDED | REG_NOSUB | REG_ICASE | REG_NEWLINE) != 0) {
        // 			RET_ERR(db->handle, ALPM_ERR_INVALID_REGEX, NULL);
        // 		}
        //
        // 		for(j = list; j; j = j->next) {
        // 			Package *pkg = j->data;
        // 			const char *matched = NULL;
        // 			const char *name = pkg->name;
        // 			const char *desc = alpm_pkg_get_desc(pkg);
        //
        // 			/* check name as regex AND as plain text */
        // 			if(name && (regexec(&reg, name, 0, 0, 0) == 0 || strstr(name, targ))) {
        // 				matched = name;
        // 			}
        // 			/* check desc */
        // 			else if(desc && regexec(&reg, desc, 0, 0, 0) == 0) {
        // 				matched = desc;
        // 			}
        // 			/* TODO: should we be doing this, and should we print something
        // 			 * differently when we do match it since it isn't currently printed? */
        // 			if(!matched) {
        // 				/* check provides */
        // 				for(k = alpm_pkg_get_provides(pkg); k; k = k->next) {
        // 					alpm_depend_t *provide = k->data;
        // 					if(regexec(&reg, provide->name, 0, 0, 0) == 0) {
        // 						matched = provide->name;
        // 						break;
        // 					}
        // 				}
        // 			}
        // 			if(!matched) {
        // 				/* check groups */
        // 				for(k = alpm_pkg_get_groups(pkg); k; k = k->next) {
        // 					if(regexec(&reg, k->data, 0, 0, 0) == 0) {
        // 						matched = k->data;
        // 						break;
        // 					}
        // 				}
        // 			}
        //
        // 			if(matched != NULL) {
        // 				_alpm_log(db->handle, ALPM_LOG_DEBUG,
        // 						"search target '{}' matched '{}' on package '{}'\n",
        // 						targ, matched, name);
        // 				ret = alpm_list_add(ret, pkg);
        // 			}
        // 		}
        //
        // 		/* Free the existing search list, and use the returned list for the
        // 		 * next needle. This allows for AND-based package searching. */
        // 		alpm_list_free(list);
        // 		list = ret;
        // 		regfree(&reg);
        // 	}
        //
        // 	return ret;
    }

    pub fn _alpm_db_get_pkgcache(&mut self) -> Result<&Vec<Package>> {
        match self._alpm_db_get_pkgcache_hash_mut() {
            Err(e) => Err(e),
            Ok(hash) => Ok(&mut hash.list),
        }
    }

    pub fn _alpm_db_get_pkgcache_mut(&mut self) -> Result<&mut Vec<Package>> {
        match self._alpm_db_get_pkgcache_hash_mut() {
            Err(e) => Err(e),
            Ok(hash) => Ok(&mut hash.list),
        }
    }

    /// Sets the usage bitmask for a repo
    pub fn alpm_db_set_usage(&mut self, usage: DatabaseUsage) {
        self.usage = usage;
    }

    pub fn _alpm_db_path(&mut self) -> Result<String> {
        if self._path == "" {
            panic!("no db path");
        }
        return Ok(self._path.clone());
    }

    pub fn create_path(&mut self, dbpath: &String, dbext: &String) -> Result<()> {
        if self._path == "" {
            // let dbpath = &handle.dbpathhandle;
            if dbpath == "" {
                eprintln!("database path is undefined");
                use self::Error::ALPM_ERR_DB_OPEN;
                return Err(ALPM_ERR_DB_OPEN);
            }

            if self.status.local {
                self._path = format!("{}/{}/", dbpath, self.treename);
            } else {
                /* all sync DBs now reside in the sync/ subdir of the dbpath */
                self._path = format!("{}/sync/{}{}", dbpath, self.treename, dbext);
            }
            debug!(
                "database path for tree {} set to {}",
                self.treename, self._path
            );
        }
        Ok(())
    }

    pub fn _alpm_db_free_pkgcache(&mut self) {
        if !self.status.pkgcache {
            return;
        }
        self.pkgcache = PackageHash::default();
        //
        // 	_alpm_log(db->handle, ALPM_LOG_DEBUG,
        // 			"freeing package cache for repository '{}'\n", db->treename);
        //
        // 	if(db->pkgcache) {
        // 		alpm_list_free_inner(db->pkgcache->list,
        // 				(alpm_list_fn_free)_alpm_pkg_free);
        // 		_alpm_pkghash_free(db->pkgcache);
        // 	}
        self.status.pkgcache = false;

        self.free_groupcache();
    }

    pub fn free_groupcache(&mut self) {
        // 	alpm_list_t *lg;
        //
        // 	if(db == NULL || !(db->status & GRPCACHE)) {
        // 		return;
        // 	}
        //
        // 	_alpm_log(db->handle, ALPM_LOG_DEBUG,
        // 			"freeing group cache for repository '{}'", db->treename);
        //
        // 	for(lg = db->grpcache; lg; lg = lg->next) {
        // 		_alpm_group_free(lg->data);
        // 		lg->data = NULL;
        // 	}
        // 	FREELIST(db->grpcache);
        self.status.grpcache = false;
    }

    pub fn _alpm_db_new(treename: &String, is_local: bool) -> Self {
        let mut db = Self::default();
        db.treename = treename.clone();
        if is_local {
            db.status.local = true;
        } else {
            db.status.local = false;
        }
        db.usage.all = true;

        return db;
    }

    /// Gets the usage bitmask for a repo */
    pub fn alpm_db_get_usage(&self, usage: &mut DatabaseUsage) {
        *usage = self.usage;
    }
}

fn sanitize_url(url: &String) -> String {
    let newurl: String;
    newurl = url.clone();
    /* strip the trailing slash if one exists */
    newurl.trim_right_matches('/');
    return newurl;
}

// void _alpm_db_free(Database *db)
// {
// 	ASSERT(db != NULL, return);
// 	/* cleanup pkgcache */
// 	_alpm_db_free_pkgcache(db);
// 	/* cleanup server list */
// 	FREELIST(db->servers);
// 	FREE(db->_path);
// 	FREE(db->treename);
// 	FREE(db);
//
// 	return;
// }

// int _alpm_db_cmp(const void *d1, const void *d2)
// {
// 	const Database *db1 = d1;
// 	const Database *db2 = d2;
// 	return strcmp(db1->treename, db2->treename);
// }

// /* "duplicate" pkg then add it to pkgcache */
// int _alpm_db_add_pkgincache(Database *db, Package *pkg)
// {
// 	Package *newpkg = NULL;
//
// 	if(db == NULL || pkg == NULL || !(db->status & PKGCACHE)) {
// 		return -1;
// 	}
//
// 	if(_alpm_pkg_dup(pkg, &newpkg)) {
// 		/* we return memory on "non-fatal" error in _alpm_pkg_dup */
// 		_alpm_pkg_free(newpkg);
// 		return -1;
// 	}
//
// 	_alpm_log(db->handle, ALPM_LOG_DEBUG, "adding entry '{}' in '{}' cache",
// 						newpkg->name, db->treename);
// 	if(newpkg->origin == ALPM_PKG_FROM_FILE) {
// 		free(newpkg->origin_data.file);
// 	}
// 	newpkg->origin = (db->status & LOCAL)
// 		? ALPM_PKG_FROM_LOCALDB
// 		: ALPM_PKG_FROM_SYNCDB;
// 	newpkg->origin_data.db = db;
// 	db->pkgcache = _alpm_pkghash_add_sorted(db->pkgcache, newpkg);
//
// 	free_groupcache(db);
//
// 	return 0;
// }

// int _alpm_db_remove_pkgfromcache(Database *db, Package *pkg)
// {
// 	Package *data = NULL;
//
// 	if(db == NULL || pkg == NULL || !(db->status & PKGCACHE)) {
// 		return -1;
// 	}
//
// 	_alpm_log(db->handle, ALPM_LOG_DEBUG, "removing entry '{}' from '{}' cache",
// 						pkg->name, db->treename);
//
// 	db->pkgcache = _alpm_pkghash_remove(db->pkgcache, pkg, &data);
// 	if(data == NULL) {
// 		/* package not found */
// 		_alpm_log(db->handle, ALPM_LOG_DEBUG, "cannot remove entry '{}' from '{}' cache: not found",
// 							pkg->name, db->treename);
// 		return -1;
// 	}
//
// 	_alpm_pkg_free(data);
//
// 	free_groupcache(db);
//
// 	return 0;
// }
