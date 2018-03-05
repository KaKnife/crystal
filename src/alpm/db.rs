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

use super::*;
use std::collections::HashMap;
use std::fs::{create_dir, metadata, read_dir, remove_dir_all, File};
use std::io::{ErrorKind, Write};
use libarchive::reader::{Builder, FileReader, Reader};
use libarchive::archive::{Entry, FileType, ReadCompression, ReadFormat};

// /* libarchive */
// #include <archive.h>
// #include <archive_entry.h>

pub const ALPM_LOCAL_DB_VERSION: usize = 9;
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
pub struct DbStatus {
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
    treename: String,
    _path: String,
    pub pkgcache: HashMap<String, Package>,
    grpcache: Vec<Group>,
    servers: Vec<String>,
    // ops: db_operations,
    ops_type: DbOpsType, //I created this to deturmine if it is local or other stuff

    /* bitfields for validity, local, loaded caches, etc. */
    pub status: DbStatus,
    siglevel: SigLevel,
    usage: DatabaseUsage,
}

#[derive(Debug, Clone)]
pub enum DbOpsType {
    Unknown,
    Local,
    Sync,
}
impl Default for DbOpsType {
    fn default() -> Self {
        DbOpsType::Unknown
    }
}

impl Database {
    pub fn sync_db_validate(&mut self, handle: &Handle) -> Result<bool> {
        if self.status.valid || self.status.missing {
            return Ok(true);
        }
        if self.status.invalid {
            return Err(Error::DatabaseInvalidSig);
        }

        let dbpath = self.path()?;

        /* we can skip any validation if the database doesn't exist */
        if let Err(e) = metadata(&dbpath) {
            match e.kind() {
                ErrorKind::NotFound => {
                    // unimplemented!("DB NOT Found: {}", dbpath);
                    // let event = event_database_missing_t {
                    // 	etype: event_type_t::ALPM_EVENT_DATABASE_MISSING,
                    // 	dbname: self.treename.clone(),
                    // };
                    self.status.exists = false;
                    self.status.missing = true;
                    // EVENT!(handle, &event_t::database_missing(event));
                    self.status.valid = true;
                    self.status.invalid = false;
                    return Ok(true);
                }
                _ => {}
            }
        }

        self.status.exists = true;
        self.status.missing = false;

        /* this takes into account the default verification level if UNKNOWN
         * was assigned to this db */
        let siglevel = self.get_siglevel();

        if siglevel.database {
            let mut ret = 0;
            let mut retry = 1;
            while retry != 0 {
                retry = 0;
                let siglist = SignatureList::default();
                ret = _check_pgp_helper(
                    handle,
                    &dbpath,
                    None,
                    siglevel.database_optional,
                    siglevel.database_marginal_ok,
                    siglevel.database_unknown_ok,
                    &siglist,
                );
                if ret != 0 {
                    retry = _process_siglist(
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
                return Err(Error::DatabaseInvalidSig);
            }
        }

        /* valid: */
        self.status.valid = true;
        self.status.invalid = false;
        Ok(true)
    }

    fn checkdbdir(&self) -> Result<()> {
        let path = self.path()?;
        match metadata(&path) {
            Err(_) => {
                debug!("database dir '{}' does not exist, creating it", path);
                create_dir(&path)?;
            }
            Ok(p) => if !p.is_dir() {
                warn!("removing invalid database: {}", path);
                remove_dir_all(&path)?;
                create_dir(&path)?;
            },
        }
        Ok(())
    }

    fn local_db_prepare(&self, info: &Package) -> Result<()> {
        self.checkdbdir()?;
        let pkgpath = self.local_db_pkgpath(info, &String::new())?;

        if let Err(e) = create_dir(&pkgpath) {
            error!("could not create directory {}: {}", pkgpath, e);
            Err(Error::from(e))
        } else {
            Ok(())
        }
    }

    fn local_db_write(&self, info: &Package, inforeq: i32) -> i32 {
        unimplemented!();
        // 	FILE *fp = NULL;
        // 	mode_t oldmask;
        // 	list_t *lp;
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
        // 		_log(db.handle, ALPM_LOG_DEBUG,
        // 				"writing {}-{} DESC information back to db",
        // 				pkg.get_name(), info.version);
        // 		path = _local_db_pkgpath(db, info, "desc");
        // 		if(!path || (fp = fopen(path, "w")) == NULL) {
        // 			_log(db.handle, ALPM_LOG_ERROR, _("could not open file {}: {}"),
        // 					path, strerror(errno));
        // 			retval = -1;
        // 			free(path);
        // 			goto cleanup;
        // 		}
        // 		free(path);
        // 		fprintf(fp, "%%NAME%%{}"
        // 						"%%VERSION%%{}", pkg.get_name(), info.version);
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
        // 		_log(db->handle, ALPM_LOG_DEBUG,
        // 				"writing {}-{} FILES information back to db",
        // 				info->name, info->version);
        // 		path = _local_db_pkgpath(db, info, "files");
        // 		if(!path || (fp = fopen(path, "w")) == NULL) {
        // 			_log(db->handle, ALPM_LOG_ERROR, _("could not open file {}: {}"),
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
        // 				const file_t *file = info->files.files + i;
        // 				fputs(file->name, fp);
        // 				fputc('', fp);
        // 			}
        // 			fputc('', fp);
        // 		}
        // 		if(info->backup) {
        // 			fputs("%BACKUP%", fp);
        // 			for(lp = info->backup; lp; lp = lp->next) {
        // 				const backup_t *backup = lp->data;
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

    fn local_db_remove(&self, info: &Package) -> i32 {
        unimplemented!();
        // 	int ret = 0;
        // 	DIR *dirp;
        // 	struct dirent *dp;
        // 	char *pkgpath;
        // 	size_t pkgpath_len;
        //
        // 	pkgpath = _local_db_pkgpath(db, info, NULL);
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

    fn load_pkg_for_entry(
        &mut self,
        entryname: &String,
        entry_filename: &mut String,
    ) -> Option<&mut Package> {
        /* get package and db file names */
        *entry_filename = entryname.split('/').last().unwrap_or(entryname).to_string();
        let (pkgname, pkgver) = if let Ok(d) = _splitname(entryname) {
            d
        } else {
            error!("invalid name for database entry '{}'", entryname);
            return None;
        };

        if self.pkgcache.get(&pkgname).is_none() {
            let mut tmp_pkg = Package::default();

            tmp_pkg.set_name(&pkgname);
            tmp_pkg.set_version(pkgver);
            tmp_pkg.set_origin(PackageFrom::SyncDatabase);

            // tmp_pkg.origin_data.db = db;
            // tmp_pkg.ops = &default_pkg_ops;
            // tmp_pkg.ops.get_validation = _sync_get_validation;

            /* add to the collection */
            debug!(
                "adding '{}' to package cache for db '{}'",
                tmp_pkg.get_name(),
                self.treename
            );
            self.pkgcache.insert(pkgname.clone(), tmp_pkg);
        }
        self.pkgcache.get_mut(&pkgname)
    }

    fn sync_db_read(&mut self, entryname: &str, archive: &FileReader) -> i32 {
        let mut entryname = entryname.to_string();
        let mut filename: String = String::new();
        let dbname = self.treename.clone();
        let mut pkg;

        debug!("loading package data from archive entry {}", entryname);

        pkg = if let Some(p) = self.load_pkg_for_entry(&mut entryname, &mut filename) {
            p
        } else {
            debug!(
                "entry {} could not be loaded into {} sync database",
                entryname, dbname
            );
            return -1;
        };

        if filename == "" {
            /* A file exists outside of a subdirectory. This isn't a read error, so return
             * success and try to continue on. */
            warn!("unknown database file: {}", filename);
            return 0;
        }

        if filename == "desc" || filename == "depends" || filename == "files"
        /*|| (filename== "deltas" && db->handle->deltaratio > 0.0)*/
        {
            let mut lines = Vec::new();
            while let Ok(Some(line)) = archive.read_block() {
                lines.push(String::from_utf8_lossy(line).to_string());
            }
            pkg.parse_lines(lines.iter().map(|line| line.as_ref()).collect(), &dbname);
            pkg.infolevel = INFRQ_ALL;
        } else if filename == "deltas" {
            // 		/* skip reading delta files if UseDelta is unset */
        } else {
            // 		/* unknown database file */
            // 		_log(db->handle, ALPM_LOG_DEBUG, "unknown database file: %s\n", filename);
        }

        return 0;
        // error:
        // 	_log(db->handle, ALPM_LOG_DEBUG, "error parsing database file: %s\n", filename);
        // 	return -1;
    }

    fn sync_db_populate(&mut self) -> Result<()> {
        // 	const char *dbpath;
        // 	int fd;
        let mut ret = Ok(());
        let mut fd;
        let mut builder;
        let dbpath;
        // 	int archive_ret;
        // 	struct stat buf;
        // 	struct archive *archive;
        // 	struct archive_entry *entry;
        // 	pkg_t *pkg = NULL;

        if self.status.invalid {
            return Err(Error::DatabaseInvalid);
        }
        if self.status.missing {
            return Err(Error::DatabaseNotFound);
        }
        dbpath = self.path()?;

        builder = Builder::new();
        builder.support_compression(ReadCompression::All);
        builder.support_format(ReadFormat::All);
        fd = match builder.open_file(&dbpath) {
            Ok(fd) => fd,
            Err(e) => unimplemented!("{} : {}", dbpath, e),
        };

        loop {
            let entryname;
            {
                match fd.next_header() {
                    Some(entry) => {
                        entryname = entry.pathname().to_string();
                        match entry.filetype() {
                            FileType::Directory => continue,
                            _ => {}
                        }
                    }
                    None => break,
                }
            }
            /* we have desc, depends or deltas - parse it */
            if self.sync_db_read(&entryname, &fd) != 0 {
                error!(
                    "could not parse package description file '{}' from db '{}'",
                    entryname, self.treename
                );
                ret = Err(Error::Other);
            }
        }

        debug!(
            "added {} packages to package cache for db '{}'",
            self.pkgcache.len(),
            self.get_name()
        );

        // cleanup:
        ret
    }

    /*True Mut*/
    fn local_db_populate(&mut self) -> Result<()> {
        use std::fs;
        let mut count = 0;
        let dbdir;
        let dbpath;

        if self.status.invalid {
            return Err(Error::DatabaseInvalid);
        }
        if self.status.missing {
            return Err(Error::DatabaseNotFound);
        }

        dbpath = self.path()?;

        dbdir = if let Ok(d) = fs::read_dir(dbpath) {
            d
        } else {
            return Err(Error::DatabaseOpen);
        };
        self.status.exists = true;
        self.status.missing = false;
        self.pkgcache = HashMap::new();

        for ent in dbdir {
            if let Ok(ent) = ent {
                let mut pkg;
                let name = ent.file_name().into_string()?;

                if name == "." || name == ".." {
                    continue;
                }
                if let Ok(m) = fs::metadata(ent.path()) {
                    if !m.is_dir() {
                        continue;
                    }
                }

                pkg = Package::default();
                /* split the db entry name */
                let (name, version) = if let Ok(d) = _splitname(&name) {
                    d
                } else {
                    error!("invalid name for database entry '{}'", name);
                    continue;
                };
                pkg.set_name(&name);
                pkg.set_version(version);

                /* duplicated database entries are not allowed */
                // 		if(_pkghash_find(db->pkgcache, pkg->name)) {
                // 			_log(db->handle, ALPM_LOG_ERROR, _("duplicated database entry '{}'"), pkg->name);
                // 			_pkg_free(pkg);
                // 			continue;
                // 		}

                pkg.set_origin(PackageFrom::LocalDatabase);

                if pkg.local_db_read(self, INFRQ_ALL).is_err() {
                    debug!("corrupted database entry '{}'", name);
                    continue;
                }

                /* add to the collection */
                debug!(
                    "adding '{}' to package cache for db '{}'",
                    pkg.get_name(),
                    self.treename
                );
                self.pkgcache.insert(pkg.get_name().clone(), pkg);
                count += 1;
            }
        }

        debug!(
            "added {} packages to package cache for db '{}'",
            count, self.treename
        );
        Ok(())
    }

    /*True Mut*/
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

        dbpath = self.path()?;

        dbdir = match read_dir(&dbpath) {
            Ok(d) => d,
            Err(e) => {
                match e.kind() {
                    ErrorKind::NotFound => {
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
                        return Err(Error::DatabaseOpen);
                    }
                }
            }
        };
        self.status.exists = true;
        self.status.missing = false;

        dbverpath = format!("{}ALPM_DB_VERSION", dbpath);

        dbverfile = if let Ok(f) = File::open(&dbverpath) {
            f
        } else {
            /* create dbverfile if local database is empty - otherwise version error */
            for ent in dbdir {
                if let Ok(ent) = ent {
                    let name = &ent.file_name();
                    if name == "." || name == ".." {
                        continue;
                    } else {
                        self.status.valid = false;
                        self.status.invalid = true;
                        return Err(Error::DatabaseVersion);
                    }
                }
            }

            if self.local_db_add_version(&dbpath).is_err() {
                self.status.valid = false;
                self.status.invalid = true;
                return Err(Error::DatabaseVersion);
            }

            self.status.valid = true;
            self.status.invalid = false;
            return Ok(true);
        };

        use std::io::Read;
        let mut dbverfilestr = String::new();
        dbverfile.read_to_string(&mut dbverfilestr)?;
        dbverfilestr = dbverfilestr.trim().to_string();
        version = if let Ok(v) = dbverfilestr.parse() {
            v
        } else {
            self.status.valid = false;
            self.status.invalid = true;
            return Err(Error::DatabaseVersion);
        };

        if version != ALPM_LOCAL_DB_VERSION {
            self.status.valid = false;
            self.status.invalid = true;
            return Err(Error::DatabaseVersion);
        }

        self.status.valid = true;
        self.status.invalid = false;
        Ok(true)
    }

    fn local_db_create(&self, dbpath: &String) -> Result<i32> {
        if let Err(e) = create_dir(dbpath) {
            error!("could not create directory {}: {}", dbpath, e);
            return Err(Error::DatabaseCreate);
        }
        if self.local_db_add_version(dbpath).is_err() {
            // return 1;
            unimplemented!();
        }
        Ok(0)
    }

    fn local_db_add_version(&self, dbpath: &String) -> Result<usize> {
        let dbverpath = format!("{}ALPM_DB_VERSION", dbpath);
        let mut dbverfile = File::create(dbverpath)?;
        let data = format!("{}", ALPM_LOCAL_DB_VERSION);
        Ok(dbverfile.write(data.as_bytes())?)
    }

    /* Note: the return value must be freed by the caller */
    pub fn local_db_pkgpath(&self, pkg: &Package, filename: &String) -> Result<String> {
        let pkgpath: String;
        let dbpath: String;

        dbpath = self.path()?;
        pkgpath = format!(
            "{}{}-{}/{}",
            dbpath,
            pkg.get_name(),
            pkg.get_version(),
            filename
        );
        Ok(pkgpath)
    }

    fn validate(&mut self, handle: &Handle) -> Result<bool> {
        match self.ops_type {
            DbOpsType::Local => self.local_db_validate(),
            DbOpsType::Sync => self.sync_db_validate(handle),
            DbOpsType::Unknown => unimplemented!(),
        }
    }

    /// Get the serverlist of a database.
    pub fn get_servers(&self) -> &Vec<String> {
        &self.servers
    }

    /// Set the serverlist of a database.
    fn set_servers(&mut self, servers: Vec<String>) {
        self.servers = servers;
    }

    /// Add a download server to a database.
    /// db database pointer
    /// url url of the server
    /// return - 0 on success, -1 on error (pm_errno is set accordingly)
    pub fn add_server(&mut self, url: &String) -> Result<()> {
        let newurl;

        /* Sanity checks */
        if url.len() == 0 {
            return Err(Error::WrongArgs);
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
    fn remove_server(&mut self, url: &String) -> i32 {
        let newurl = sanitize_url(url);

        if let Ok(index) = self.servers.binary_search(&newurl) {
            self.servers.remove(index);
            debug!(
                "removed server URL from database '{}': {}",
                self.treename, newurl
            );
            0
        } else {
            1
        }
    }

    /// Get a group entry from a package database.
    pub fn get_group(&self, name: &String) -> Result<&Group> {
        self.get_groupfromcache(name)
    }

    pub fn get_group_mut(&mut self, name: &String) -> Result<&mut Group> {
        self.get_groupfromcache_mut(name)
    }

    fn get_groupfromcache(&self, target: &String) -> Result<&Group> {
        for grp in self.get_groupcache() {
            if grp.name == *target {
                return Ok(grp);
            }
        }

        Err(Error::GroupNotFound)
    }

    fn get_groupfromcache_mut(&mut self, target: &String) -> Result<&mut Group> {
        for info in self.get_groupcache_mut() {
            if info.name == *target {
                return Ok(info);
            }
        }

        Err(Error::GroupNotFound)
    }

    /// Get the group cache of a package database.
    pub fn get_groupcache_mut(&mut self) -> &mut Vec<Group> {
        if self.status.valid {
            unimplemented!();
            // RET_ERR(db->handle, DatabaseNotInvalid, NULL);
        }

        if self.status.grpcache {
            self.load_grpcache();
        }

        &mut self.grpcache
    }

    /// Returns a new group cache from db.
    fn load_grpcache(&self) -> i32 {
        unimplemented!();
        // list_t *lp;
        // if(db == NULL) {
        // 	return -1;
        // }
        // debug!("loading group cache for repository '{}'",
        // 		db.treename);
        //
        // for pkg in _db_get_pkgcache(&self) {
        //     // const list_t *i;
        //     // Package *pkg = lp->data;
        //
        //     for grpname in pkg_get_groups(pkg) {
        //         // const char *grpname = i->data;
        //         // list_t *j;
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
        //         let grp = _group_new(grpname);
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
    pub fn get_groupcache(&self) -> &Vec<Group> {
        if self.status.valid {
            unimplemented!();
            // RET_ERR(db->handle, DatabaseNotInvalid, NULL);
        }

        if self.status.grpcache {
            self.load_grpcache();
        }

        &self.grpcache
    }

    pub fn get_pkgfromcache(&self, target: &String) -> Result<&Package> {
        let pkgcache = self.get_pkgcache_hash()?;
        match pkgcache.get(target) {
            None => Err(Error::PkgNotFound),
            Some(pkg) => Ok(pkg),
        }
    }

    fn get_pkgcache_hash(&self) -> Result<&HashMap<String, Package>> {
        if !self.status.valid {
            Err(Error::DatabaseInvalid)
        } else if !self.status.pkgcache {
            Err(Error::PkgCacheNotLoaded)
        } else {
            Ok(&self.pkgcache)
        }
    }

    /// Returns a new package cache from db.
    /// It frees the cache if it already exists.
    pub fn load_pkgcache(&mut self) -> i32 {
        debug!("loading package cache for repository '{}'", self.treename);
        if self.populate().is_err() {
            debug!(
                "failed to load package cache for repository '{}'",
                self.treename
            );
            return -1;
        }
        self.status.pkgcache = true;
        0
    }

    pub fn populate(&mut self) -> Result<()> {
        match self.ops_type {
            DbOpsType::Local => self.local_db_populate(),
            DbOpsType::Sync => self.sync_db_populate(),
            _ => unimplemented!(),
        }
    }

    /// Check the validity of a database.
    pub fn get_valid(&mut self, handle: &mut Handle) -> Result<bool> {
        self.validate(handle)
    }

    /// Get a package entry from a package database. */
    pub fn get_pkg(&self, name: &String) -> Result<&Package> {
        let pkg = self.get_pkgfromcache(name);
        if pkg.is_err() {
            Err(Error::PkgNotFound)
        } else {
            pkg
        }
    }

    /// Get a package entry from a package database. */
    pub fn get_pkg_mut(&mut self, name: &String) -> Option<&mut Package> {
        unimplemented!()
        // Package *pkg;
        // ASSERT(db != NULL, return NULL);
        // db->handle->pm_errno = ALPM_ERR_OK;
        // ASSERT(name != NULL && strlen(name) != 0,
        // 		RET_ERR(db->handle, WrongArgs, NULL));
        //
        // pkg = _db_get_pkgfromcache(db, name);
        // if(!pkg) {
        // 	RET_ERR(db->handle, ALPM_ERR_PKG_NOT_FOUND, NULL);
        // }
        // return pkg;
    }

    /// Get the name of a package database. */
    pub fn get_name(&self) -> &String {
        return &self.treename;
    }

    /// Get the signature verification level for a database. */
    pub fn get_siglevel(&self) -> SigLevel {
        if self.siglevel.use_default {
            unimplemented!();
        // return self.handle.SigLevel;
        } else {
            return self.siglevel;
        }
    }

    pub fn set_siglevel(&mut self, level: SigLevel) {
        self.siglevel = level;
    }

    /// Searches a database.
    // pub fn db_search(&self, needles: &Vec<Package>) -> list_t {
    pub fn search(&self, needles: &Vec<String>) -> &Vec<&Package> {
        unimplemented!();
        // 	const list_t *i, *j, *k;
        // 	list_t *ret = NULL;
        //
        // 	if(!(db->usage & ALPM_DB_USAGE_SEARCH)) {
        // 		return NULL;
        // 	}
        //
        // 	/* copy the pkgcache- we will free the list var after each needle */
        // 	list_t *list = list_copy(_db_get_pkgcache(db));
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
        // 		_log(db->handle, ALPM_LOG_DEBUG, "searching for target '{}'\n", targ);
        //
        // 		if(regcomp(&reg, targ, REG_EXTENDED | REG_NOSUB | REG_ICASE | REG_NEWLINE) != 0) {
        // 			RET_ERR(db->handle, ALPM_ERR_INVALID_REGEX, NULL);
        // 		}
        //
        // 		for(j = list; j; j = j->next) {
        // 			Package *pkg = j->data;
        // 			const char *matched = NULL;
        // 			const char *name = pkg->name;
        // 			const char *desc = pkg_get_desc(pkg);
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
        // 				for(k = pkg_get_provides(pkg); k; k = k->next) {
        // 					depend_t *provide = k->data;
        // 					if(regexec(&reg, provide->name, 0, 0, 0) == 0) {
        // 						matched = provide->name;
        // 						break;
        // 					}
        // 				}
        // 			}
        // 			if(!matched) {
        // 				/* check groups */
        // 				for(k = pkg_get_groups(pkg); k; k = k->next) {
        // 					if(regexec(&reg, k->data, 0, 0, 0) == 0) {
        // 						matched = k->data;
        // 						break;
        // 					}
        // 				}
        // 			}
        //
        // 			if(matched != NULL) {
        // 				_log(db->handle, ALPM_LOG_DEBUG,
        // 						"search target '{}' matched '{}' on package '{}'\n",
        // 						targ, matched, name);
        // 				ret = list_add(ret, pkg);
        // 			}
        // 		}
        //
        // 		/* Free the existing search list, and use the returned list for the
        // 		 * next needle. This allows for AND-based package searching. */
        // 		list_free(list);
        // 		list = ret;
        // 		regfree(&reg);
        // 	}
        //
        // 	return ret;
    }

    /// Get the package cache of a package database.
    pub fn get_pkgcache(&self) -> Result<Vec<&Package>> {
        let mut cache: Vec<&Package> = self.get_pkgcache_hash()?.values().collect();
        cache.sort();
        Ok(cache)
    }

    /// Sets the usage of a database.
    pub fn set_usage(&mut self, usage: DatabaseUsage) {
        self.usage = usage;
    }

    pub fn path(&self) -> Result<String> {
        if self._path == "" {
            Err(Error::NoDbPath)
        } else {
            Ok(self._path.clone())
        }
    }

    pub fn create_path(&mut self, dbpath: &String, dbext: &String) -> Result<()> {
        if self._path == "" {
            // let dbpath = &handle.dbpathhandle;
            if dbpath == "" {
                error!("database path is undefined");
                return Err(Error::DatabaseOpen);
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

    pub fn free_pkgcache(&mut self) {
        if !self.status.pkgcache {
            return;
        }
        self.pkgcache = HashMap::new();
        debug!("freeing package cache for repository '{}'", self.treename);
        self.status.pkgcache = false;
        self.free_groupcache();
    }

    pub fn free_groupcache(&mut self) {
        if self.status.grpcache {
            debug!("freeing group cache for repository '{}'", self.treename);
            self.status.grpcache = false;
        }
    }

    pub fn new(treename: &String, is_local: bool, op_type: DbOpsType) -> Self {
        let mut db = Self::default();
        db.treename = treename.clone();
        if is_local {
            db.status.local = true;
        } else {
            db.status.local = false;
        }
        db.usage.set_all();
        db.ops_type = op_type;
        return db;
    }

    /// Gets the usage bitmask for a repo */
    pub fn get_usage(&self) -> &DatabaseUsage {
        &self.usage
    }

    /// Gets the usage bitmask for a repo */
    pub fn get_usage_mut(&mut self) -> &mut DatabaseUsage {
        &mut self.usage
    }
}

fn sanitize_url(url: &String) -> String {
    let newurl: String;
    newurl = url.clone();
    /* strip the trailing slash if one exists */
    newurl.trim_right_matches('/');
    return newurl;
}

// void _db_free(Database *db)
// {
// 	ASSERT(db != NULL, return);
// 	/* cleanup pkgcache */
// 	_db_free_pkgcache(db);
// 	/* cleanup server list */
// 	FREELIST(db->servers);
// 	FREE(db->_path);
// 	FREE(db->treename);
// 	FREE(db);
//
// 	return;
// }

// int _db_cmp(const void *d1, const void *d2)
// {
// 	const Database *db1 = d1;
// 	const Database *db2 = d2;
// 	return strcmp(db1->treename, db2->treename);
// }

// /* "duplicate" pkg then add it to pkgcache */
// int _db_add_pkgincache(Database *db, Package *pkg)
// {
// 	Package *newpkg = NULL;
//
// 	if(db == NULL || pkg == NULL || !(db->status & PKGCACHE)) {
// 		return -1;
// 	}
//
// 	if(_pkg_dup(pkg, &newpkg)) {
// 		/* we return memory on "non-fatal" error in _pkg_dup */
// 		_pkg_free(newpkg);
// 		return -1;
// 	}
//
// 	_log(db->handle, ALPM_LOG_DEBUG, "adding entry '{}' in '{}' cache",
// 						newpkg->name, db->treename);
// 	if(newpkg->origin == ALPM_PKG_FROM_FILE) {
// 		free(newpkg->origin_data.file);
// 	}
// 	newpkg->origin = (db->status & LOCAL)
// 		? LocalDatabase
// 		: SyncDatabase;
// 	newpkg->origin_data.db = db;
// 	db->pkgcache = _pkghash_add_sorted(db->pkgcache, newpkg);
//
// 	free_groupcache(db);
//
// 	return 0;
// }

// int _db_remove_pkgfromcache(Database *db, Package *pkg)
// {
// 	Package *data = NULL;
//
// 	if(db == NULL || pkg == NULL || !(db->status & PKGCACHE)) {
// 		return -1;
// 	}
//
// 	_log(db->handle, ALPM_LOG_DEBUG, "removing entry '{}' from '{}' cache",
// 						pkg->name, db->treename);
//
// 	db->pkgcache = _pkghash_remove(db->pkgcache, pkg, &data);
// 	if(data == NULL) {
// 		/* package not found */
// 		_log(db->handle, ALPM_LOG_DEBUG, "cannot remove entry '{}' from '{}' cache: not found",
// 							pkg->name, db->treename);
// 		return -1;
// 	}
//
// 	_pkg_free(data);
//
// 	free_groupcache(db);
//
// 	return 0;
// }
