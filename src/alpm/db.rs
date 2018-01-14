use super::*;
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
/* Database entries */
// pub enum alpm_dbinfrq_t {
pub const INFRQ_BASE: i32 = (1 << 0);
pub const INFRQ_DESC: i32 = (1 << 1);
pub const INFRQ_FILES: i32 = (1 << 2);
pub const INFRQ_SCRIPTLET: i32 = (1 << 3);
pub const INFRQ_DSIZE: i32 = (1 << 4);
/* ALL should be info stored in the package or database */
pub const INFRQ_ALL: i32 = INFRQ_BASE | INFRQ_DESC | INFRQ_FILES | INFRQ_SCRIPTLET | INFRQ_DSIZE;
pub const INFRQ_ERROR: i32 = (1 << 30);
// }

/// Database status. Bitflags. */
#[derive(Debug, Clone, Default)]
pub struct alpm_dbstatus_t {
    pub DB_STATUS_VALID: bool,
    pub DB_STATUS_INVALID: bool,
    pub DB_STATUS_EXISTS: bool,
    pub DB_STATUS_MISSING: bool,

    pub DB_STATUS_LOCAL: bool,
    pub DB_STATUS_PKGCACHE: bool,
    pub DB_STATUS_GRPCACHE: bool,
}

// impl Default for alpm_dbstatus_t {
//     fn default() -> Self {
//         alpm_dbstatus_t::DB_STATUS_VALID
//     }
// }

// struct db_operations {
//     validate: &Fn(&alpm_db_t) -> i32,
//     populate: Fn(&alpm_db_t) -> i32,
//     unregister: Fn(&alpm_db_t),
// }

/// Database
#[derive(Debug, Default, Clone)]
pub struct alpm_db_t {
    // handle: alpm_handle_t,
    pub treename: String,
    /// do not access directly, use _alpm_db_path(db) for lazy access
    pub _path: String,
    pub pkgcache: alpm_pkghash_t,
    grpcache: Vec<alpm_group_t>,
    pub servers: Vec<String>,
    // ops: db_operations,
    pub ops_type: db_ops_type, //I created this to deturmine if it is local or other stuff

    /* bitfields for validity, local, loaded caches, etc. */
    pub status: alpm_dbstatus_t,
    pub siglevel: siglevel,
    pub usage: alpm_db_usage_t,
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

/*
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

impl alpm_db_t {
    fn validate(&mut self, handle: &alpm_handle_t) -> Result<bool> {
        match self.ops_type {
            db_ops_type::local => self.local_db_validate(handle),
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
            return Err(alpm_errno_t::ALPM_ERR_WRONG_ARGS);
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
        // self.handle.pm_errno = alpm_errno_t::ALPM_ERR_OK;
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

    /// Get a group entry from a package database. */
    pub fn alpm_db_get_group(&self, name: &String) -> Option<&alpm_group_t> {
        // if name.len() ==0{
        //     return Err(alpm_errno_t::ALPM_ERR_WRONG_ARGS);
        // }

        return self._alpm_db_get_groupfromcache(name);
    }

    fn _alpm_db_get_groupfromcache(&self, target: &String) -> Option<&alpm_group_t> {
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

    fn _alpm_db_get_groupcache(&self) -> &Vec<alpm_group_t> {
        if self.status.DB_STATUS_VALID {
            unimplemented!();
            // RET_ERR(db->handle, ALPM_ERR_DB_INVALID, NULL);
        }

        if self.status.DB_STATUS_GRPCACHE {
            self.load_grpcache();
        }

        return &self.grpcache;
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
        //     // alpm_pkg_t *pkg = lp->data;
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
        // self.status = alpm_dbstatus_t::DB_STATUS_GRPCACHE;
        // return 0;
    }

    /// Get the group cache of a package database. */
    pub fn alpm_db_get_groupcache(&mut self) -> &Vec<alpm_group_t> {
        // ASSERT(db != NULL, return NULL);
        // self.handle.pm_errno = alpm_errno_t::ALPM_ERR_OK;

        return self._alpm_db_get_groupcache();
    }

    pub fn _alpm_db_get_pkgfromcache(&mut self, target: &String) -> Option<alpm_pkg_t> {
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

    fn _alpm_db_get_pkgcache_hash(&mut self) -> Result<&alpm_pkghash_t> {
        if !self.status.DB_STATUS_VALID {
            // debug!(
            //     "returning error {} from {} : {}\n",
            //     ALPM_ERR_DB_INVALID,
            //     __func__,
            //     alpm_errno_t::ALPM_ERR_DB_INVALID
            // );
            return Err(alpm_errno_t::ALPM_ERR_DB_INVALID);
            // return None;
        }

        if !self.status.DB_STATUS_PKGCACHE {
            if self.load_pkgcache() != 0 {
                /* handle->error set in local/sync-db-populate */
                unimplemented!();
                // return None;
            }
        }
        return Ok(&self.pkgcache);
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
        self.status.DB_STATUS_PKGCACHE = true;
        return 0;
    }

    pub fn populate(&mut self) -> Result<()> {
        match self.ops_type {
            db_ops_type::local => self.local_db_populate(),
            _ => unimplemented!(),
        }
    }

    /* Unregister a package database. */
    // int SYMEXPORT alpm_db_unregister(alpm_db_t *db)
    // {
    // 	int found = 0;
    // 	alpm_handle_t *handle;
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
    pub fn alpm_db_get_valid(&mut self, handle: &mut alpm_handle_t) -> Result<bool> {
        self.validate(handle)
    }

    /// Get a package entry from a package database. */
    pub fn alpm_db_get_pkg(&self, name: &String) -> Option<alpm_pkg_t> {
        unimplemented!()
        // alpm_pkg_t *pkg;
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

    /// Get the package cache of a package database. */
    pub fn alpm_db_get_pkgcache(&mut self) -> Result<&Vec<alpm_pkg_t>> {
        return self._alpm_db_get_pkgcache();
    }

    /// Get the name of a package database. */
    pub fn alpm_db_get_name(&self) -> &String {
        return &self.treename;
    }

    /// Get the signature verification level for a database. */
    pub fn alpm_db_get_siglevel(&self) -> siglevel {
        if self.siglevel.ALPM_SIG_USE_DEFAULT {
            unimplemented!();
        // return self.handle.siglevel;
        } else {
            return self.siglevel;
        }
    }

    /// Searches a database. */
    // pub fn alpm_db_search(&self, needles: &Vec<alpm_pkg_t>) -> alpm_list_t {
    pub fn alpm_db_search(&self, needles: &Vec<String>) -> &alpm_list_t<alpm_pkg_t> {
        return self._alpm_db_search(needles);
    }

    // pub fn _alpm_db_search(&self, needles: &Vec<alpm_pkg_t>) -> alpm_list_t {
    pub fn _alpm_db_search(&self, needles: &Vec<String>) -> &alpm_list_t<alpm_pkg_t> {
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
        // 			alpm_pkg_t *pkg = j->data;
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

    pub fn _alpm_db_get_pkgcache(&mut self) -> Result<&Vec<alpm_pkg_t>> {
        match self._alpm_db_get_pkgcache_hash() {
            Err(e) => Err(e),
            Ok(hash) => Ok(&hash.list),
        }
    }

    /// Sets the usage bitmask for a repo
    pub fn alpm_db_set_usage(&mut self, usage: alpm_db_usage_t) {
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
                use self::alpm_errno_t::ALPM_ERR_DB_OPEN;
                return Err(ALPM_ERR_DB_OPEN);
            }

            if self.status.DB_STATUS_LOCAL {
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
        if !self.status.DB_STATUS_PKGCACHE {
            return;
        }
        self.pkgcache = alpm_pkghash_t::default();
        //
        // 	_alpm_log(db->handle, ALPM_LOG_DEBUG,
        // 			"freeing package cache for repository '{}'\n", db->treename);
        //
        // 	if(db->pkgcache) {
        // 		alpm_list_free_inner(db->pkgcache->list,
        // 				(alpm_list_fn_free)_alpm_pkg_free);
        // 		_alpm_pkghash_free(db->pkgcache);
        // 	}
        self.status.DB_STATUS_PKGCACHE = false;

        self.free_groupcache();
    }

    pub fn free_groupcache(&mut self) {
        // 	alpm_list_t *lg;
        //
        // 	if(db == NULL || !(db->status & DB_STATUS_GRPCACHE)) {
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
        self.status.DB_STATUS_GRPCACHE = false;
    }

    pub fn _alpm_db_new(treename: &String, is_local: bool) -> Self {
        let mut db = Self::default();
        db.treename = treename.clone();
        if is_local {
            db.status.DB_STATUS_LOCAL = true;
        } else {
            db.status.DB_STATUS_LOCAL = false;
        }
        db.usage.ALPM_DB_USAGE_ALL = true;

        return db;
    }

    /// Gets the usage bitmask for a repo */
    pub fn alpm_db_get_usage(&self, usage: &mut alpm_db_usage_t) {
        *usage = self.usage;
    }
}

impl alpm_handle_t {
    /// Unregister all package databases. */
    pub fn alpm_unregister_all_syncdbs(&self) -> i32 {
        unimplemented!();
        // 	alpm_list_t *i;
        // 	alpm_db_t *db;
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

    /// Register a sync database of packages. */
    pub fn alpm_register_syncdb(
        &mut self,
        treename: &String,
        siglevel: siglevel,
    ) -> Result<alpm_db_t> {
        /* ensure database name is unique */
        if treename == "local" {
            return Err(alpm_errno_t::ALPM_ERR_DB_NOT_NULL);
        }
        for d in &self.dbs_sync {
            if treename == &d.treename {
                return Err(alpm_errno_t::ALPM_ERR_DB_NOT_NULL);
            }
        }

        Ok(self._alpm_db_register_sync(&treename, siglevel))
    }
}

fn sanitize_url(url: &String) -> String {
    let newurl: String;
    newurl = url.clone();
    /* strip the trailing slash if one exists */
    newurl.trim_right_matches('/');
    return newurl;
}

// void _alpm_db_free(alpm_db_t *db)
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
// 	const alpm_db_t *db1 = d1;
// 	const alpm_db_t *db2 = d2;
// 	return strcmp(db1->treename, db2->treename);
// }

// /* "duplicate" pkg then add it to pkgcache */
// int _alpm_db_add_pkgincache(alpm_db_t *db, alpm_pkg_t *pkg)
// {
// 	alpm_pkg_t *newpkg = NULL;
//
// 	if(db == NULL || pkg == NULL || !(db->status & DB_STATUS_PKGCACHE)) {
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
// 	newpkg->origin = (db->status & DB_STATUS_LOCAL)
// 		? ALPM_PKG_FROM_LOCALDB
// 		: ALPM_PKG_FROM_SYNCDB;
// 	newpkg->origin_data.db = db;
// 	db->pkgcache = _alpm_pkghash_add_sorted(db->pkgcache, newpkg);
//
// 	free_groupcache(db);
//
// 	return 0;
// }

// int _alpm_db_remove_pkgfromcache(alpm_db_t *db, alpm_pkg_t *pkg)
// {
// 	alpm_pkg_t *data = NULL;
//
// 	if(db == NULL || pkg == NULL || !(db->status & DB_STATUS_PKGCACHE)) {
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
