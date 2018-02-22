use super::*;
/*
 *  deps.c
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

// #include <stdlib.h>
// #include <stdio.h>
// #include <string.h>
//
// /* libalpm */
// #include "deps.h"
// #include "alpm_list.h"
// #include "util.h"
// #include "log.h"
// #include "graph.h"
// #include "package.h"
// #include "db.h"
// #include "handle.h"
// #include "trans.h"

// void SYMEXPORT alpm_dep_free(Dependency *dep)
// {
// 	ASSERT(dep != NULL, return);
// 	FREE(dep->name);
// 	FREE(dep->version);
// 	FREE(dep->desc);
// 	FREE(dep);
// }
//
// static alpm_depmissing_t *depmiss_new(const char *target, Dependency *dep,
// 		const char *causingpkg)
// {
// 	alpm_depmissing_t *miss;
//
// 	CALLOC(miss, 1, sizeof(alpm_depmissing_t), return NULL);
//
// 	STRDUP(miss->target, target, goto error);
// 	miss->depend = _alpm_dep_dup(dep);
// 	STRDUP(miss->causingpkg, causingpkg, goto error);
//
// 	return miss;
//
// error:
// 	alpm_depmissing_free(miss);
// 	return NULL;
// }
//
// void SYMEXPORT alpm_depmissing_free(alpm_depmissing_t *miss)
// {
// 	ASSERT(miss != NULL, return);
// 	alpm_dep_free(miss->depend);
// 	FREE(miss->target);
// 	FREE(miss->causingpkg);
// 	FREE(miss);
// }
//
// /** Check if pkg2 satisfies a dependency of pkg1 */
// static int _alpm_pkg_depends_on(Package *pkg1, Package *pkg2)
// {
// 	alpm_list_t *i;
// 	for(i = alpm_pkg_get_depends(pkg1); i; i = i->next) {
// 		if(_alpm_depcmp(pkg2, i->data)) {
// 			return 1;
// 		}
// 	}
// 	return 0;
// }

pub fn find_dep_satisfier<'a>(pkgs: &'a Vec<Package>, dep: &Dependency) -> Option<&'a Package> {
    // alpm_list_t *i;

    for pkg in pkgs {
        // Package *pkg = i->data;
        if pkg.depcmp(dep) {
            return Some(pkg);
        }
    }
    return None;
}

// /* Convert a list of Package * to a graph structure,
//  * with a edge for each dependency.
//  * Returns a list of vertices (one vertex = one package)
//  * (used by alpm_sortbydeps)
//  */
// static alpm_list_t *dep_graph_init(Handle *handle,
// 		alpm_list_t *targets, alpm_list_t *ignore)
// {
// 	alpm_list_t *i, *j;
// 	alpm_list_t *vertices = NULL;
// 	alpm_list_t *localpkgs = alpm_list_diff(
// 			alpm_db_get_pkgcache(handle->db_local), targets, _alpm_pkg_cmp);
//
// 	if(ignore) {
// 		alpm_list_t *oldlocal = localpkgs;
// 		localpkgs = alpm_list_diff(oldlocal, ignore, _alpm_pkg_cmp);
// 		alpm_list_free(oldlocal);
// 	}
//
// 	/* We create the vertices */
// 	for(i = targets; i; i = i->next) {
// 		alpm_graph_t *vertex = _alpm_graph_new();
// 		vertex->data = (void *)i->data;
// 		vertices = alpm_list_add(vertices, vertex);
// 	}
//
// 	/* We compute the edges */
// 	for(i = vertices; i; i = i->next) {
// 		alpm_graph_t *vertex_i = i->data;
// 		Package *p_i = vertex_i->data;
// 		/* TODO this should be somehow combined with alpm_checkdeps */
// 		for(j = vertices; j; j = j->next) {
// 			alpm_graph_t *vertex_j = j->data;
// 			Package *p_j = vertex_j->data;
// 			if(_alpm_pkg_depends_on(p_i, p_j)) {
// 				vertex_i->children =
// 					alpm_list_add(vertex_i->children, vertex_j);
// 			}
// 		}
//
// 		/* lazily add local packages to the dep graph so they don't
// 		 * get resolved unnecessarily */
// 		j = localpkgs;
// 		while(j) {
// 			alpm_list_t *next = j->next;
// 			if(_alpm_pkg_depends_on(p_i, j->data)) {
// 				alpm_graph_t *vertex_j = _alpm_graph_new();
// 				vertex_j->data = (void *)j->data;
// 				vertices = alpm_list_add(vertices, vertex_j);
// 				vertex_i->children = alpm_list_add(vertex_i->children, vertex_j);
// 				localpkgs = alpm_list_remove_item(localpkgs, j);
// 				free(j);
// 			}
// 			j = next;
// 		}
//
// 		vertex_i->iterator = vertex_i->children;
// 	}
// 	alpm_list_free(localpkgs);
// 	return vertices;
// }
//
// static void _alpm_warn_dep_cycle(Handle *handle, alpm_list_t *targets,
// 		alpm_graph_t *ancestor, alpm_graph_t *vertex, int reverse)
// {
// 	/* vertex depends on and is required by ancestor */
// 	if(!alpm_list_find_ptr(targets, vertex->data)) {
// 		/* child is not part of the transaction, not a problem */
// 		return;
// 	}
//
// 	/* find the nearest ancestor that's part of the transaction */
// 	while(ancestor) {
// 		if(alpm_list_find_ptr(targets, ancestor->data)) {
// 			break;
// 		}
// 		ancestor = ancestor->parent;
// 	}
//
// 	if(!ancestor || ancestor == vertex) {
// 		/* no transaction package in our ancestry or the package has
// 		 * a circular dependency with itself, not a problem */
// 	} else {
// 		Package *ancestorpkg = ancestor->data;
// 		Package *childpkg = vertex->data;
// 		_alpm_log(handle, ALPM_LOG_WARNING, _("dependency cycle detected:\n"));
// 		if(reverse) {
// 			_alpm_log(handle, ALPM_LOG_WARNING,
// 					_("%s will be removed after its %s dependency\n"),
// 					ancestorpkg->name, childpkg->name);
// 		} else {
// 			_alpm_log(handle, ALPM_LOG_WARNING,
// 					_("%s will be installed before its %s dependency\n"),
// 					ancestorpkg->name, childpkg->name);
// 		}
// 	}
// }

/* Re-order a list of target packages with respect to their dependencies.
 *
 * Example (reverse == 0):
 *   A depends on C
 *   B depends on A
 *   Target order is A,B,C,D
 *
 *   Should be re-ordered to C,A,B,D
 *
 * packages listed in ignore will not be used to detect indirect dependencies
 *
 * if reverse is > 0, the dependency order will be reversed.
 *
 * This function returns the new alpm_list_t* target list.
 *
 */
fn _alpm_sortbydeps<T>(
    handle: Handle,
    targets: &mut Vec<T>,
    ignore: &Vec<T>,
    reverse: i32,
) -> Vec<T> {
    let newtargs: Vec<T>;
    let vertices: Vec<T>;
    let i: Vec<T>;
    // 	alpm_graph_t *vertex;

    if targets.is_empty() {
        return Vec::new();
    }

    debug!("started sorting dependencies");

    // 	vertices = dep_graph_init(handle, targets, ignore);

    // 	i = vertices;
    // 	vertex = vertices->data;
    // 	while(i) {
    // 		/* mark that we touched the vertex */
    // 		vertex->state = ALPM_GRAPH_STATE_PROCESSING;
    // 		int switched_to_child = 0;
    // 		while(vertex->iterator && !switched_to_child) {
    // 			alpm_graph_t *nextchild = vertex->iterator->data;
    // 			vertex->iterator = vertex->iterator->next;
    // 			if(nextchild->state == ALPM_GRAPH_STATE_UNPROCESSED) {
    // 				switched_to_child = 1;
    // 				nextchild->parent = vertex;
    // 				vertex = nextchild;
    // 			} else if(nextchild->state == ALPM_GRAPH_STATE_PROCESSING) {
    // 				_alpm_warn_dep_cycle(handle, targets, vertex, nextchild, reverse);
    // 			}
    // 		}
    // 		if(!switched_to_child) {
    // 			if(alpm_list_find_ptr(targets, vertex->data)) {
    // 				newtargs = alpm_list_add(newtargs, vertex->data);
    // 			}
    // 			/* mark that we've left this vertex */
    // 			vertex->state = ALPM_GRAPH_STATE_PROCESSED;
    // 			vertex = vertex->parent;
    // 			if(!vertex) {
    // 				/* top level vertex reached, move to the next unprocessed vertex */
    // 				for(i = i->next; i; i = i->next) {
    // 					vertex = i->data;
    // 					if(vertex->state == ALPM_GRAPH_STATE_UNPROCESSED) {
    // 						break;
    // 					}
    // 				}
    // 			}
    // 		}
    // 	}

    unimplemented!();
    debug!("sorting dependencies finished");

    // 	if(reverse) {
    // 		/* reverse the order */
    // 		alpm_list_t *tmptargs = alpm_list_reverse(newtargs);
    // 		/* free the old one */
    // 		alpm_list_free(newtargs);
    // 		newtargs = tmptargs;
    // 	}

    // 	return newtargs;
}

/** Find a package satisfying a specified dependency.
 * The dependency can include versions with depmod operators.
 * @param pkgs an alpm_list_t* of Package where the satisfier will be searched
 * @param depstring package or provision name, versioned or not
 * @return a Package* satisfying depstring
 */
pub fn alpm_find_satisfier<'a>(pkgs: &'a Vec<Package>, depstring: &String) -> Option<&'a Package> {
    // Dependency *dep = alpm_dep_from_string(depstring);
    let dep = &alpm_dep_from_string(depstring);
    // if(!dep) {
    // 	return NULL;
    // }
    let pkg = find_dep_satisfier(pkgs, dep);
    return pkg;
}

pub fn dep_vercmp(version1: &String, depmod: &Depmod, version2: &String) -> bool {
    // int equal = 0;
    let cmp = alpm_pkg_vercmp(version1, version2);
    // use pkgfrom_t::*;
    match depmod {
        &Depmod::Any => true,
        &Depmod::EQ => cmp == 0,
        &Depmod::GE => cmp >= 0,
        &Depmod::LE => cmp <= 0,
        &Depmod::LT => cmp < 0,
        &Depmod::GT => cmp > 0,
        // _ => true,
    }
}

/// Return a newly allocated dependency information parsed from a string
/// * `depstring` - a formatted string, e.g. "glibc=2.12"
/// * return - a dependency info structure
pub fn alpm_dep_from_string(depstring: &String) -> Dependency {
    unimplemented!()
    // 	Dependency *depend;
    // 	const char *ptr, *version, *desc;
    // 	size_t deplen;
    //
    // 	if(depstring == NULL) {
    // 		return NULL;
    // 	}
    //
    // 	CALLOC(depend, 1, sizeof(Dependency), return NULL);
    //
    // 	/* Note the extra space in ": " to avoid matching the epoch */
    // 	if((desc = strstr(depstring, ": ")) != NULL) {
    // 		STRDUP(depend->desc, desc + 2, goto error);
    // 		deplen = desc - depstring;
    // 	} else {
    // 		/* no description- point desc at NULL at end of string for later use */
    // 		depend->desc = NULL;
    // 		deplen = strlen(depstring);
    // 		desc = depstring + deplen;
    // 	}
    //
    // 	/* Find a version comparator if one exists. If it does, set the type and
    // 	 * increment the ptr accordingly so we can copy the right strings. */
    // 	if((ptr = memchr(depstring, '<', deplen))) {
    // 		if(ptr[1] == '=') {
    // 			depend->mod = LE;
    // 			version = ptr + 2;
    // 		} else {
    // 			depend->mod = LT;
    // 			version = ptr + 1;
    // 		}
    // 	} else if((ptr = memchr(depstring, '>', deplen))) {
    // 		if(ptr[1] == '=') {
    // 			depend->mod = GE;
    // 			version = ptr + 2;
    // 		} else {
    // 			depend->mod = GT;
    // 			version = ptr + 1;
    // 		}
    // 	} else if((ptr = memchr(depstring, '=', deplen))) {
    // 		/* Note: we must do =,<,> checks after <=, >= checks */
    // 		depend->mod = EQ;
    // 		version = ptr + 1;
    // 	} else {
    // 		/* no version specified, set ptr to end of string and version to NULL */
    // 		ptr = depstring + deplen;
    // 		depend->mod = ANY;
    // 		depend->version = NULL;
    // 		version = NULL;
    // 	}
    //
    // 	/* copy the right parts to the right places */
    // 	STRNDUP(depend->name, depstring, ptr - depstring, goto error);
    // 	depend->name_hash = _alpm_hash_sdbm(depend->name);
    // 	if(version) {
    // 		STRNDUP(depend->version, version, desc - version, goto error);
    // 	}
    //
    // 	return depend;
    //
    // error:
    // 	alpm_dep_free(depend);
    // 	return NULL;
}

impl Dependency {
    /**
     * @param dep dependency to check against the provision list
     * @param provisions provision list
     * @return 1 if provider is found, 0 otherwise
     */
    pub fn _alpm_depcmp_provides(&self, provisions: &Vec<Dependency>) -> bool {
        let satisfy = false;
        // alpm_list_t * i;

        /* check provisions, name and version if available */
        for provision in provisions {
            // Dependency *provision = i->data;

            match self.depmod {
                Depmod::Any => {
                    /* any version will satisfy the requirement */
                    return provision.name_hash == self.name_hash && provision.name == self.name;
                }
                _ => {}
            }
            match provision.depmod {
                Depmod::EQ => {
                    /* provision specifies a version, so try it out */
                    return provision.name_hash == self.name_hash && provision.name == self.name
                        && dep_vercmp(&provision.version, &self.depmod, &self.version);
                }
                _ => {}
            }
        }

        return satisfy;
    }

    // Dependency *_alpm_dep_dup(const Dependency *dep)
    // {
    // 	Dependency *newdep;
    // 	CALLOC(newdep, 1, sizeof(Dependency), return NULL);
    //
    // 	STRDUP(newdep->name, dep->name, goto error);
    // 	STRDUP(newdep->version, dep->version, goto error);
    // 	STRDUP(newdep->desc, dep->desc, goto error);
    // 	newdep->name_hash = dep->name_hash;
    // 	newdep->mod = dep->mod;
    //
    // 	return newdep;
    //
    // error:
    // 	alpm_dep_free(newdep);
    // 	return NULL;
    // }
    //
    // /** Move package dependencies from one list to another
    //  * @param from list to scan for dependencies
    //  * @param to list to add dependencies to
    //  * @param pkg package whose dependencies are moved
    //  * @param explicit if 0, explicitly installed packages are not moved
    //  */
    // static void _alpm_select_depends(alpm_list_t **from, alpm_list_t **to,
    // 		Package *pkg, int explicit)
    // {
    // 	alpm_list_t *i, *next;
    // 	if(!alpm_pkg_get_depends(pkg)) {
    // 		return;
    // 	}
    // 	for(i = *from; i; i = next) {
    // 		Package *deppkg = i->data;
    // 		next = i->next;
    // 		if((explicit || alpm_pkg_get_reason(deppkg) != ALPM_PKG_REASON_EXPLICIT)
    // 				&& _alpm_pkg_depends_on(pkg, deppkg)) {
    // 			*to = alpm_list_add(*to, deppkg);
    // 			*from = alpm_list_remove_item(*from, i);
    // 			free(i);
    // 		}
    // 	}
    // }
    //
    // /**
    //  * @brief Adds unneeded dependencies to an existing list of packages.
    //  * By unneeded, we mean dependencies that are only required by packages in the
    //  * target list, so they can be safely removed.
    //  * If the input list was topo sorted, the output list will be topo sorted too.
    //  *
    //  * @param db package database to do dependency tracing in
    //  * @param *targs pointer to a list of packages
    //  * @param include_explicit if 0, explicitly installed packages are not included
    //  * @return 0 on success, -1 on errors
    //  */
    // int _alpm_recursedeps(alpm_db_t *db, alpm_list_t **targs, int include_explicit)
    // {
    // 	alpm_list_t *i, *keep, *rem = NULL;
    //
    // 	if(db == NULL || targs == NULL) {
    // 		return -1;
    // 	}
    //
    // 	keep = alpm_list_copy(_alpm_db_get_pkgcache(db));
    // 	for(i = *targs; i; i = i->next) {
    // 		keep = alpm_list_remove(keep, i->data, _alpm_pkg_cmp, NULL);
    // 	}
    //
    // 	/* recursively select all dependencies for removal */
    // 	for(i = *targs; i; i = i->next) {
    // 		_alpm_select_depends(&keep, &rem, i->data, include_explicit);
    // 	}
    // 	for(i = rem; i; i = i->next) {
    // 		_alpm_select_depends(&keep, &rem, i->data, include_explicit);
    // 	}
    //
    // 	/* recursively select any still needed packages to keep */
    // 	for(i = keep; i && rem; i = i->next) {
    // 		_alpm_select_depends(&rem, &keep, i->data, 1);
    // 	}
    // 	alpm_list_free(keep);
    //
    // 	/* copy selected packages into the target list */
    // 	for(i = rem; i; i = i->next) {
    // 		Package *pkg = i->data, *copy = NULL;
    // 		_alpm_log(db->handle, ALPM_LOG_DEBUG,
    // 				"adding '%s' to the targets\n", pkg->name);
    // 		if(_alpm_pkg_dup(pkg, &copy)) {
    // 			/* we return memory on "non-fatal" error in _alpm_pkg_dup */
    // 			_alpm_pkg_free(copy);
    // 			alpm_list_free(rem);
    // 			return -1;
    // 		}
    // 		*targs = alpm_list_add(*targs, copy);
    // 	}
    // 	alpm_list_free(rem);
    //
    // 	return 0;
    // }

    // /**
    //  * helper function for resolvedeps: search for dep satisfier in dbs
    //  *
    //  * @param handle the context handle
    //  * @param dep is the dependency to search for
    //  * @param dbs are the databases to search
    //  * @param excluding are the packages to exclude from the search
    //  * @param prompt if true, will cause an unresolvable dependency to issue an
    //  *        interactive prompt asking whether the package should be removed from
    //  *        the transaction or the transaction aborted; if false, simply returns
    //  *        an error code without prompting
    //  * @return the resolved package
    //  **/
    // static Package *resolvedep(Handle *handle, Dependency *dep,
    // 		alpm_list_t *dbs, alpm_list_t *excluding, int prompt)
    // {
    // 	alpm_list_t *i, *j;
    // 	int ignored = 0;
    //
    // 	alpm_list_t *providers = NULL;
    // 	int count;
    //
    // 	/* 1. literals */
    // 	for(i = dbs; i; i = i->next) {
    // 		Package *pkg;
    // 		alpm_db_t *db = i->data;
    //
    // 		if(!(db->usage & (ALPM_DB_USAGE_INSTALL|ALPM_DB_USAGE_UPGRADE))) {
    // 			continue;
    // 		}
    //
    // 		pkg = _alpm_db_get_pkgfromcache(db, dep->name);
    // 		if(pkg && _alpm_depcmp_literal(pkg, dep)
    // 				&& !alpm_pkg_find(excluding, pkg->name)) {
    // 			if(alpm_pkg_should_ignore(handle, pkg)) {
    // 				alpm_question_install_ignorePackage question = {
    // 					.type = ALPM_QUESTION_INSTALL_IGNOREPKG,
    // 					.install = 0,
    // 					.pkg = pkg
    // 				};
    // 				if(prompt) {
    // 					QUESTION(handle, &question);
    // 				} else {
    // 					_alpm_log(handle, ALPM_LOG_WARNING, _("ignoring package %s-%s\n"),
    // 							pkg->name, pkg->version);
    // 				}
    // 				if(!question.install) {
    // 					ignored = 1;
    // 					continue;
    // 				}
    // 			}
    // 			return pkg;
    // 		}
    // 	}
    // 	/* 2. satisfiers (skip literals here) */
    // 	for(i = dbs; i; i = i->next) {
    // 		alpm_db_t *db = i->data;
    // 		if(!(db->usage & (ALPM_DB_USAGE_INSTALL|ALPM_DB_USAGE_UPGRADE))) {
    // 			continue;
    // 		}
    // 		for(j = _alpm_db_get_pkgcache(db); j; j = j->next) {
    // 			Package *pkg = j->data;
    // 			/* with hash != hash, we can even skip the strcmp() as we know they can't
    // 			 * possibly be the same string */
    // 			if(pkg->name_hash != dep->name_hash && _alpm_depcmp(pkg, dep)
    // 					&& !alpm_pkg_find(excluding, pkg->name)) {
    // 				if(alpm_pkg_should_ignore(handle, pkg)) {
    // 					alpm_question_install_ignorePackage question = {
    // 						.type = ALPM_QUESTION_INSTALL_IGNOREPKG,
    // 						.install = 0,
    // 						.pkg = pkg
    // 					};
    // 					if(prompt) {
    // 						QUESTION(handle, &question);
    // 					} else {
    // 						_alpm_log(handle, ALPM_LOG_WARNING, _("ignoring package %s-%s\n"),
    // 								pkg->name, pkg->version);
    // 					}
    // 					if(!question.install) {
    // 						ignored = 1;
    // 						continue;
    // 					}
    // 				}
    // 				_alpm_log(handle, ALPM_LOG_DEBUG, "provider found (%s provides %s)\n",
    // 						pkg->name, dep->name);
    // 				providers = alpm_list_add(providers, pkg);
    // 				/* keep looking for other providers in the all dbs */
    // 			}
    // 		}
    // 	}
    //
    // 	/* first check if one provider is already installed locally */
    // 	for(i = providers; i; i = i->next) {
    // 		Package *pkg = i->data;
    // 		if(_alpm_db_get_pkgfromcache(handle->db_local, pkg->name)) {
    // 			alpm_list_free(providers);
    // 			return pkg;
    // 		}
    // 	}
    // 	count = alpm_list_count(providers);
    // 	if(count >= 1) {
    // 		alpm_question_select_provider_t question = {
    // 			.type = ALPM_QUESTION_SELECT_PROVIDER,
    // 			/* default to first provider if there is no QUESTION callback */
    // 			.use_index = 0,
    // 			.providers = providers,
    // 			.depend = dep
    // 		};
    // 		if(count > 1) {
    // 			/* if there is more than one provider, we ask the user */
    // 			QUESTION(handle, &question);
    // 		}
    // 		if(question.use_index >= 0 && question.use_index < count) {
    // 			alpm_list_t *nth = alpm_list_nth(providers, question.use_index);
    // 			Package *pkg = nth->data;
    // 			alpm_list_free(providers);
    // 			return pkg;
    // 		}
    // 		alpm_list_free(providers);
    // 		providers = NULL;
    // 	}
    //
    // 	if(ignored) { /* resolvedeps will override these */
    // 		handle->pm_errno = ALPM_ERR_PKG_IGNORED;
    // 	} else {
    // 		handle->pm_errno = ALPM_ERR_PKG_NOT_FOUND;
    // 	}
    // 	return NULL;
    // }

    // /**
    //  * Computes resolvable dependencies for a given package and adds that package
    //  * and those resolvable dependencies to a list.
    //  *
    //  * @param handle the context handle
    //  * @param localpkgs is the list of local packages
    //  * @param pkg is the package to resolve
    //  * @param preferred packages to prefer when resolving
    //  * @param packages is a pointer to a list of packages which will be
    //  *        searched first for any dependency packages needed to complete the
    //  *        resolve, and to which will be added any [pkg] and all of its
    //  *        dependencies not already on the list
    //  * @param remove is the set of packages which will be removed in this
    //  *        transaction
    //  * @param data returns the dependency which could not be satisfied in the
    //  *        event of an error
    //  * @return 0 on success, with [pkg] and all of its dependencies not already on
    //  *         the [*packages] list added to that list, or -1 on failure due to an
    //  *         unresolvable dependency, in which case the [*packages] list will be
    //  *         unmodified by this function
    //  */
    // int _alpm_resolvedeps(Handle *handle, alpm_list_t *localpkgs,
    // 		Package *pkg, alpm_list_t *preferred, alpm_list_t **packages,
    // 		alpm_list_t *rem, alpm_list_t **data)
    // {
    // 	int ret = 0;
    // 	alpm_list_t *j;
    // 	alpm_list_t *targ;
    // 	alpm_list_t *deps = NULL;
    // 	alpm_list_t *packages_copy;
    //
    // 	if(alpm_pkg_find(*packages, pkg->name) != NULL) {
    // 		return 0;
    // 	}
    //
    // 	/* Create a copy of the packages list, so that it can be restored
    // 	   on error */
    // 	packages_copy = alpm_list_copy(*packages);
    // 	/* [pkg] has not already been resolved into the packages list, so put it
    // 	   on that list */
    // 	*packages = alpm_list_add(*packages, pkg);
    //
    // 	_alpm_log(handle, ALPM_LOG_DEBUG, "started resolving dependencies\n");
    // 	targ = alpm_list_add(NULL, pkg);
    // 	deps = alpm_checkdeps(handle, localpkgs, rem, targ, 0);
    // 	alpm_list_free(targ);
    // 	targ = NULL;
    //
    // 	for(j = deps; j; j = j->next) {
    // 		alpm_depmissing_t *miss = j->data;
    // 		Dependency *missdep = miss->depend;
    // 		/* check if one of the packages in the [*packages] list already satisfies
    // 		 * this dependency */
    // 		if(find_dep_satisfier(*packages, missdep)) {
    // 			alpm_depmissing_free(miss);
    // 			continue;
    // 		}
    // 		/* check if one of the packages in the [preferred] list already satisfies
    // 		 * this dependency */
    // 		Package *spkg = find_dep_satisfier(preferred, missdep);
    // 		if(!spkg) {
    // 			/* find a satisfier package in the given repositories */
    // 			spkg = resolvedep(handle, missdep, handle->dbs_sync, *packages, 0);
    // 		}
    // 		if(spkg && _alpm_resolvedeps(handle, localpkgs, spkg, preferred, packages, rem, data) == 0) {
    // 			_alpm_log(handle, ALPM_LOG_DEBUG,
    // 					"pulling dependency %s (needed by %s)\n",
    // 					spkg->name, pkg->name);
    // 			alpm_depmissing_free(miss);
    // } else if(resolvedep(handle, missdep, (targ = alpm_list_add(NULL, handle->db_local)), rem, 0)) {
    // 			alpm_depmissing_free(miss);
    // 		} else {
    // 			handle->pm_errno = ALPM_ERR_UNSATISFIED_DEPS;
    // 			char *missdepstring = alpm_dep_compute_string(missdep);
    // 			_alpm_log(handle, ALPM_LOG_WARNING,
    // 					_("cannot resolve \"%s\", a dependency of \"%s\"\n"),
    // 					missdepstring, pkg->name);
    // 			free(missdepstring);
    // 			if(data) {
    // 				*data = alpm_list_add(*data, miss);
    // 			}
    // 			ret = -1;
    // 		}
    // 		alpm_list_free(targ);
    // 		targ = NULL;
    // 	}
    // 	alpm_list_free(deps);
    //
    // 	if(ret != 0) {
    // 		alpm_list_free(*packages);
    // 		*packages = packages_copy;
    // 	} else {
    // 		alpm_list_free(packages_copy);
    // 	}
    // 	_alpm_log(handle, ALPM_LOG_DEBUG, "finished resolving dependencies\n");
    // 	return ret;
    // }

    /// Reverse of splitdep; make a dep string from a Dependency struct.
    /// returns a string-formatted dependency with operator if necessary
    pub fn alpm_dep_compute_string(&self) -> String {
        unimplemented!();
        // 	const char *name, *opr, *ver, *desc_delim, *desc;
        // 	char *str;
        // 	size_t len;
        //
        // 	ASSERT(dep != NULL, return NULL);
        //
        // 	if(dep->name) {
        // 		name = dep->name;
        // 	} else {
        // 		name = "";
        // 	}
        //
        // 	switch(dep->mod) {
        // 		case ANY:
        // 			opr = "";
        // 			break;
        // 		case GE:
        // 			opr = ">=";
        // 			break;
        // 		case LE:
        // 			opr = "<=";
        // 			break;
        // 		case EQ:
        // 			opr = "=";
        // 			break;
        // 		case LT:
        // 			opr = "<";
        // 			break;
        // 		case GT:
        // 			opr = ">";
        // 			break;
        // 		default:
        // 			opr = "";
        // 			break;
        // 	}
        //
        // 	if(dep->mod != ANY && dep->version) {
        // 		ver = dep->version;
        // 	} else {
        // 		ver = "";
        // 	}
        //
        // 	if(dep->desc) {
        // 		desc_delim = ": ";
        // 		desc = dep->desc;
        // 	} else {
        // 		desc_delim = "";
        // 		desc = "";
        // 	}
        //
        // 	/* we can always compute len and print the string like this because opr
        // 	 * and ver will be empty when ANY is the depend type. the
        // 	 * reassignments above also ensure we do not do a strlen(NULL). */
        // 	len = strlen(name) + strlen(opr) + strlen(ver)
        // 		+ strlen(desc_delim) + strlen(desc) + 1;
        // 	MALLOC(str, len, return NULL);
        // 	snprintf(str, len, "%s%s%s%s%s", name, opr, ver, desc_delim, desc);
        //
        // 	return str;
    }
}
