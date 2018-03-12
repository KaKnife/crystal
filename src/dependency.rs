use alpm::pkg_vercmp;
use Handle;
use Package;

/// Types of version constraints in dependency specs.
#[derive(Debug, Clone, Copy)]
pub enum Depmod {
    /// No version constraint
    Any,
    /// Test version equality (package=x.y.z)
    EQ,
    /// Test for at least a version (package>=x.y.z)
    GE,
    /// Test for at most a version (package<=x.y.z)
    LE,
    /// Test for greater than some version (package>x.y.z)
    GT,
    /// Test for less than some version (package<x.y.z)
    LT,
}

impl Default for Depmod {
    fn default() -> Self {
        Depmod::Any
    }
}

/// Dependency
#[derive(Debug, Clone, Default)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    desc: String,
    pub depmod: Depmod,
}

/// Missing dependency
pub struct DepMissing {
    pub target: String,
    pub depend: Dependency,
    /// this is used only in the case of a remove dependency error
    pub causingpkg: String,
}

impl Dependency {
    pub fn provides(&self, provisions: &Vec<Dependency>) -> bool {
        /* check provisions, name and version if available */
        for provision in provisions {
            match self.depmod {
                Depmod::Any => {
                    /* any version will satisfy the requirement */
                    return provision.name == self.name;
                }
                _ => {}
            }
            match provision.depmod {
                Depmod::EQ => {
                    /* provision specifies a version, so try it out */
                    return provision.name == self.name
                        && dep_vercmp(&provision.version, &self.depmod, &self.version);
                }
                _ => {}
            }
        }

        false
    }

    // Dependency *_dep_dup(const Dependency *dep)
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
    // 	dep_free(newdep);
    // 	return NULL;
    // }
    //
    // /** Move package dependencies from one list to another
    //  * @param from list to scan for dependencies
    //  * @param to list to add dependencies to
    //  * @param pkg package whose dependencies are moved
    //  * @param explicit if 0, explicitly installed packages are not moved
    //  */
    // static void _select_depends(list_t **from, list_t **to,
    // 		Package *pkg, int explicit)
    // {
    // 	list_t *i, *next;
    // 	if(!pkg_get_depends(pkg)) {
    // 		return;
    // 	}
    // 	for(i = *from; i; i = next) {
    // 		Package *deppkg = i->data;
    // 		next = i->next;
    // 		if((explicit || pkg_get_reason(deppkg) != ALPM_PKG_REASON_EXPLICIT)
    // 				&& _pkg_depends_on(pkg, deppkg)) {
    // 			*to = list_add(*to, deppkg);
    // 			*from = list_remove_item(*from, i);
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
    // int _recursedeps(db_t *db, list_t **targs, int include_explicit)
    // {
    // 	list_t *i, *keep, *rem = NULL;
    //
    // 	if(db == NULL || targs == NULL) {
    // 		return -1;
    // 	}
    //
    // 	keep = list_copy(_db_get_pkgcache(db));
    // 	for(i = *targs; i; i = i->next) {
    // 		keep = list_remove(keep, i->data, _pkg_cmp, NULL);
    // 	}
    //
    // 	/* recursively select all dependencies for removal */
    // 	for(i = *targs; i; i = i->next) {
    // 		_select_depends(&keep, &rem, i->data, include_explicit);
    // 	}
    // 	for(i = rem; i; i = i->next) {
    // 		_select_depends(&keep, &rem, i->data, include_explicit);
    // 	}
    //
    // 	/* recursively select any still needed packages to keep */
    // 	for(i = keep; i && rem; i = i->next) {
    // 		_select_depends(&rem, &keep, i->data, 1);
    // 	}
    // 	list_free(keep);
    //
    // 	/* copy selected packages into the target list */
    // 	for(i = rem; i; i = i->next) {
    // 		Package *pkg = i->data, *copy = NULL;
    // 		_log(db->handle, ALPM_LOG_DEBUG,
    // 				"adding '{}' to the targets\n", pkg->name);
    // 		if(_pkg_dup(pkg, &copy)) {
    // 			/* we return memory on "non-fatal" error in _pkg_dup */
    // 			_pkg_free(copy);
    // 			list_free(rem);
    // 			return -1;
    // 		}
    // 		*targs = list_add(*targs, copy);
    // 	}
    // 	list_free(rem);
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
    // 		list_t *dbs, list_t *excluding, int prompt)
    // {
    // 	list_t *i, *j;
    // 	int ignored = 0;
    //
    // 	list_t *providers = NULL;
    // 	int count;
    //
    // 	/* 1. literals */
    // 	for(i = dbs; i; i = i->next) {
    // 		Package *pkg;
    // 		db_t *db = i->data;
    //
    // 		if(!(db->usage & (ALPM_DB_USAGE_INSTALL|ALPM_DB_USAGE_UPGRADE))) {
    // 			continue;
    // 		}
    //
    // 		pkg = _db_get_pkgfromcache(db, dep->name);
    // 		if(pkg && _depcmp_literal(pkg, dep)
    // 				&& !pkg_find(excluding, pkg->name)) {
    // 			if(pkg_should_ignore(handle, pkg)) {
    // 				question_install_ignorePackage question = {
    // 					.type = ALPM_QUESTION_INSTALL_IGNOREPKG,
    // 					.install = 0,
    // 					.pkg = pkg
    // 				};
    // 				if(prompt) {
    // 					QUESTION(handle, &question);
    // 				} else {
    // 					_log(handle, ALPM_LOG_WARNING, _("ignoring package {}-{}\n"),
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
    // 		db_t *db = i->data;
    // 		if(!(db->usage & (ALPM_DB_USAGE_INSTALL|ALPM_DB_USAGE_UPGRADE))) {
    // 			continue;
    // 		}
    // 		for(j = _db_get_pkgcache(db); j; j = j->next) {
    // 			Package *pkg = j->data;
    // 			/* with hash != hash, we can even skip the strcmp() as we know they can't
    // 			 * possibly be the same string */
    // 			if(pkg->name_hash != dep->name_hash && _depcmp(pkg, dep)
    // 					&& !pkg_find(excluding, pkg->name)) {
    // 				if(pkg_should_ignore(handle, pkg)) {
    // 					question_install_ignorePackage question = {
    // 						.type = ALPM_QUESTION_INSTALL_IGNOREPKG,
    // 						.install = 0,
    // 						.pkg = pkg
    // 					};
    // 					if(prompt) {
    // 						QUESTION(handle, &question);
    // 					} else {
    // 						_log(handle, ALPM_LOG_WARNING, _("ignoring package {}-{}\n"),
    // 								pkg->name, pkg->version);
    // 					}
    // 					if(!question.install) {
    // 						ignored = 1;
    // 						continue;
    // 					}
    // 				}
    // 				_log(handle, ALPM_LOG_DEBUG, "provider found ({} provides {})\n",
    // 						pkg->name, dep->name);
    // 				providers = list_add(providers, pkg);
    // 				/* keep looking for other providers in the all dbs */
    // 			}
    // 		}
    // 	}
    //
    // 	/* first check if one provider is already installed locally */
    // 	for(i = providers; i; i = i->next) {
    // 		Package *pkg = i->data;
    // 		if(_db_get_pkgfromcache(handle->db_local, pkg->name)) {
    // 			list_free(providers);
    // 			return pkg;
    // 		}
    // 	}
    // 	count = list_count(providers);
    // 	if(count >= 1) {
    // 		question_select_provider_t question = {
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
    // 			list_t *nth = list_nth(providers, question.use_index);
    // 			Package *pkg = nth->data;
    // 			list_free(providers);
    // 			return pkg;
    // 		}
    // 		list_free(providers);
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
    // int _resolvedeps(Handle *handle, list_t *localpkgs,
    // 		Package *pkg, list_t *preferred, list_t **packages,
    // 		list_t *rem, list_t **data)
    // {
    // 	int ret = 0;
    // 	list_t *j;
    // 	list_t *targ;
    // 	list_t *deps = NULL;
    // 	list_t *packages_copy;
    //
    // 	if(pkg_find(*packages, pkg->name) != NULL) {
    // 		return 0;
    // 	}
    //
    // 	/* Create a copy of the packages list, so that it can be restored
    // 	   on error */
    // 	packages_copy = list_copy(*packages);
    // 	/* [pkg] has not already been resolved into the packages list, so put it
    // 	   on that list */
    // 	*packages = list_add(*packages, pkg);
    //
    // 	_log(handle, ALPM_LOG_DEBUG, "started resolving dependencies\n");
    // 	targ = list_add(NULL, pkg);
    // 	deps = checkdeps(handle, localpkgs, rem, targ, 0);
    // 	list_free(targ);
    // 	targ = NULL;
    //
    // 	for(j = deps; j; j = j->next) {
    // 		depmissing_t *miss = j->data;
    // 		Dependency *missdep = miss->depend;
    // 		/* check if one of the packages in the [*packages] list already satisfies
    // 		 * this dependency */
    // 		if(find_dep_satisfier(*packages, missdep)) {
    // 			depmissing_free(miss);
    // 			continue;
    // 		}
    // 		/* check if one of the packages in the [preferred] list already satisfies
    // 		 * this dependency */
    // 		Package *spkg = find_dep_satisfier(preferred, missdep);
    // 		if(!spkg) {
    // 			/* find a satisfier package in the given repositories */
    // 			spkg = resolvedep(handle, missdep, handle->dbs_sync, *packages, 0);
    // 		}
    // 		if(spkg && _resolvedeps(handle, localpkgs, spkg, preferred, packages, rem, data) == 0) {
    // 			_log(handle, ALPM_LOG_DEBUG,
    // 					"pulling dependency {} (needed by {})\n",
    // 					spkg->name, pkg->name);
    // 			depmissing_free(miss);
    // } else if(resolvedep(handle, missdep, (targ = list_add(NULL, handle->db_local)), rem, 0)) {
    // 			depmissing_free(miss);
    // 		} else {
    // 			handle->pm_errno = ALPM_ERR_UNSATISFIED_DEPS;
    // 			char *missdepstring = dep_compute_string(missdep);
    // 			_log(handle, ALPM_LOG_WARNING,
    // 					_("cannot resolve \"{}\", a dependency of \"{}\"\n"),
    // 					missdepstring, pkg->name);
    // 			free(missdepstring);
    // 			if(data) {
    // 				*data = list_add(*data, miss);
    // 			}
    // 			ret = -1;
    // 		}
    // 		list_free(targ);
    // 		targ = NULL;
    // 	}
    // 	list_free(deps);
    //
    // 	if(ret != 0) {
    // 		list_free(*packages);
    // 		*packages = packages_copy;
    // 	} else {
    // 		list_free(packages_copy);
    // 	}
    // 	_log(handle, ALPM_LOG_DEBUG, "finished resolving dependencies\n");
    // 	return ret;
    // }

    /// Reverse of splitdep; make a dep string from a Dependency struct.
    /// returns a string-formatted dependency with operator if necessary
    pub fn dep_compute_string(&self) -> String {
        let opr = match self.depmod {
            Depmod::Any => "",
            Depmod::GE => ">=",
            Depmod::LE => "<=",
            Depmod::EQ => "=",
            Depmod::LT => "<",
            Depmod::GT => ">",
        };
        let desc_delim = if self.desc != "" { ": " } else { "" };

        format!(
            "{}{}{}{}{}",
            self.name, opr, self.version, desc_delim, self.desc
        )
    }
}
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

// static depmissing_t *depmiss_new(const char *target, Dependency *dep,
// 		const char *causingpkg)
// {
// 	depmissing_t *miss;
//
// 	CALLOC(miss, 1, sizeof(depmissing_t), return NULL);
//
// 	STRDUP(miss->target, target, goto error);
// 	miss->depend = _dep_dup(dep);
// 	STRDUP(miss->causingpkg, causingpkg, goto error);
//
// 	return miss;
//
// error:
// 	depmissing_free(miss);
// 	return NULL;
// }

// void SYMEXPORT depmissing_free(depmissing_t *miss)
// {
// 	ASSERT(miss != NULL, return);
// 	dep_free(miss->depend);
// 	FREE(miss->target);
// 	FREE(miss->causingpkg);
// 	FREE(miss);
// }

// /** Check if pkg2 satisfies a dependency of pkg1 */
// static int _pkg_depends_on(Package *pkg1, Package *pkg2)
// {
// 	list_t *i;
// 	for(i = pkg_get_depends(pkg1); i; i = i->next) {
// 		if(_depcmp(pkg2, i->data)) {
// 			return 1;
// 		}
// 	}
// 	return 0;
// }

pub fn find_dep_satisfier<'a>(pkgs: &'a Vec<Package>, dep: &Dependency) -> Option<&'a Package> {
    for pkg in pkgs {
        if pkg.depcmp(dep) {
            return Some(pkg);
        }
    }
    return None;
}

pub fn find_dep_satisfier_ref<'a>(
    pkgs: &'a Vec<&Package>,
    dep: &Dependency,
) -> Option<&'a Package> {
    for pkg in pkgs {
        if pkg.depcmp(dep) {
            return Some(pkg);
        }
    }
    return None;
}

// /* Convert a list of Package * to a graph structure,
//  * with a edge for each dependency.
//  * Returns a list of vertices (one vertex = one package)
//  * (used by sortbydeps)
//  */
// static list_t *dep_graph_init(Handle *handle,
// 		list_t *targets, list_t *ignore)
// {
// 	list_t *i, *j;
// 	list_t *vertices = NULL;
// 	list_t *localpkgs = list_diff(
// 			db_get_pkgcache(handle->db_local), targets, _pkg_cmp);
//
// 	if(ignore) {
// 		list_t *oldlocal = localpkgs;
// 		localpkgs = list_diff(oldlocal, ignore, _pkg_cmp);
// 		list_free(oldlocal);
// 	}
//
// 	/* We create the vertices */
// 	for(i = targets; i; i = i->next) {
// 		graph_t *vertex = _graph_new();
// 		vertex->data = (void *)i->data;
// 		vertices = list_add(vertices, vertex);
// 	}
//
// 	/* We compute the edges */
// 	for(i = vertices; i; i = i->next) {
// 		graph_t *vertex_i = i->data;
// 		Package *p_i = vertex_i->data;
// 		/* TODO this should be somehow combined with checkdeps */
// 		for(j = vertices; j; j = j->next) {
// 			graph_t *vertex_j = j->data;
// 			Package *p_j = vertex_j->data;
// 			if(_pkg_depends_on(p_i, p_j)) {
// 				vertex_i->children =
// 					list_add(vertex_i->children, vertex_j);
// 			}
// 		}
//
// 		/* lazily add local packages to the dep graph so they don't
// 		 * get resolved unnecessarily */
// 		j = localpkgs;
// 		while(j) {
// 			list_t *next = j->next;
// 			if(_pkg_depends_on(p_i, j->data)) {
// 				graph_t *vertex_j = _graph_new();
// 				vertex_j->data = (void *)j->data;
// 				vertices = list_add(vertices, vertex_j);
// 				vertex_i->children = list_add(vertex_i->children, vertex_j);
// 				localpkgs = list_remove_item(localpkgs, j);
// 				free(j);
// 			}
// 			j = next;
// 		}
//
// 		vertex_i->iterator = vertex_i->children;
// 	}
// 	list_free(localpkgs);
// 	return vertices;
// }

// static void _warn_dep_cycle(Handle *handle, list_t *targets,
// 		graph_t *ancestor, graph_t *vertex, int reverse)
// {
// 	/* vertex depends on and is required by ancestor */
// 	if(!list_find_ptr(targets, vertex->data)) {
// 		/* child is not part of the transaction, not a problem */
// 		return;
// 	}
//
// 	/* find the nearest ancestor that's part of the transaction */
// 	while(ancestor) {
// 		if(list_find_ptr(targets, ancestor->data)) {
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
// 		_log(handle, ALPM_LOG_WARNING, _("dependency cycle detected:\n"));
// 		if(reverse) {
// 			_log(handle, ALPM_LOG_WARNING,
// 					_("{} will be removed after its {} dependency\n"),
// 					ancestorpkg->name, childpkg->name);
// 		} else {
// 			_log(handle, ALPM_LOG_WARNING,
// 					_("{} will be installed before its {} dependency\n"),
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
 * This function returns the new list_t* target list.
 *
 */
fn sortbydeps<T>(handle: Handle, targets: &mut Vec<T>, ignore: &Vec<T>, reverse: i32) -> Vec<T> {
    let newtargs: Vec<T>;
    let vertices: Vec<T>;
    let i: Vec<T>;
    // 	graph_t *vertex;

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
    // 			graph_t *nextchild = vertex->iterator->data;
    // 			vertex->iterator = vertex->iterator->next;
    // 			if(nextchild->state == ALPM_GRAPH_STATE_UNPROCESSED) {
    // 				switched_to_child = 1;
    // 				nextchild->parent = vertex;
    // 				vertex = nextchild;
    // 			} else if(nextchild->state == ALPM_GRAPH_STATE_PROCESSING) {
    // 				_warn_dep_cycle(handle, targets, vertex, nextchild, reverse);
    // 			}
    // 		}
    // 		if(!switched_to_child) {
    // 			if(list_find_ptr(targets, vertex->data)) {
    // 				newtargs = list_add(newtargs, vertex->data);
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
    // 		list_t *tmptargs = list_reverse(newtargs);
    // 		/* free the old one */
    // 		list_free(newtargs);
    // 		newtargs = tmptargs;
    // 	}

    // 	return newtargs;
}

/// Find a package satisfying a specified dependency.
/// The dependency can include versions with depmod operators.
pub fn find_satisfier<'a>(pkgs: &'a Vec<&Package>, depstring: &String) -> Option<&'a Package> {
    let dep = &dep_from_string(depstring);
    find_dep_satisfier_ref(pkgs, dep)
}

/// Compare two version strings and determine which one is 'newer'.
pub fn dep_vercmp(version1: &str, depmod: &Depmod, version2: &str) -> bool {
    let cmp = pkg_vercmp(version1, version2);
    match depmod {
        &Depmod::Any => true,
        &Depmod::EQ => cmp == 0,
        &Depmod::GE => cmp >= 0,
        &Depmod::LE => cmp <= 0,
        &Depmod::LT => cmp < 0,
        &Depmod::GT => cmp > 0,
    }
}

/// Return a newly allocated dependency information parsed from a string.
/// Format: "glibc=2.12"
pub fn dep_from_string(depstring: &str) -> Dependency {
    let mut depend: Dependency = Dependency::default();
    let tmp: String;
    let mut desc: Vec<&str>;

    /* Note the extra space in ": " to avoid matching the epoch */
    desc = depstring.splitn(2, ": ").collect();
    if desc.len() == 2 {
        depend.desc = desc[1].to_string();
    }

    /* Find a version comparator if one exists. If it does, set the type and
     * increment the ptr accordingly so we can copy the right strings. */
    tmp = desc[0].to_string();
    depend.name = desc[0].to_string();
    desc = tmp.splitn(2, "=").collect();
    if desc.len() == 2 {
        depend.depmod = Depmod::EQ;
        depend.name = desc[0].to_string();
        depend.version = desc[1].to_string();
    }
    desc = tmp.splitn(2, "<=").collect();
    if desc.len() == 2 {
        depend.depmod = Depmod::LE;
        depend.name = desc[0].to_string();
        depend.version = desc[1].to_string();
    }
    desc = tmp.splitn(2, "<").collect();
    if desc.len() == 2 {
        depend.depmod = Depmod::LT;
        depend.name = desc[0].to_string();
        depend.version = desc[1].to_string();
    }
    desc = tmp.splitn(2, ">=").collect();
    if desc.len() == 2 {
        depend.depmod = Depmod::GE;
        depend.name = desc[0].to_string();
        depend.version = desc[1].to_string();
    }
    desc = tmp.splitn(2, ">").collect();
    if desc.len() == 2 {
        depend.depmod = Depmod::GT;
        depend.name = desc[0].to_string();
        depend.version = desc[1].to_string();
    }

    depend
}
