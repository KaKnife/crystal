use super::*;
use super::alpm::*;
// /*
//  *  remove.c
//  *
//  *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
//  *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
//  *
//  *  This program is free software; you can redistribute it and/or modify
//  *  it under the terms of the GNU General Public License as published by
//  *  the Free Software Foundation; either version 2 of the License, or
//  *  (at your option) any later version.
//  *
//  *  This program is distributed in the hope that it will be useful,
//  *  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  *  GNU General Public License for more details.
//  *
//  *  You should have received a copy of the GNU General Public License
//  *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//  */
//
// #include <fnmatch.h>
// #include <stdlib.h>
// #include <stdio.h>
//
// #include <alpm.h>
// #include <alpm_list.h>
//
// /* pacman */
// #include "pacman.h"
// #include "util.h"
// #include "conf.h"

fn fnmatch_cmp(pattern: &String, string: &String) -> std::cmp::Ordering {
	unimplemented!();
	// return fnmatch(pattern, string, 0);
}

fn remove_target(target: String, config: &mut config_t) -> i32 {
	unimplemented!();
	// alpm_pkg_t *pkg;
 // alpm_db_t *db_local = alpm_get_localdb(config->handle);
	let mut db_local = alpm_get_localdb(&config.handle);
	// alpm_list_t *p;

	match alpm_db_get_pkg(&db_local, &target) {
		Some(pkg) => {
			if alpm_remove_pkg(&mut config.handle, &pkg) == -1 {
				// alpm_errno_t err = alpm_errno(config.handle);
				let err = alpm_errno(&config.handle);
				use self::alpm_errno_t::*;
				match err {
					ALPM_ERR_TRANS_DUP_TARGET => {
						/* just skip duplicate targets */
						println!("skipping target: {}", target);
						return 0;
					}
					_ => {
						eprintln!("'{}': {}\n", target, alpm_strerror(err));
						return -1;
					}
				}
			}
			config.explicit_removes.push(pkg);
			return 0;
		}
		_=>{}
	}

	/* fallback to group */
	// alpm_group_t *grp = alpm_db_get_group(db_local, target);
	let grp = db_local.alpm_db_get_group(&target);

	match grp {
		Some(grp) => {
			for pkg in &grp.packages {
				// pkg = p->data;
				if alpm_remove_pkg(&mut config.handle, &pkg) == -1 {
					eprintln!(
						"'{}': {}",
						target,
						alpm_strerror(alpm_errno(&config.handle))
					);
					return -1;
				}
				let newpkg = pkg.clone();

				// config.explicit_removes.push(*newpkg);
			}
			return 0;
		}
		None => {
			// if(grp == NULL) {
			eprintln!("target not found: {}", target);
			return -1;
			// }
		}
	}
}

/**
 * @brief Remove a specified list of packages.
 *
 * @param targets a list of packages (as strings) to remove from the system
 *
 * @return 0 on success, 1 on failure
 */
pub fn pacman_remove(targets: Vec<String>, config: &mut config_t) -> Result<(), i32> {
	unimplemented!();
	let mut retval = 0;
	// let data;
 // 	alpm_list_t *i, *data = NULL;

	if targets.is_empty() {
		eprintln!("no targets specified (use -h for help)");
		return Err(1);
	}

	/* Step 0: create a new transaction */
	if trans_init(&config.flags, 0, config) == -1 {
		return Err(1);
	}

	/* Step 1: add targets to the created transaction */
	for mut target in targets {
		// char *target = i->data;
		if target.starts_with("local/") {
			target = String::from(target.split_at(6).1);
		}
		if remove_target(target, config) == -1 {
			retval = 1;
		}
	}

	if retval == 1 {
		if !trans_release(config) {
			retval = 1;
		}
		return Err(retval);
	}

	/* Step 2: prepare the transaction based on its type, targets and flags */
	// if alpm_trans_prepare(&config.handle, &data) == -1 {
 // unimplemented!();
 // alpm_errno_t err = alpm_errno(config.handle);
 // pm_printf(ALPM_LOG_ERROR, _("failed to prepare transaction (%s)\n"),
 //         alpm_strerror(err));
 // switch(err) {
 // 	case ALPM_ERR_UNSATISFIED_DEPS:
 // 		for(i = data; i; i = alpm_list_next(i)) {
 // 			alpm_depmissing_t *miss = i->data;
 // 			char *depstring = alpm_dep_compute_string(miss->depend);
 // 			colon_printf(_("%s: removing %s breaks dependency '%s'\n"),
 // 					miss->target, miss->causingpkg, depstring);
 // 			free(depstring);
 // 			alpm_depmissing_free(miss);
 // 		}
 // 		break;
 // 	default:
 // 		break;
 // }
 // alpm_list_free(data);
 // retval = 1;
 // goto cleanup;
 // }

	// /* Search for holdpkg in target list */
 let mut holdpkg = 0;
 for pkg in &config.handle.trans.remove {
 	// alpm_pkg_t *pkg = i->data;
 	if config.holdpkg.binary_search_by(|other| fnmatch_cmp(&pkg.name, other)).is_ok() {
 		println!("{} is designated as a HoldPkg.", pkg.name);
 		holdpkg = 1;
 	}
 }
 if holdpkg!=0 /*&& (noyes("HoldPkg was found in target list. Do you want to continue?") == 0)*/ {
 	retval = 1;
	if !trans_release(config) {
		retval = 1;
	}
	return Err(retval);
 }
 //
 // 	/* Step 3: actually perform the removal */
 // 	alpm_list_t *pkglist = alpm_trans_get_remove(config->handle);
 	let pkglist = &config.handle.trans.remove;
 	if pkglist.is_empty() {
 		println!(" there is nothing to do");
		if !trans_release(config) {
			retval = 1;
		}
		return Err(retval);
 	}

 	if config.print {
 		print_packages(&pkglist, &mut config.print_format);
		if !trans_release(config) {
			retval = 1;
		}
		return Err(retval);
 	}

 // 	/* print targets and ask user confirmation */
 // 	display_targets();
 // 	printf("\n");
 // 	if(yesno(_("Do you want to remove these packages?")) == 0) {
 // 		retval = 1;
 // 		goto cleanup;
 // 	}
 //
 // 	if(alpm_trans_commit(config->handle, &data) == -1) {
 // 		pm_printf(ALPM_LOG_ERROR, _("failed to commit transaction (%s)\n"),
 // 		        alpm_strerror(alpm_errno(config->handle)));
 // 		retval = 1;
 // 	}
 //
 // 	FREELIST(data);
 //
 // 	/* Step 4: release transaction resources */
 // cleanup:
 // 	if(trans_release() == -1) {
 // 		retval = 1;
 // 	}
	if retval != 0 {
		return Err(retval);
	}
	return Ok(());
}
