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

fn fnmatch_cmp(pattern: &String, string: &String) -> std::cmp::Ordering {
    unimplemented!();
    // return fnmatch(pattern, string, 0);
}

fn remove_target(target: String, config: &mut Config, handle:&mut Handle) -> i32 {
    match handle.db_local.get_pkg(&target) {
        Ok(pkg) => {
            match alpm_remove_pkg(&mut handle.trans, &pkg) {
                Err(err) => {
                    match err {
                        Error::TransactionDupTarget => {
                            /* just skip duplicate targets */
                            print!("skipping target: {}\n", target);
                            return 0;
                        }
                        _ => {
                            error!("'{}': {}\n", target, err);
                            return -1;
                        }
                    }
                }
                Ok(_) => {}
            }
            config.explicit_removes.push(pkg.clone());
            return 0;
        }
        _ => {}
    }

    /* fallback to group */
    let grp = handle.db_local.get_group(&target);

    match grp {
        Ok(grp) => {
            for pkg in &grp.packages {
                match alpm_remove_pkg(&mut handle.trans, &pkg) {
                    Err(e) => {
                        error!("'{}': {}", target, e);
                        return -1;
                    }
                    Ok(_) => {}
                }
                let newpkg = pkg.clone();

                config.explicit_removes.push(newpkg);
            }
            return 0;
        }
        Err(_) => {
            error!("target not found: {}", target);
            return -1;
        }
    }
}

/// Remove a specified list of packages.
/// returns Ok on success, Err(1) on failure.
///
/// * `targets` - a Vec of packages (as strings) to remove from the system
pub fn pacman_remove(targets: Vec<String>, config: &mut Config, handle:&mut Handle) -> std::result::Result<(), i32> {
    unimplemented!();
    let mut retval = 0;
    // let data;
    // 	alpm_list_t *i, *data = NULL;

    if targets.is_empty() {
        error!("no targets specified (use -h for help)");
        return Err(1);
    }

    /* Step 0: create a new transaction */
    if trans_init(&config.flags.clone(), false, handle).is_err() {
        return Err(1);
    }

    /* Step 1: add targets to the created transaction */
    for mut target in targets {
        if target.starts_with("local/") {
            target = String::from(target.split_at(6).1);
        }
        if remove_target(target, config, handle) == -1 {
            retval = 1;
        }
    }

    if retval == 1 {
        if !trans_release(handle) {
            retval = 1;
        }
        return Err(retval);
    }

    /* Step 2: prepare the transaction based on its type, targets and flags */
    // if alpm_trans_prepare(&config.handle, &data) == -1 {
    //     unimplemented!();
    //     let err = alpm_errno(&config.handle);
    //     error!("failed to prepare transaction ({})", alpm_strerror(err));
    //     match err {
    //         errno_t::ALPM_ERR_UNSATISFIED_DEPS => {
    //             for miss in data {
    //                 let depstring = alpm_dep_compute_string(&miss.depend);
    //                 unimplemented!();
    //                 // colon_printf(_("%s: removing %s breaks dependency '%s'\n"),
    //                 // miss.target, miss.causingpkg, depstring);
    //             }
    //         }
    //         _ => {}
    //     }
    //     retval = 1;
    //     if retval != 0 {
    //         return Err(retval);
    //     }
    // }

    /* Search for holdpkg in target list */
    let mut holdpkg = 0;
    for pkg in &handle.trans.remove {
        if config
            .holdpkg
            .binary_search_by(|other| fnmatch_cmp(pkg.get_name(), other))
            .is_ok()
        {
            print!("{} is designated as a HoldPkg.\n", pkg.get_name());
            holdpkg = 1;
        }
    }
    if holdpkg != 0
    // && (noyes("HoldPkg was found in target list. Do you want to continue?") == 0)
    {
        retval = 1;
        if !trans_release(handle) {
            retval = 1;
        }
        return Err(retval);
    }

    /* Step 3: actually perform the removal */
    let mut pkglist = handle.trans.remove.clone();
    if pkglist.is_empty() {
        print!(" there is nothing to do\n");
        if !trans_release(handle) {
            retval = 1;
        }
        return Err(retval);
    }

    if config.print {
        print_packages(&mut pkglist, &config.print_format, config,handle);
        if !trans_release(handle) {
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
    // if alpm_trans_commit(config.handle, &data) == -1 {
    //     error!(
    //         "failed to commit transaction ({})\n",
    //         alpm_strerror(alpm_errno(&config.handle))
    //     );
    //     retval = 1;
    // }

    /* Step 4: release transaction resources */

    // cleanup:
    if retval != 0 {
        return Err(retval);
    }
    return Ok(());
}
