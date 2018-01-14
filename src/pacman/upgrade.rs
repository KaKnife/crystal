use super::*;
/*
 *  upgrade.c
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
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
// #include <alpm.h>
// #include <alpm_list.h>
//
// /* pacman */
// #include "pacman.h"
// #include "conf.h"
// #include "util.h"

/// Upgrade a specified list of packages.
///
/// * `targets` - a list of packages (as strings) to upgrade
/// * return - Ok(()) on success, Err(()) on failure
pub fn pacman_upgrade(
    mut targets: Vec<String>,
    config: &mut config_t,
    handle: &mut alpm_handle_t,
) -> std::result::Result<(), ()> {
    let mut retval = Ok(());
    let mut file_is_remote: Vec<bool>;
    if targets.is_empty() {
        eprintln!("no targets specified (use -h for help)");
        return Err(());
    }

    file_is_remote = Vec::new();

    for target in &mut targets {
        if target.contains("://") {
            match handle.alpm_fetch_pkgurl(&target) {
                Err(e) => {
                    eprintln!("'{}': {}\n", target, e);
                    retval = Err(());
                    file_is_remote.push(false);
                }
                Ok(url) => {
                    *target = url;
                    file_is_remote.push(true);
                }
            }
        } else {
            file_is_remote.push(false);
        }
    }

    if retval.is_err() {
        return retval;
    }

    /* Step 1: create a new transaction */
    if trans_init(&config.flags.clone(), true,  handle) == -1 {
        return Err(());
    }

    println!("loading packages...");
    /* add targets to the created transaction */
    for (n, targ) in targets.clone().iter().enumerate() {
        let mut pkg = alpm_pkg_t::default();
        let siglevel;

        if file_is_remote[n] {
            siglevel = handle.alpm_option_get_remote_file_siglevel();
        } else {
            siglevel = handle.alpm_option_get_local_file_siglevel();
        }
        match handle.alpm_pkg_load(targ, 1, &siglevel, &pkg) {
            Err(e) => {
                eprintln!("'{}': {}", targ, e);
                retval = Err(());
                continue;
            }
            Ok(_) => {}
        }
        match handle.alpm_add_pkg(&mut pkg) {
            Err(e) => {
                eprintln!("'{}': {}", targ, e);
                retval = Err(());
                continue;
            }
            Ok(_) => {}
        }
        config.explicit_adds.push(pkg);
    }

    if retval.is_err() {
        return retval;
    }

    /* now that targets are resolved, we can hand it all off to the sync code */
    sync_prepare_execute()
}

/* vim: set noet: */
