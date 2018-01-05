use super::*;
// /*
//  *  upgrade.c
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

/**
 * @brief Upgrade a specified list of packages.
 *
 * @param targets a list of packages (as strings) to upgrade
 *
 * @return 0 on success, 1 on failure
 */
pub fn pacman_upgrade(mut targets: Vec<String>, config: &mut config_t) -> Result<(), i32> {
    // int retval = 0, *file_is_remote;
    let mut retval = 0;
    // alpm_list_t *i;
    // unsigned int n, num_targets;
    // let num_targets= targets.len();

    if targets.is_empty() {
        eprintln!("no targets specified (use -h for help)");
        return Err(1);
    }

    let mut file_is_remote = Vec::new();

    for ref mut target in &mut targets {
        if target.contains("://") {
            // char *str = alpm_fetch_pkgurl(config->handle, i->data);
            let url = alpm_fetch_pkgurl(&config.handle, &target);
            if url == "" {
                eprintln!(
                    "'{}': {}\n",
                    target,
                    config.handle.alpm_errno().alpm_strerror()
                );
                retval = 1;
                file_is_remote.push(false);
            } else {
                // free(i->data);
                **target = url;
                file_is_remote.push(true);
            }
        } else {
            file_is_remote.push(false);
        }
    }

    if retval != 0 {
        return Err(retval);
    }

    /* Step 1: create a new transaction */
    if trans_init(&config.flags, 1, config) == -1 {
        retval = 1;
        return Err(retval);
    }

    println!("loading packages...");
    /* add targets to the created transaction */
    for (n, targ) in targets.clone().iter().enumerate() {
        // const char *targ = i->data;
        // alpm_pkg_t *pkg;
        let pkg = alpm_pkg_t::default();
        let siglevel;

        if file_is_remote[n] {
            siglevel = config.handle.alpm_option_get_remote_file_siglevel();
        } else {
            siglevel = config.handle.alpm_option_get_local_file_siglevel();
        }
        if alpm_pkg_load(&config.handle, targ, 1, &siglevel, &pkg) != 0 {
            eprintln!("'{}': {}", targ, config.handle.alpm_errno().alpm_strerror());
            retval = 1;
            continue;
        }
        if config.handle.alpm_add_pkg(&pkg) == -1 {
            eprintln!("'{}': {}", targ, config.handle.alpm_errno().alpm_strerror());
            // alpm_pkg_free(pkg);
            retval = 1;
            continue;
        }
        config.explicit_adds.push(pkg);
    }

    if retval != 0 {
        // goto fail_release;
    }

    // free(file_is_remote);

    /* now that targets are resolved, we can hand it all off to the sync code */
    match sync_prepare_execute() {
        0 => Ok(()),
        e @ _ => Err(e),
    }

    // fail_release:
    // trans_release();
    // fail_free:
    // free(file_is_remote);

    // return retval;
}

/* vim: set noet: */
