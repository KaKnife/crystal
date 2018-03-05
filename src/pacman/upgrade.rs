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
use super::alpm::Handle;
use super::sync_prepare_execute;
use super::trans_init;
use super::Config;
use super::alpm::Result;
use super::alpm::Error;

/// Upgrade a specified list of packages.
pub fn pacman_upgrade(
    mut targets: Vec<String>,
    config: &mut Config,
    handle: &mut Handle,
) -> Result<()> {
    let mut retval = Ok(());
    let mut file_is_remote: Vec<bool>;
    if targets.is_empty() {
        error!("no targets specified (use -h for help)");
        return Err(Error::WrongArgs);
    }

    file_is_remote = Vec::new();

    for target in &mut targets {
        if target.contains("://") {
            match handle.fetch_pkgurl(&target) {
                Err(e) => {
                    error!("'{}': {}\n", target, e);
                    retval = Err(e);
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
    trans_init(&config.flags.clone(), true, handle)?;

    print!("loading packages...\n");
    /* add targets to the created transaction */
    for (n, targ) in targets.iter().enumerate() {
        let mut pkg;
        let siglevel;

        if file_is_remote[n] {
            siglevel = handle.get_remote_file_siglevel();
        } else {
            siglevel = handle.get_local_file_siglevel();
        }
        pkg = match handle.pkg_load(targ, 1, &siglevel) {
            Err(e) => {
                error!("'{}': {}", targ, e);
                retval = Err(e);
                continue;
            }
            Ok(p) => p.clone(),
        };
        if let Err(e) = handle.add_pkg(&mut pkg) {
            error!("'{}': {}", targ, e);
            retval = Err(e);
            continue;
        }
        config.explicit_adds.push(pkg.clone());
    }

    if retval.is_err() {
        return retval;
    }

    /* now that targets are resolved, we can hand it all off to the sync code */
    sync_prepare_execute(config, handle)
}
