use super::*;
/*
 *  deptest.c
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

pub fn pacman_deptest(targets: Vec<String>, config: &mut config_t) -> std::result::Result<(),i32> {
	let mut deps: Vec<String> = Vec::new();
	let localdb = config.handle.alpm_get_localdb();

	for target in targets {
		// unimplemented!();
		if alpm_find_satisfier(&localdb.alpm_db_get_pkgcache(), &target).is_none() {
			deps.push(target);
		}
	}

	if deps.is_empty() {
		return Ok(());
	}

	for dep in deps {
		println!("{}", dep);
	}
	return Err(127);
}
