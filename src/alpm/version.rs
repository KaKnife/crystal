/*
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
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

/// Split EVR into epoch, version, and release components.
/// * `evr` - [epoch:]version[-release] string
///
/// returns `(ep,vp.rp)`
/// * ep - reference to epoch
/// * vp - reference to version
/// * rp - reference to release
fn parse_evr(evr: &str) -> (String, String, String) {
    let mut tmp: Vec<&str>;
    let epoch: String;
    let version: String;
    let release: String;
    tmp = evr.split(':').collect();
    if tmp.len() > 1 {
        epoch = String::from(tmp[0]);
        tmp = tmp[1].split('-').collect();
    } else {
        epoch = String::from("0");
        tmp = tmp[0].split('-').collect();
    }
    version = String::from(tmp[0]);
    release = if tmp.len() > 1 {
        String::from(tmp[1])
    } else {
        String::new()
    };
    (epoch, version, release)
}

/// Compare alpha and numeric segments of two versions.
/// return 1: a is newer than b;
/// 0: a and b are the same version;
/// -1: b is newer than a
pub fn rpmvercmp(a: &String, b: &String) -> i8 {
    let str1: Vec<&str>;
    let str2: Vec<&str>;

    /* easy comparison to see if versions are identical */
    if a == b {
        return 0;
    }

    str1 = a.split(|c:char| !c.is_alphanumeric()).collect();
    str2 = b.split(|c:char| !c.is_alphanumeric()).collect();

    if str1.len() > str2.len() {
        return 1;
    } else if str2.len() > str1.len() {
        return -1;
    }

    for i in 0..str1.len() {
        if str1[i] > str2[i] {
            return 1;
        } else if str1[i] < str2[i] {
            return -1;
        }
    }
    return 0;
}

/// Compare two version strings and determine which one is 'newer'.
/// Returns a value comparable to the way strcmp works. Returns 1
/// if a is newer than b, 0 if a and b are the same version, or -1
/// if b is newer than a.
///
/// Different epoch values for version strings will override any further
/// comparison. If no epoch is provided, 0 is assumed.
///
/// Keep in mind that the pkgrel is only compared if it is available
/// on both versions handed to this function. For example, comparing
/// 1.5-1 and 1.5 will yield 0; comparing 1.5-1 and 1.5-2 will yield
/// -1 as expected. This is mainly for supporting versioned dependencies
/// that do not include the pkgrel.
pub fn pkg_vercmp(a: &str, b: &str) -> i8 {
    let mut ret;
    /* another quick shortcut- if full version specs are equal */
    if a == b {
        return 0;
    }

    /* Parse both versions into [epoch:]version[-release] triplets. We probably
     * don't need epoch and release to support all the same magic, but it is
     * easier to just run it all through the same code. */
    let (epoch1, ver1, rel1) = parse_evr(a);
    let (epoch2, ver2, rel2) = parse_evr(b);
    ret = rpmvercmp(&epoch1, &epoch2);
    if ret == 0 {
        ret = rpmvercmp(&ver1, &ver2);
        if ret == 0 {
            ret = rpmvercmp(&rel1, &rel2);
        }
    }

    ret
}
