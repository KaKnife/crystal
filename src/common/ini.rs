use std::fs::File;
use std::io::Read;
use super::Result;
use super::Config;
use super::Section;
/*
 *  ini.c
 *
 *  Copyright (c) 2013-2017 Pacman Development Team <pacman-dev@archlinux.org>
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

pub type IniParserFn =
    Fn(&String, usize, &String, &Option<String>, &Option<String>, &mut Section, &mut Config)
        -> Result<()>;

/// Parse a pacman-style INI config file.
///
/// Note: The callback will be called at the beginning of each section with an
/// empty key and value and for each key/value pair.
///
/// Note: If the parser encounters an error the callback will be called with
/// section, key, and value set to NULL and errno set by fopen, fgets, or
/// strdup.
///
/// Note: The key and value passed to cb will be overwritten between
/// calls.  The section name will remain valid until after cb is called to
/// begin a new section.
///
/// Note: Parsing will immediately stop if the callback returns non-zero.
pub fn parse_ini(
    file: &String,
    cb: &IniParserFn,
    data: &mut Section,
    config: &mut Config,
) -> Result<()> {
    let mut section_name = String::new();
    // let mut ret = Ok(());
    let mut input: String = String::new();
    let mut fp = File::open(file)?;
    let lines;

    fp.read_to_string(&mut input)?;
    lines = input.lines();

    for (linenum, mut line) in lines.enumerate() {
        let key: String;
        let value: Option<String>;

        line = line.trim();

        if line.len() == 0 || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let mut name;
            /* new config section, skip the '[' */
            name = line;
            name = name.trim_left_matches('[');
            name = name.trim_right_matches("]");

            cb(file, linenum, &name.to_string(), &None, &None, data, config)?;
            section_name = name.to_string();

            continue;
        }

        /* directive */
        /* strsep modifies the 'line' string: 'key \0 value' */
        let keyvalue: Vec<&str> = line.split("=").collect();

        key = String::from(keyvalue[0].trim());
        value = if keyvalue.len() > 1 {
            Some(String::from(keyvalue[1].trim()))
        } else {
            None
        };
        cb(
            file,
            linenum,
            &section_name,
            &Some(key),
            &value,
            data,
            config,
        )?;
    }
    return Ok(());
}
