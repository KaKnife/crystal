use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use super::*;
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

// #include <errno.h>
// #include <limits.h>
// #include <string.h> /* strdup */
//
// #include <alpm.h>
//
// #include "ini.h"
// #include "util.h"

/*
 * @brief Parse a pacman-style INI config file.
 *
 * @param file path to the config file
 * @param cb callback for key/value pairs
 * @param data caller defined data to be passed to the callback
 *
 * @return the callback return value
 *
 * @note The callback will be called at the beginning of each section with an
 * empty key and value and for each key/value pair.
 *
 * @note If the parser encounters an error the callback will be called with
 * section, key, and value set to NULL and errno set by fopen, fgets, or
 * strdup.
 *
 * @note The @a key and @a value passed to @ cb will be overwritten between
 * calls.  The section name will remain valid until after @a cb is called to
 * begin a new section.
 *
 * @note Parsing will immediately stop if the callback returns non-zero.
 */

pub type ini_parser_fn =
	Fn(&String, i32, &String, &Option<String>, &Option<String>, &mut section_t, &mut config_t)
		-> i32;

pub fn parse_ini(
	file: &String,
	cb: &ini_parser_fn,
	data: &mut section_t,
	config: &mut config_t,
) -> i32 {
	// char line[PATH_MAX], *section_name = NULL;
	let mut section_name = String::new();
	// FILE *fp = NULL;
	let mut linenum = 0;
	let mut ret = 0;
	// int linenum = 0;
	// int ret = 0;

	let fp = match File::open(file) {
		Ok(f) => BufReader::new(f),
		Err(e) => unimplemented!("{}:{}", e, file),
	};
	// if fp == NULL {
	// 	return cb(file, 0, NULL, NULL, NULL, data);
	// }

	for linew in fp.lines() {
		let line;
		match linew {
			Ok(l) => line = l,
			Err(_) => continue,
		}
		let key:String;
		let value;
		// size_t line_len;
		// let line_len;

		linenum += 1;

		line.trim();
		// line_len = strtrim(line);

		if line.len() == 0 || line.starts_with('#') {
			continue;
		}

		if line.starts_with('[') && line.ends_with(']') {
			let mut name;
			/* new config section, skip the '[' */
			name = line;
			name = String::from(name.trim_left_matches('['));
			name = String::from(name.trim_right_matches("]"));
			// name[line_len - 2] = '\0';

			ret = cb(file, linenum, &name, &None, &None, data, config);
			// free(section_name);
			section_name = name;

			/* we're at a new section; perform any post-actions for the prior */
			if ret != 0 {
				return ret;
				// goto cleanup;
			}
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

		ret = cb(
			file,
			linenum,
			&section_name,
			&Some(key),
			&value,
			data,
			config,
		);
		if ret != 0 {
			// goto cleanup;
			return ret;
		}
	}
	return ret;
}

/* vim: set noet: */
