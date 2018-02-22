use super::*;
// /*
//  *  package.c
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
// #include <unistd.h>
// #include <limits.h>
// #include <errno.h>
// #include <time.h>
// #include <wchar.h>
//
// #include <alpm.h>
// #include <alpm_list.h>
//
// /* pacman */
// #include "package.h"
// #include "util.h"
// #include "conf.h"
//
// #define CLBUF_SIZE 4096
//
// /* The term "title" refers to the first field of each line in the package
//  * information displayed by pacman. Titles are stored in the `titles` array and
//  * referenced by the following indices.
//  */
// enum title_enum {
// 	T_ARCHITECTURE = 0,
// 	T_BACKUP_FILES,
// 	T_BUILD_DATE,
// 	T_COMPRESSED_SIZE,
// 	T_CONFLICTS_WITH,
// 	T_DEPENDS_ON,
// 	T_DESCRIPTION,
// 	T_DOWNLOAD_SIZE,
// 	T_GROUPS,
// 	T_INSTALL_DATE,
// 	T_INSTALL_REASON,
// 	T_INSTALL_SCRIPT,
// 	T_INSTALLED_SIZE,
// 	T_LICENSES,
// 	T_MD5_SUM,
// 	T_NAME,
// 	T_OPTIONAL_DEPS,
// 	T_OPTIONAL_FOR,
// 	T_PACKAGER,
// 	T_PROVIDES,
// 	T_REPLACES,
// 	T_REPOSITORY,
// 	T_REQUIRED_BY,
// 	T_SHA_256_SUM,
// 	T_SIGNATURES,
// 	T_URL,
// 	T_VALIDATED_BY,
// 	T_VERSION,
// 	/* the following is a sentinel and should remain in last position */
// 	_T_MAX,
// }
//
// /* As of 2015/10/20, the longest title (all locales considered) was less than 30
//  * characters long. We set the title maximum length to 50 to allow for some
//  * potential growth.
//  */
// #define TITLE_MAXLEN 50
//
// static char titles[_T_MAX][TITLE_MAXLEN * sizeof(wchar_t)];
//
// /** Build the `titles` array of localized titles and pad them with spaces so
//  * that they align with the longest title. Storage for strings is stack
//  * allocated and naively truncated to TITLE_MAXLEN characters.
//  */

const T_ARCHITECTURE: &str = "Architecture";
const T_BACKUP_FILES: &str = "Backup Files";
const T_BUILD_DATE: &str = "Build Date";
const T_COMPRESSED_SIZE: &str = "Compressed Size";
const T_CONFLICTS_WITH: &str = "Conflicts With";
const T_DEPENDS_ON: &str = "Depends On";
const T_DESCRIPTION: &str = "Description";
const T_DOWNLOAD_SIZE: &str = "Download Size";
const T_GROUPS: &str = "Groups";
const T_INSTALL_DATE: &str = "Install Date";
const T_INSTALL_REASON: &str = "Install Reason";
const T_INSTALL_SCRIPT: &str = "Install Script";
const T_INSTALLED_SIZE: &str = "Installed Size";
const T_LICENSES: &str = "Licenses";
const T_MD5_SUM: &str = "MD5 Sum";
const T_NAME: &str = "Name";
const T_OPTIONAL_DEPS: &str = "Optional Deps";
const T_OPTIONAL_FOR: &str = "Optional For";
const T_PACKAGER: &str = "Packager";
const T_PROVIDES: &str = "Provides";
const T_REPLACES: &str = "Replaces";
const T_REPOSITORY: &str = "Repository";
const T_REQUIRED_BY: &str = "Required By";
const T_SHA_256_SUM: &str = "SHA-256 Sum";
const T_SIGNATURES: &str = "Signatures";
const T_URL: &str = "URL";
const T_VALIDATED_BY: &str = "Validated By";
const T_VERSION: &str = "Version";

pub fn make_aligned_titles() {
	unimplemented!();
	// 	unsigned int i;
	// 	size_t maxlen = 0;
	// 	int maxcol = 0;
	// 	static const wchar_t title_suffix[] = L" :";
	// 	wchar_t wbuf[ARRAYSIZE(titles)][TITLE_MAXLEN + ARRAYSIZE(title_suffix)];
	// 	size_t wlen[ARRAYSIZE(wbuf)];
	// 	int wcol[ARRAYSIZE(wbuf)];
	// 	char *buf[ARRAYSIZE(wbuf)];
	// let buf: [&str; _T_MAX as i32]
	// 	buf[T_ARCHITECTURE] = _("Architecture");
	// 	buf[T_BACKUP_FILES] = _("Backup Files");
	// 	buf[T_BUILD_DATE] = _("Build Date");
	// 	buf[T_COMPRESSED_SIZE] = _("Compressed Size");
	// 	buf[T_CONFLICTS_WITH] = _("Conflicts With");
	// 	buf[T_DEPENDS_ON] = _("Depends On");
	// 	buf[T_DESCRIPTION] = _("Description");
	// 	buf[T_DOWNLOAD_SIZE] = _("Download Size");
	// 	buf[T_GROUPS] = _("Groups");
	// 	buf[T_INSTALL_DATE] = _("Install Date");
	// 	buf[T_INSTALL_REASON] = _("Install Reason");
	// 	buf[T_INSTALL_SCRIPT] = _("Install Script");
	// 	buf[T_INSTALLED_SIZE] = _("Installed Size");
	// 	buf[T_LICENSES] = _("Licenses");
	// 	buf[T_MD5_SUM] = _("MD5 Sum");
	// 	buf[T_NAME] = _("Name");
	// 	buf[T_OPTIONAL_DEPS] = _("Optional Deps");
	// 	buf[T_OPTIONAL_FOR] = _("Optional For");
	// 	buf[T_PACKAGER] = _("Packager");
	// 	buf[T_PROVIDES] = _("Provides");
	// 	buf[T_REPLACES] = _("Replaces");
	// 	buf[T_REPOSITORY] = _("Repository");
	// 	buf[T_REQUIRED_BY] = _("Required By");
	// 	buf[T_SHA_256_SUM] = _("SHA-256 Sum");
	// 	buf[T_SIGNATURES] = _("Signatures");
	// 	buf[T_URL] = _("URL");
	// 	buf[T_VALIDATED_BY] = _("Validated By");
	// 	buf[T_VERSION] = _("Version");
	//
	// 	for(i = 0; i < ARRAYSIZE(wbuf); i++) {
	// 		wlen[i] = mbstowcs(wbuf[i], buf[i], strlen(buf[i]) + 1);
	// 		wcol[i] = wcswidth(wbuf[i], wlen[i]);
	// 		if(wcol[i] > maxcol) {
	// 			maxcol = wcol[i];
	// 		}
	// 		if(wlen[i] > maxlen) {
	// 			maxlen = wlen[i];
	// 		}
	// 	}
	//
	// 	for(i = 0; i < ARRAYSIZE(wbuf); i++) {
	// 		size_t padlen = maxcol - wcol[i];
	// 		wmemset(wbuf[i] + wlen[i], L' ', padlen);
	// 		wmemcpy(wbuf[i] + wlen[i] + padlen, title_suffix, ARRAYSIZE(title_suffix));
	// 		wcstombs(titles[i], wbuf[i], sizeof(wbuf[i]));
	// 	}
}

/** Turn a depends list into a text list.
 * @param deps a list with items of type depend_t
 */
fn deplist_display(title: &str, deps: &Vec<Dependency>, cols: usize) {
	let mut text = Vec::new();
	for dep in deps {
		text.push(dep.alpm_dep_compute_string());
	}
	list_display(title, &text, cols);
}

// /** Turn a optdepends list into a text list.
//  * @param optdeps a list with items of type depend_t
//  */
// static void optdeplist_display(Package *pkg, unsigned short cols)
// {
// 	alpm_list_t *i, *text = NULL;
// 	Database *localdb = alpm_get_localdb(config->handle);
// 	for(i = alpm_pkg_get_optdepends(pkg); i; i = alpm_list_next(i)) {
// 		depend_t *optdep = i->data;
// 		char *depstring = alpm_dep_compute_string(optdep);
// 		if(alpm_pkg_get_origin(pkg) == ALPM_PKG_FROM_LOCALDB) {
// 			if(alpm_find_satisfier(alpm_db_get_pkgcache(localdb), optdep->name)) {
// 				const char *installed = _(" [installed]");
// 				depstring = realloc(depstring, strlen(depstring) + strlen(installed) + 1);
// 				strcpy(depstring + strlen(depstring), installed);
// 			}
// 		}
// 		text = alpm_list_add(text, depstring);
// 	}
// 	list_display_linebreak(titles[T_OPTIONAL_DEPS], text, cols);
// 	FREELIST(text);
// }

/**
 * Display the details of a package.
 * Extra information entails 'required by' info for sync packages and backup
 * files info for local packages.
 * @param pkg package to display information for
 * @param extra should we show extra information
 */
pub fn dump_pkg_full(
	pkg: &mut Package,
	extra: bool,
	config: &Config,
	db_local: &mut Database,
	dbs_sync: &mut Vec<Database>,
) {
	// unimplemented!();
	// unsigned short cols;
	// time_t bdate, idate;
	let bdate;
	let idate;
	// PackageFrom from;
	let from;
	let reason;
	// double size;
	let mut size;
	// char bdatestr[50] = "", idatestr[50] = "";
	// const char *label, *reason;
	let mut label = String::from("\0");
	// alpm_list_t *validation = NULL, *requiredby = NULL, *optionalfor = NULL;
	let mut validation: Vec<String> = Vec::new();
	let requiredby;
	let optionalfor;

	/* make aligned titles once only */
	// static int need_alignment = 1;
	// static mut need_alignment: bool = true;
	// if need_alignment {
	// 	need_alignment = false;
	// 	make_aligned_titles();
	// }

	from = pkg.alpm_pkg_get_origin();

	/* set variables here, do all output below */
	bdate = pkg.alpm_pkg_get_builddate(db_local);
	if bdate != 0 {
		// unimplemented!();
		// bdatestr = time::strftime("%c", localtime(&bdate));
	}
	idate = pkg.alpm_pkg_get_installdate(db_local);
	if idate != 0 {
		// unimplemented!();
		// strftime(idatestr, 50, "%c", localtime(&idate));
	}

	reason = match pkg.alpm_pkg_get_reason(db_local) {
		&PackageReason::ALPM_PKG_REASON_EXPLICIT => "Explicitly installed",
		&PackageReason::ALPM_PKG_REASON_DEPEND => "Installed as a dependency for another package",
		// _ => "Unknown",
	};

	let v = pkg.alpm_pkg_get_validation(db_local);
	if v != 0 {
		if v & PackageValidation::ALPM_PKG_VALIDATION_NONE as i32 != 0 {
			validation.push(String::from("None"));
		} else {
			if v & PackageValidation::ALPM_PKG_VALIDATION_MD5SUM as i32 != 0 {
				validation.push(String::from("MD5 Sum"));
			}
			if v & PackageValidation::ALPM_PKG_VALIDATION_SHA256SUM as i32 != 0 {
				validation.push(String::from("SHA-256 Sum"));
			}
			if v & PackageValidation::ALPM_PKG_VALIDATION_SIGNATURE as i32 != 0 {
				validation.push(String::from("Signature"));
			}
		}
	} else {
		validation.push(String::from("Unknown"));
	}

	match (&from, extra) {
		(&PackageFrom::ALPM_PKG_FROM_LOCALDB, _) | (_, true) => {
			/* compute this here so we don't get a pause in the middle of output */
			requiredby = pkg.alpm_pkg_compute_requiredby(db_local, dbs_sync);
			optionalfor = pkg.alpm_pkg_compute_optionalfor(db_local, dbs_sync);
		}
		_ => {}
	}

	let cols = getcols();
	/* actual output */
	// match from {
	// 	PackageFrom::ALPM_PKG_FROM_SYNCDB => {
	// 		string_display(T_REPOSITORY, alpm_db_get_name(alpm_pkg_get_db(pkg)), cols, config)
	// 	}
	// 	_ => {}
	// }
	string_display(T_NAME, &pkg.alpm_pkg_get_name(), cols, config);
	string_display(T_VERSION, &pkg.alpm_pkg_get_version(), cols, config);
	string_display(T_DESCRIPTION, pkg.alpm_pkg_get_desc(db_local), cols, config);
	string_display(
		T_ARCHITECTURE,
		&pkg.alpm_pkg_get_arch(db_local),
		cols,
		config,
	);
	string_display(T_URL, &pkg.alpm_pkg_get_url(db_local), cols, config);
	list_display(T_LICENSES, pkg.alpm_pkg_get_licenses(db_local), cols);
	list_display(T_GROUPS, pkg.alpm_pkg_get_groups(db_local), cols);
	deplist_display(T_PROVIDES, pkg.alpm_pkg_get_provides(db_local), cols);
	deplist_display(T_DEPENDS_ON, pkg.alpm_pkg_get_depends(), cols);
	// optdeplist_display(pkg, cols);

	match from {
		PackageFrom::ALPM_PKG_FROM_LOCALDB if extra => {
			// list_display(T_REQUIRED_BY, requiredby, cols);
			// list_display(T_OPTIONAL_FOR, optionalfor, cols);
		}
		_ => {}
	}
	deplist_display(T_CONFLICTS_WITH, pkg.alpm_pkg_get_conflicts(db_local), cols);
	deplist_display(T_REPLACES, pkg.alpm_pkg_get_replaces(db_local), cols);

	size = humanize_size(pkg.alpm_pkg_get_size(), '\0', 2, &mut label);
	match from {
		PackageFrom::ALPM_PKG_FROM_SYNCDB => {
			println!("{} {} {}", T_DOWNLOAD_SIZE, size, label);
		}
		PackageFrom::ALPM_PKG_FROM_FILE => {
			println!("{} {} {}", T_COMPRESSED_SIZE, size, label);
		}
		_ => {}
	}
	size = humanize_size(
		pkg.alpm_pkg_get_isize(db_local),
		label.chars().collect::<Vec<char>>()[0],
		2,
		&mut label,
	);
	println!("{} {} {}", T_INSTALLED_SIZE, size, label);

	string_display(T_PACKAGER, &pkg.alpm_pkg_get_packager(db_local), cols, config);
	// string_display(T_BUILD_DATE, bdatestr, cols);
	match from {
		PackageFrom::ALPM_PKG_FROM_LOCALDB => {
			// string_display(T_INSTALL_DATE, idatestr, cols, config);
			// string_display(T_INSTALL_REASON, reason, cols, config);
		}
		_ => {}
	}
	let has_scriptlet = if pkg.alpm_pkg_has_scriptlet(db_local) != 0 {
		String::from("Yes")
	} else {
		String::from("No")
	};
	match from {
		PackageFrom::ALPM_PKG_FROM_FILE | PackageFrom::ALPM_PKG_FROM_LOCALDB => {
			string_display(T_INSTALL_SCRIPT, &has_scriptlet, cols, config);
		}
		_ => {}
	}

	match from {
		PackageFrom::ALPM_PKG_FROM_SYNCDB if extra => {
			unimplemented!();
			let base64_sig = pkg.alpm_pkg_get_base64_sig();
			let mut keys = Vec::new();
			if !base64_sig.is_empty() {
				unimplemented!();
			// unsigned char *decoded_sigdata = NULL;
			// size_t data_len;
			// alpm_decode_signature(base64_sig, &decoded_sigdata, &data_len);
			// alpm_extract_keyid(config.handle, alpm_pkg_get_name(pkg),
			// 		decoded_sigdata, data_len, &keys);
			} else {
				keys.push(String::from("None"));
			}

			string_display(T_MD5_SUM, &pkg.alpm_pkg_get_md5sum(), cols, config);
			string_display(T_SHA_256_SUM, &pkg.alpm_pkg_get_sha256sum(), cols, config);
			list_display(T_SIGNATURES, &keys, cols);
		}
		_ => {
			list_display(T_VALIDATED_BY, &validation, cols);
		}
	}

	/* Print additional package info if info flag passed more than once */
	match from {
		PackageFrom::ALPM_PKG_FROM_FILE => {
			unimplemented!();
			// 		alpm_siglist_t siglist;
			// 		int err = alpm_pkg_check_pgp_signature(pkg, &siglist);
			// 		if(err && alpm_errno(config->handle) == ALPM_ERR_SIG_MISSING) {
			// 			string_display(titles[T_SIGNATURES], _("None"), cols);
			// 		} else if(err) {
			// 			string_display(titles[T_SIGNATURES],
			// 					alpm_strerror(alpm_errno(config->handle)), cols);
			// 		} else {
			// 			signature_display(titles[T_SIGNATURES], &siglist, cols);
			// 		}
			// 		alpm_siglist_cleanup(&siglist);
		}
		PackageFrom::ALPM_PKG_FROM_LOCALDB if extra => {
			unimplemented!();
			// pkg.dump_pkg_backups();
		}
		_ => {}
	}

	/* final newline to separate packages */
	println!();
}

// static const char *get_backup_file_status(const char *root,
// 		const alpm_backup_t *backup)
// {
// 	char path[PATH_MAX];
// 	const char *ret;
//
// 	snprintf(path, PATH_MAX, "{}{}", root, backup->name);
//
// 	/* if we find the file, calculate checksums, otherwise it is missing */
// 	if(access(path, R_OK) == 0) {
// 		char *md5sum = alpm_compute_md5sum(path);
//
// 		if(md5sum == NULL) {
// 			pm_printf(ALPM_LOG_ERROR,
// 					_("could not calculate checksums for {}\n"), path);
// 			return NULL;
// 		}
//
// 		/* if checksums don't match, file has been modified */
// 		if(strcmp(md5sum, backup->hash) != 0) {
// 			ret = "MODIFIED";
// 		} else {
// 			ret = "UNMODIFIED";
// 		}
// 		free(md5sum);
// 	} else {
// 		switch(errno) {
// 			case EACCES:
// 				ret = "UNREADABLE";
// 				break;
// 			case ENOENT:
// 				ret = "MISSING";
// 				break;
// 			default:
// 				ret = "UNKNOWN";
// 		}
// 	}
// 	return ret;
// }
//
// /* Display list of backup files and their modification states
//  */
// void dump_pkg_backups(Package *pkg)
// {
// 	alpm_list_t *i;
// 	const char *root = alpm_option_get_root(config->handle);
// 	printf("{}{}\n{}", config->colstr.title, titles[T_BACKUP_FILES],
// 				 config->colstr.nocolor);
// 	if(alpm_pkg_get_backup(pkg)) {
// 		/* package has backup files, so print them */
// 		for(i = alpm_pkg_get_backup(pkg); i; i = alpm_list_next(i)) {
// 			const alpm_backup_t *backup = i->data;
// 			const char *value;
// 			if(!backup->hash) {
// 				continue;
// 			}
// 			value = get_backup_file_status(root, backup);
// 			printf("{}\t{}{}\n", value, root, backup->name);
// 		}
// 	} else {
// 		/* package had no backup files */
// 		printf(_("(none)\n"));
// 	}
// }

/* List all files contained in a package
 */
pub fn dump_pkg_files(pkg: &Package, quiet: bool) {
	unimplemented!();
	// 	const char *pkgname, *root;
	// 	alpm_filelist_t *pkgfiles;
	// 	size_t i;
	//
	// 	pkgname = alpm_pkg_get_name(pkg);
	// 	pkgfiles = alpm_pkg_get_files(pkg);
	// 	root = alpm_option_get_root(config->handle);
	//
	// 	for(i = 0; i < pkgfiles->count; i++) {
	// 		const alpm_file_t *file = pkgfiles->files + i;
	// 		/* Regular: '<pkgname> <root><filepath>\n'
	// 		 * Quiet  : '<root><filepath>\n'
	// 		 */
	// 		if(!quiet) {
	// 			printf("{}{}{} ", config->colstr.title, pkgname, config->colstr.nocolor);
	// 		}
	// 		printf("{}{}\n", root, file->name);
	// 	}
	//
	// 	fflush(stdout);
}

/* Display the changelog of a package
 */
pub fn dump_pkg_changelog(pkg: &Package) {
	unimplemented!();
	// 	void *fp = NULL;
	//
	// 	if((fp = alpm_pkg_changelog_open(pkg)) == NULL) {
	// 		pm_printf(ALPM_LOG_ERROR, _("no changelog available for '{}'.\n"),
	// 				alpm_pkg_get_name(pkg));
	// 		return;
	// 	} else {
	// 		fprintf(stdout, _("Changelog for {}:\n"), alpm_pkg_get_name(pkg));
	// 		/* allocate a buffer to get the changelog back in chunks */
	// 		char buf[CLBUF_SIZE];
	// 		size_t ret = 0;
	// 		while((ret = alpm_pkg_changelog_read(buf, CLBUF_SIZE, pkg, fp))) {
	// 			if(ret < CLBUF_SIZE) {
	// 				/* if we hit the end of the file, we need to add a null terminator */
	// 				*(buf + ret) = '\0';
	// 			}
	// 			fputs(buf, stdout);
	// 		}
	// 		alpm_pkg_changelog_close(pkg, fp);
	// 		putchar('\n');
	// 	}
}

// void print_installed(Database *db_local, Package *pkg)
// {
// 	const char *pkgname = alpm_pkg_get_name(pkg);
// 	const char *pkgver = alpm_pkg_get_version(pkg);
// 	Package *lpkg = alpm_db_get_pkg(db_local, pkgname);
// 	if(lpkg) {
// 		const char *lpkgver = alpm_pkg_get_version(lpkg);
// 		const colstr_t *colstr = &config->colstr;
// 		if(strcmp(lpkgver, pkgver) == 0) {
// 			printf(" {}[{}]{}", colstr->meta, _("installed"), colstr->nocolor);
// 		} else {
// 			printf(" {}[{}: {}]{}", colstr->meta, _("installed"),
// 					lpkgver, colstr->nocolor);
// 		}
// 	}
// }

/**
 * Display the details of a search.
 * @param db the database we're searching
 * @param targets the targets we're searching for
 * @param show_status show if the package is also in the local db
 */
pub fn dump_pkg_search(
	db: &mut Database,
	targets: &Vec<String>,
	show_status: i32,
	colstr: &ColStr,
	handle: &Handle,
	quiet: bool,
) -> i32 {
	unimplemented!();
	// 	int freelist = 0;
	// 	Database *db_local;
	let db_local;
	// 	alpm_list_t *i, *searchlist;
	let searchlist;
	let mut freelist = 0;
	// 	unsigned short cols;
	let cols;
	// 	const colstr_t *colstr = &config->colstr;
	// let colstr = &config.colstr;
	//
	if show_status != 0 {
		db_local = handle.alpm_get_localdb();
	}

	/* if we have a targets list, search for packages matching it */
	if !targets.is_empty() {
		searchlist = db.alpm_db_search(targets).clone();
		freelist = 1;
	} else {
		searchlist = db.alpm_db_get_pkgcache().unwrap().clone();
		freelist = 0;
	}
	if searchlist.is_empty() {
		return 1;
	}

	cols = getcols();
	for pkg in searchlist {
		// let grp;
		// 		alpm_list_t *grp;
		// 		Package *pkg = i->data;
		//
		if quiet {
			print!("{}", pkg.alpm_pkg_get_name())
		// 			fputs(alpm_pkg_get_name(pkg), stdout);
		} else {
			print!(
				"{}{}/{}{} {}{}{}",
				colstr.repo,
				db.alpm_db_get_name(),
				colstr.title,
				pkg.alpm_pkg_get_name(),
				colstr.version,
				pkg.alpm_pkg_get_version(),
				colstr.nocolor
			);
			// grp = pkg.alpm_pkg_get_groups();
			// if grp.is_some() {
			// 	// 				alpm_list_t *k;
			// 	// 				printf(" {}(", colstr->groups);
			// 	for group in grp {
			// 		// 					const char *group = k->data;
			// 		// 					fputs(group, stdout);
			// 		// 					if(alpm_list_next(k)) {
			// 		// 						/* only print a spacer if there are more groups */
			// 		// 						putchar(' ');
			// 		// 					}
			// 	}
			// 	// print!("){}", colstr->nocolor);
			// }
			//
			// 			if(show_status) {
			// 				print_installed(db_local, pkg);
			// 			}
			//
			// 			/* we need a newline and initial indent first */
			// 			fputs("\n    ", stdout);
			// 			indentprint(alpm_pkg_get_desc(pkg), 4, cols);
		}
		// print!("\n");
	}

	// /* we only want to free if the list was a search list */
	// if (freelist != 0) {
	// 	alpm_list_free(searchlist);
	// }

	return 0;
}
