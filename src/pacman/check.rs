/*
 *  check.c
 *
 *  Copyright (c) 2012-2017 Pacman Development Team <pacman-dev@archlinux.org>
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

// static int check_file_exists(const char *pkgname, char *filepath, size_t rootlen,
// 		struct stat *st)
// {
// 	/* use lstat to prevent errors from symlinks */
// 	if(llstat(filepath, st) != 0) {
// 		if(alpm_option_match_noextract(config->handle, filepath + rootlen) == 0) {
// 			/* NoExtract */
// 			return -1;
// 		} else {
// 			if(config->quiet) {
// 				printf("%s %s\n", pkgname, filepath);
// 			} else {
// 				pm_printf(ALPM_LOG_WARNING, "%s: %s (%s)\n",
// 						pkgname, filepath, strerror(errno));
// 			}
// 			return 1;
// 		}
// 	}
//
// 	return 0;
// }

// static int check_file_type(const char *pkgname, const char *filepath,
// 		struct stat *st, struct archive_entry *entry)
// {
// 	mode_t archive_type = archive_entry_filetype(entry);
// 	mode_t file_type = st->st_mode;
//
// 	if((archive_type == AE_IFREG && !S_ISREG(file_type)) ||
// 			(archive_type == AE_IFDIR && !S_ISDIR(file_type)) ||
// 			(archive_type == AE_IFLNK && !S_ISLNK(file_type))) {
// 		if(config->quiet) {
// 			printf("%s %s\n", pkgname, filepath);
// 		} else {
// 			pm_printf(ALPM_LOG_WARNING, _("%s: %s (File type mismatch)\n"),
// 					pkgname, filepath);
// 		}
// 		return 1;
// 	}
//
// 	return 0;
// }

// static int check_file_permissions(const char *pkgname, const char *filepath,
// 		struct stat *st, struct archive_entry *entry)
// {
// 	int errors = 0;
// 	mode_t fsmode;
//
// 	/* uid */
// 	if(st->st_uid != archive_entry_uid(entry)) {
// 		errors++;
// 		if(!config->quiet) {
// 			pm_printf(ALPM_LOG_WARNING, _("%s: %s (UID mismatch)\n"),
// 					pkgname, filepath);
// 		}
// 	}
//
// 	/* gid */
// 	if(st->st_gid != archive_entry_gid(entry)) {
// 		errors++;
// 		if(!config->quiet) {
// 			pm_printf(ALPM_LOG_WARNING, _("%s: %s (GID mismatch)\n"),
// 					pkgname, filepath);
// 		}
// 	}
//
// 	/* mode */
// 	fsmode = st->st_mode & (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO);
// 	if(fsmode != (~AE_IFMT & archive_entry_mode(entry))) {
// 		errors++;
// 		if(!config->quiet) {
// 			pm_printf(ALPM_LOG_WARNING, _("%s: %s (Permissions mismatch)\n"),
// 					pkgname, filepath);
// 		}
// 	}
//
// 	return (errors != 0 ? 1 : 0);
// }

// static int check_file_time(const char *pkgname, const char *filepath,
// 		struct stat *st, struct archive_entry *entry, int backup)
// {
// 	if(st->st_mtime != archive_entry_mtime(entry)) {
// 		if(backup) {
// 			if(!config->quiet) {
// 				printf("%s%s%s: ", config->colstr.title, _("backup file"),
// 						config->colstr.nocolor);
// 				printf(_("%s: %s (Modification time mismatch)\n"),
// 						pkgname, filepath);
// 			}
// 			return 0;
// 		}
// 		if(!config->quiet) {
// 			pm_printf(ALPM_LOG_WARNING, _("%s: %s (Modification time mismatch)\n"),
// 					pkgname, filepath);
// 		}
// 		return 1;
// 	}
//
// 	return 0;
// }

// static int check_file_link(const char *pkgname, const char *filepath,
// 		struct stat *st, struct archive_entry *entry)
// {
// 	size_t length = st->st_size + 1;
// 	char link[length];
//
// 	if(readlink(filepath, link, length) != st->st_size) {
// 		/* this should not happen */
// 		pm_printf(ALPM_LOG_ERROR, _("unable to read symlink contents: %s\n"), filepath);
// 		return 1;
// 	}
// 	link[length - 1] = '\0';
//
// 	if(strcmp(link, archive_entry_symlink(entry)) != 0) {
// 		if(!config->quiet) {
// 			pm_printf(ALPM_LOG_WARNING, _("%s: %s (Symlink path mismatch)\n"),
// 					pkgname, filepath);
// 		}
// 		return 1;
// 	}
//
// 	return 0;
// }

// static int check_file_size(const char *pkgname, const char *filepath,
// 		struct stat *st, struct archive_entry *entry, int backup)
// {
// 	if(st->st_size != archive_entry_size(entry)) {
// 		if(backup) {
// 			if(!config->quiet) {
// 				printf("%s%s%s: ", config->colstr.title, _("backup file"),
// 						config->colstr.nocolor);
// 				printf(_("%s: %s (Size mismatch)\n"),
// 						pkgname, filepath);
// 			}
// 			return 0;
// 		}
// 		if(!config->quiet) {
// 			pm_printf(ALPM_LOG_WARNING, _("%s: %s (Size mismatch)\n"),
// 					pkgname, filepath);
// 		}
// 		return 1;
// 	}
//
// 	return 0;
// }

/* placeholders - libarchive currently does not read checksums from mtree files
// static int check_file_md5sum(const char *pkgname, const char *filepath,
// 		struct stat *st, struct archive_entry *entry, int backup)
// {
// 	return 0;
// }
// static int check_file_sha256sum(const char *pkgname, const char *filepath,
// 		struct stat *st, struct archive_entry *entry, int backup)
// {
// 	return 0;
// }
*/
