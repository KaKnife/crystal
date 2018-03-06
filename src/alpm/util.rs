/*
 *  util.c
 *
 *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
 *  Copyright (c) 2005 by Christian Hamar <krics@linuxforum.hu>
 *  Copyright (c) 2006 by David Kimpe <dnaku@frugalware.org>
 *  Copyright (c) 2005, 2006 by Miklos Vajna <vmiklos@frugalware.org>
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

use super::*;
use std::num::Wrapping;

// /* libarchive */
// #include <archive.h>
// #include <archive_entry.h>
//
// #ifdef HAVE_LIBSSL
// #include <openssl/md5.h>
// #include <openssl/sha.h>
// #endif
//
// #ifdef HAVE_LIBNETTLE
// #include <nettle/md5.h>
// #include <nettle/sha2.h>
// #endif

// #ifndef HAVE_STRSEP
// /** Extracts tokens from a string.
//  * Replaces strset which is not portable (missing on Solaris).
//  * Copyright (c) 2001 by François Gouget <fgouget_at_codeweavers.com>
//  * Modifies str to point to the first character after the token if one is
//  * found, or NULL if one is not.
//  * @param str string containing delimited tokens to parse
//  * @param delim character delimiting tokens in str
//  * @return pointer to the first token in str if str is not NULL, NULL if
//  * str is NULL
//  */
// char *strsep(char **str, const char *delims)
// {
// 	char *token;
//
// 	if(*str == NULL) {
// 		/* No more tokens */
// 		return NULL;
// 	}
//
// 	token = *str;
// 	while(**str != '\0') {
// 		if(strchr(delims, **str) != NULL) {
// 			**str = '\0';
// 			(*str)++;
// 			return token;
// 		}
// 		(*str)++;
// 	}
// 	/* There is no other token */
// 	*str = NULL;
// 	return token;
// }
// #endif

// pub fn _makepath(path: &String) -> i32
// {
// 	return _makepath_mode(path, 0755);
// }
//
// /** Creates a directory, including parents if needed, similar to 'mkdir -p'.
//  * @param path directory path to create
//  * @param mode permission mode for created directories
//  * @return 0 on success, 1 on error
//  */
// fn _makepath_mode(const char *path, mode_t mode) -> i32
// {
//     unimplemented!();
// 	char *ptr, *str;
// 	mode_t oldmask;
// 	int ret = 0;
//
// 	STRDUP(str, path, return 1);
//
// 	oldmask = umask(0000);
//
// 	for(ptr = str; *ptr; ptr++) {
// 		/* detect mid-path condition and zero length paths */
// 		if(*ptr != '/' || ptr == str || ptr[-1] == '/') {
// 			continue;
// 		}
//
// 		/* temporarily mask the end of the path */
// 		*ptr = '\0';
//
// 		if(mkdir(str, mode) < 0 && errno != EEXIST) {
// 			ret = 1;
// 			goto done;
// 		}
//
// 		/* restore path separator */
// 		*ptr = '/';
// 	}
//
// 	/* end of the string. add the full path. It will already exist when the path
// 	 * passed in has a trailing slash. */
// 	if(mkdir(str, mode) < 0 && errno != EEXIST) {
// 		ret = 1;
// 	}
//
// done:
// 	umask(oldmask);
// 	free(str);
// 	return ret;
// }

// /** Copies a file.
//  * @param src file path to copy from
//  * @param dest file path to copy to
//  * @return 0 on success, 1 on error
//  */
// int _copyfile(const char *src, const char *dest)
// {
// 	char *buf;
// 	int in, out, ret = 1;
// 	ssize_t nread;
// 	struct stat st;
//
// 	MALLOC(buf, (size_t)ALPM_BUFFER_SIZE, return 1);
//
// 	OPEN(in, src, O_RDONLY | O_CLOEXEC);
// 	do {
// 		out = open(dest, O_WRONLY | O_CREAT | O_BINARY | O_CLOEXEC, 0000);
// 	} while(out == -1 && errno == EINTR);
// 	if(in < 0 || out < 0) {
// 		goto cleanup;
// 	}
//
// 	if(fstat(in, &st) || fchmod(out, st.st_mode)) {
// 		goto cleanup;
// 	}
//
// 	/* do the actual file copy */
// 	while((nread = read(in, buf, ALPM_BUFFER_SIZE)) > 0 || errno == EINTR) {
// 		ssize_t nwrite = 0;
// 		if(nread < 0) {
// 			continue;
// 		}
// 		do {
// 			nwrite = write(out, buf + nwrite, nread);
// 			if(nwrite >= 0) {
// 				nread -= nwrite;
// 			} else if(errno != EINTR) {
// 				goto cleanup;
// 			}
// 		} while(nread > 0);
// 	}
// 	ret = 0;
//
// cleanup:
// 	free(buf);
// 	if(in >= 0) {
// 		close(in);
// 	}
// 	if(out >= 0) {
// 		close(out);
// 	}
// 	return ret;
// }

// /** Trim trailing newlines from a string (if any exist).
//  * @param str a single line of text
//  * @param len size of str, if known, else 0
//  * @return the length of the trimmed string
//  */
// size_t _strip_newline(st: &str, size_t len)
// {
// 	if(*st == '\0') {
// 		return 0;
// 	}
// 	if(len == 0) {
// 		len = strlen(st);
// 	}
// 	while(len > 0 && st[len - 1] == '\n') {
// 		len--;
// 	}
// 	st[len] = '\0';
//
// 	return len;
// }

/* Compression functions */

// /** Open an archive for reading and perform the necessary boilerplate.
//  * This takes care of creating the libarchive 'archive' struct, setting up
//  * compression and format options, opening a file descriptor, setting up the
//  * buffer size, and performing a stat on the path once opened.
//  * On error, no file descriptor is opened, and the archive pointer returned
//  * will be set to NULL.
//  * @param handle the context handle
//  * @param path the path of the archive to open
//  * @param buf space for a stat buffer for the given path
//  * @param archive pointer to place the created archive object
//  * @param error error code to set on failure to open archive
//  * @return -1 on failure, >=0 file descriptor on success
//  */
// int _open_archive(handle_t *handle, const char *path,
// 		struct stat *buf, struct archive **archive, errno_t error)
// {
// 	int fd;
// 	size_t bufsize = ALPM_BUFFER_SIZE;
// 	errno = 0;
//
// 	if((*archive = archive_read_new()) == NULL) {
// 		RET_ERR(handle, ALPM_ERR_LIBARCHIVE, -1);
// 	}
//
// 	_archive_read_support_filter_all(*archive);
// 	archive_read_support_format_all(*archive);
//
// 	_log(handle, ALPM_LOG_DEBUG, "opening archive %s\n", path);
// 	OPEN(fd, path, O_RDONLY | O_CLOEXEC);
// 	if(fd < 0) {
// 		_log(handle, ALPM_LOG_ERROR,
// 				_("could not open file %s: %s\n"), path, strerror(errno));
// 		goto error;
// 	}
//
// 	if(fstat(fd, buf) != 0) {
// 		_log(handle, ALPM_LOG_ERROR,
// 				_("could not stat file %s: %s\n"), path, strerror(errno));
// 		goto error;
// 	}
// #ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
// 	if(buf->st_blksize > ALPM_BUFFER_SIZE) {
// 		bufsize = buf->st_blksize;
// 	}
// #endif
//
// 	if(archive_read_open_fd(*archive, fd, bufsize) != ARCHIVE_OK) {
// 		_log(handle, ALPM_LOG_ERROR, _("could not open file %s: %s\n"),
// 				path, archive_error_string(*archive));
// 		goto error;
// 	}
//
// 	return fd;
//
// error:
// 	_archive_read_free(*archive);
// 	*archive = NULL;
// 	if(fd >= 0) {
// 		close(fd);
// 	}
// 	RET_ERR(handle, error, -1);
// }
//
// /** Unpack a specific file in an archive.
//  * @param handle the context handle
//  * @param archive the archive to unpack
//  * @param prefix where to extract the files
//  * @param filename a file within the archive to unpack
//  * @return 0 on success, 1 on failure
//  */
// int _unpack_single(handle_t *handle, const char *archive,
// 		const char *prefix, const char *filename)
// {
// 	list_t *list = NULL;
// 	int ret = 0;
// 	if(filename == NULL) {
// 		return 1;
// 	}
// 	list = list_add(list, (void *)filename);
// 	ret = _unpack(handle, archive, prefix, list, 1);
// 	list_free(list);
// 	return ret;
// }
//
// /** Unpack a list of files in an archive.
//  * @param handle the context handle
//  * @param path the archive to unpack
//  * @param prefix where to extract the files
//  * @param list a list of files within the archive to unpack or NULL for all
//  * @param breakfirst break after the first entry found
//  * @return 0 on success, 1 on failure
//  */
// int _unpack(handle_t *handle, const char *path, const char *prefix,
// 		list_t *list, int breakfirst)
// {
// 	int ret = 0;
// 	mode_t oldmask;
// 	struct archive *archive;
// 	struct archive_entry *entry;
// 	struct stat buf;
// 	int fd, cwdfd;
//
// 	fd = _open_archive(handle, path, &buf, &archive, ALPM_ERR_PKG_OPEN);
// 	if(fd < 0) {
// 		return 1;
// 	}
//
// 	oldmask = umask(0022);
//
// 	/* save the cwd so we can restore it later */
// 	OPEN(cwdfd, ".", O_RDONLY | O_CLOEXEC);
// 	if(cwdfd < 0) {
// 		_log(handle, ALPM_LOG_ERROR, _("could not get current working directory\n"));
// 	}
//
// 	/* just in case our cwd was removed in the upgrade operation */
// 	if(chdir(prefix) != 0) {
// 		_log(handle, ALPM_LOG_ERROR, _("could not change directory to %s (%s)\n"),
// 				prefix, strerror(errno));
// 		ret = 1;
// 		goto cleanup;
// 	}
//
// 	while(archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
// 		const char *entryname;
// 		mode_t mode;
//
// 		entryname = archive_entry_pathname(entry);
//
// 		/* If specific files were requested, skip entries that don't match. */
// 		if(list) {
// 			char *entry_prefix = strdup(entryname);
// 			char *p = strstr(entry_prefix,"/");
// 			if(p) {
// 				*(p + 1) = '\0';
// 			}
// 			char *found = list_find_str(list, entry_prefix);
// 			free(entry_prefix);
// 			if(!found) {
// 				if(archive_read_data_skip(archive) != ARCHIVE_OK) {
// 					ret = 1;
// 					goto cleanup;
// 				}
// 				continue;
// 			} else {
// 				_log(handle, ALPM_LOG_DEBUG, "extracting: %s\n", entryname);
// 			}
// 		}
//
// 		mode = archive_entry_mode(entry);
// 		if(S_ISREG(mode)) {
// 			archive_entry_set_perm(entry, 0644);
// 		} else if(S_ISDIR(mode)) {
// 			archive_entry_set_perm(entry, 0755);
// 		}
//
// 		/* Extract the archive entry. */
// 		int readret = archive_read_extract(archive, entry, 0);
// 		if(readret == ARCHIVE_WARN) {
// 			/* operation succeeded but a non-critical error was encountered */
// 			_log(handle, ALPM_LOG_WARNING, _("warning given when extracting %s (%s)\n"),
// 					entryname, archive_error_string(archive));
// 		} else if(readret != ARCHIVE_OK) {
// 			_log(handle, ALPM_LOG_ERROR, _("could not extract %s (%s)\n"),
// 					entryname, archive_error_string(archive));
// 			ret = 1;
// 			goto cleanup;
// 		}
//
// 		if(breakfirst) {
// 			break;
// 		}
// 	}
//
// cleanup:
// 	umask(oldmask);
// 	_archive_read_free(archive);
// 	close(fd);
// 	if(cwdfd >= 0) {
// 		if(fchdir(cwdfd) != 0) {
// 			_log(handle, ALPM_LOG_ERROR,
// 					_("could not restore working directory (%s)\n"), strerror(errno));
// 		}
// 		close(cwdfd);
// 	}
//
// 	return ret;
// }
//
// /** Determine if there are files in a directory.
//  * @param handle the context handle
//  * @param path the full absolute directory path
//  * @param full_count whether to return an exact count of files
//  * @return a file count if full_count is != 0, else >0 if directory has
//  * contents, 0 if no contents, and -1 on error
//  */
// ssize_t _files_in_directory(handle_t *handle, const char *path,
// 		int full_count)
// {
// 	ssize_t files = 0;
// 	struct dirent *ent;
// 	DIR *dir = opendir(path);
//
// 	if(!dir) {
// 		if(errno == ENOTDIR) {
// 			_log(handle, ALPM_LOG_DEBUG, "%s was not a directory\n", path);
// 		} else {
// 			_log(handle, ALPM_LOG_DEBUG, "could not read directory %s\n",
// 					path);
// 		}
// 		return -1;
// 	}
// 	while((ent = readdir(dir)) != NULL) {
// 		const char *name = ent->d_name;
//
// 		if(strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
// 			continue;
// 		}
//
// 		files++;
//
// 		if(!full_count) {
// 			break;
// 		}
// 	}
//
// 	closedir(dir);
// 	return files;
// }

// static int should_retry(int errnum)
// {
// 	return errnum == EAGAIN
// /* EAGAIN may be the same value as EWOULDBLOCK (POSIX.1) - prevent GCC warning */
// #if EAGAIN != EWOULDBLOCK
// 	|| errnum == EWOULDBLOCK
// #endif
// 	|| errnum == EINTR;
// }
//
// static int _chroot_write_to_child(handle_t *handle, int fd,
// 		char *buf, ssize_t *buf_size, ssize_t buf_limit,
// 		_cb_io out_cb, void *cb_ctx)
// {
// 	ssize_t nwrite;
//
// 	if(*buf_size == 0) {
// 		/* empty buffer, ask the callback for more */
// 		if((*buf_size = out_cb(buf, buf_limit, cb_ctx)) == 0) {
// 			/* no more to write, close the pipe */
// 			return -1;
// 		}
// 	}
//
// 	nwrite = send(fd, buf, *buf_size, MSG_NOSIGNAL);
//
// 	if(nwrite != -1) {
// 		/* write was successful, remove the written data from the buffer */
// 		*buf_size -= nwrite;
// 		memmove(buf, buf + nwrite, *buf_size);
// 	} else if(should_retry(errno)) {
// 		/* nothing written, try again later */
// 	} else {
// 		_log(handle, ALPM_LOG_ERROR,
// 				_("unable to write to pipe (%s)\n"), strerror(errno));
// 		return -1;
// 	}
//
// 	return 0;
// }
//
// static void _chroot_process_output(handle_t *handle, const char *line)
// {
// 	event_scriptlet_info_t event = {
// 		.type = ALPM_EVENT_SCRIPTLET_INFO,
// 		.line = line
// 	};
// 	logaction(handle, "ALPM-SCRIPTLET", "%s", line);
// 	EVENT(handle, &event);
// }

// static int _chroot_read_from_child(handle_t *handle, int fd,
// 		char *buf, ssize_t *buf_size, ssize_t buf_limit)
// {
// 	ssize_t space = buf_limit - *buf_size - 2; /* reserve 2 for "\n\0" */
// 	ssize_t nread = read(fd, buf + *buf_size, space);
// 	if(nread > 0) {
// 		char *newline = memchr(buf + *buf_size, '\n', nread);
// 		*buf_size += nread;
// 		if(newline) {
// 			while(newline) {
// 				size_t linelen = newline - buf + 1;
// 				char old = buf[linelen];
// 				buf[linelen] = '\0';
// 				_chroot_process_output(handle, buf);
// 				buf[linelen] = old;
//
// 				*buf_size -= linelen;
// 				memmove(buf, buf + linelen, *buf_size);
// 				newline = memchr(buf, '\n', *buf_size);
// 			}
// 		} else if(nread == space) {
// 			/* we didn't read a full line, but we're out of space */
// 			strcpy(buf + *buf_size, "\n");
// 			_chroot_process_output(handle, buf);
// 			*buf_size = 0;
// 		}
// 	} else if(nread == 0) {
// 		/* end-of-file */
// 		if(*buf_size) {
// 			strcpy(buf + *buf_size, "\n");
// 			_chroot_process_output(handle, buf);
// 		}
// 		return -1;
// 	} else if(should_retry(errno)) {
// 		/* nothing read, try again */
// 	} else {
// 		/* read error */
// 		if(*buf_size) {
// 			strcpy(buf + *buf_size, "\n");
// 			_chroot_process_output(handle, buf);
// 		}
// 		_log(handle, ALPM_LOG_ERROR,
// 				_("unable to read from pipe (%s)\n"), strerror(errno));
// 		return -1;
// 	}
// 	return 0;
// }

// /** Find a filename in a registered alpm cachedir.
//  * @param handle the context handle
//  * @param filename name of file to find
//  * @return malloced path of file, NULL if not found
//  */
// char *_filecache_find(handle_t *handle, const char *filename)
// {
// 	char path[PATH_MAX];
// 	char *retpath;
// 	list_t *i;
// 	struct stat buf;
//
// 	/* Loop through the cache dirs until we find a matching file */
// 	for(i = handle->cachedirs; i; i = i->next) {
// 		snprintf(path, PATH_MAX, "%s%s", (char *)i->data,
// 				filename);
// 		if(stat(path, &buf) == 0 && S_ISREG(buf.st_mode)) {
// 			retpath = strdup(path);
// 			_log(handle, ALPM_LOG_DEBUG, "found cached pkg: %s\n", retpath);
// 			return retpath;
// 		}
// 	}
// 	/* package wasn't found in any cachedir */
// 	return NULL;
// }

// /** Check the alpm cachedirs for existence and find a writable one.
//  * If no valid cache directory can be found, use /tmp.
//  * @param handle the context handle
//  * @return pointer to a writable cache directory.
//  */
// const char *_filecache_setup(handle_t *handle)
// {
// 	struct stat buf;
// 	list_t *i;
// 	char *cachedir;
// 	const char *tmpdir;
//
// 	/* Loop through the cache dirs until we find a usable directory */
// 	for(i = handle->cachedirs; i; i = i->next) {
// 		cachedir = i->data;
// 		if(stat(cachedir, &buf) != 0) {
// 			/* cache directory does not exist.... try creating it */
// 			_log(handle, ALPM_LOG_WARNING, _("no %s cache exists, creating...\n"),
// 					cachedir);
// 			if(_makepath(cachedir) == 0) {
// 				_log(handle, ALPM_LOG_DEBUG, "using cachedir: %s\n", cachedir);
// 				return cachedir;
// 			}
// 		} else if(!S_ISDIR(buf.st_mode)) {
// 			_log(handle, ALPM_LOG_DEBUG,
// 					"skipping cachedir, not a directory: %s\n", cachedir);
// 		} else if(_access(handle, NULL, cachedir, W_OK) != 0) {
// 			_log(handle, ALPM_LOG_DEBUG,
// 					"skipping cachedir, not writable: %s\n", cachedir);
// 		} else if(!(buf.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH))) {
// 			_log(handle, ALPM_LOG_DEBUG,
// 					"skipping cachedir, no write bits set: %s\n", cachedir);
// 		} else {
// 			_log(handle, ALPM_LOG_DEBUG, "using cachedir: %s\n", cachedir);
// 			return cachedir;
// 		}
// 	}
//
// 	/* we didn't find a valid cache directory. use TMPDIR or /tmp. */
// 	if((tmpdir = getenv("TMPDIR")) && stat(tmpdir, &buf) && S_ISDIR(buf.st_mode)) {
// 		/* TMPDIR was good, we can use it */
// 	} else {
// 		tmpdir = "/tmp";
// 	}
// 	option_add_cachedir(handle, tmpdir);
// 	cachedir = handle->cachedirs->prev->data;
// 	_log(handle, ALPM_LOG_DEBUG, "using cachedir: %s\n", cachedir);
// 	_log(handle, ALPM_LOG_WARNING,
// 			_("couldn't find or create package cache, using %s instead\n"), cachedir);
// 	return cachedir;
// }

// #if defined  HAVE_LIBSSL || defined HAVE_LIBNETTLE
// /** Compute the MD5 message digest of a file.
//  * @param path file path of file to compute  MD5 digest of
//  * @param output string to hold computed MD5 digest
//  * @return 0 on success, 1 on file open error, 2 on file read error
//  */
// static int md5_file(const char *path, unsigned char output[16])
// {
// #if HAVE_LIBSSL
// 	MD5_CTX ctx;
// #else /* HAVE_LIBNETTLE */
// 	struct md5_ctx ctx;
// #endif
// 	unsigned char *buf;
// 	ssize_t n;
// 	int fd;
//
// 	MALLOC(buf, (size_t)ALPM_BUFFER_SIZE, return 1);
//
// 	OPEN(fd, path, O_RDONLY | O_CLOEXEC);
// 	if(fd < 0) {
// 		free(buf);
// 		return 1;
// 	}
//
// #if HAVE_LIBSSL
// 	MD5_Init(&ctx);
// #else /* HAVE_LIBNETTLE */
// 	md5_init(&ctx);
// #endif
//
// 	while((n = read(fd, buf, ALPM_BUFFER_SIZE)) > 0 || errno == EINTR) {
// 		if(n < 0) {
// 			continue;
// 		}
// #if HAVE_LIBSSL
// 		MD5_Update(&ctx, buf, n);
// #else /* HAVE_LIBNETTLE */
// 		md5_update(&ctx, n, buf);
// #endif
// 	}
//
// 	close(fd);
// 	free(buf);
//
// 	if(n < 0) {
// 		return 2;
// 	}
//
// #if HAVE_LIBSSL
// 	MD5_Final(output, &ctx);
// #else /* HAVE_LIBNETTLE */
// 	md5_digest(&ctx, MD5_DIGEST_SIZE, output);
// #endif
// 	return 0;
// }

// /** Compute the SHA-256 message digest of a file.
//  * @param path file path of file to compute SHA256 digest of
//  * @param output string to hold computed SHA256 digest
//  * @return 0 on success, 1 on file open error, 2 on file read error
//  */
// static int sha256_file(const char *path, unsigned char output[32])
// {
// #if HAVE_LIBSSL
// 	SHA256_CTX ctx;
// #else /* HAVE_LIBNETTLE */
// 	struct sha256_ctx ctx;
// #endif
// 	unsigned char *buf;
// 	ssize_t n;
// 	int fd;
//
// 	MALLOC(buf, (size_t)ALPM_BUFFER_SIZE, return 1);
//
// 	OPEN(fd, path, O_RDONLY | O_CLOEXEC);
// 	if(fd < 0) {
// 		free(buf);
// 		return 1;
// 	}
//
// #if HAVE_LIBSSL
// 	SHA256_Init(&ctx);
// #else /* HAVE_LIBNETTLE */
// 	sha256_init(&ctx);
// #endif
//
// 	while((n = read(fd, buf, ALPM_BUFFER_SIZE)) > 0 || errno == EINTR) {
// 		if(n < 0) {
// 			continue;
// 		}
// #if HAVE_LIBSSL
// 		SHA256_Update(&ctx, buf, n);
// #else /* HAVE_LIBNETTLE */
// 		sha256_update(&ctx, n, buf);
// #endif
// 	}
//
// 	close(fd);
// 	free(buf);
//
// 	if(n < 0) {
// 		return 2;
// 	}
//
// #if HAVE_LIBSSL
// 	SHA256_Final(output, &ctx);
// #else /* HAVE_LIBNETTLE */
// 	sha256_digest(&ctx, SHA256_DIGEST_SIZE, output);
// #endif
// 	return 0;
// }
// #endif /* HAVE_LIBSSL || HAVE_LIBNETTLE */

/// Create a string representing bytes in hexadecimal.
fn hex_representation(bytes: Vec<u8>, size: usize) -> String {
    let mut ret = String::new();
    for byte in bytes {
        ret = format!("{}{:x}", ret, byte)
    }
    ret
}

/// Get the md5 sum of file.
fn compute_md5sum(filename: &str) -> String {
    // 	unsigned char output[16];
    //
    // 	ASSERT(filename != NULL, return NULL);
    //
    // 	if(md5_file(filename, output) > 0) {
    // 		return NULL;
    // 	}
    //
    // 	return hex_representation(output, 16);
    unimplemented!();
}

/// Get the sha256 sum of file.
fn compute_sha256sum(filename: &str) -> String {
    // 	unsigned char output[32];
    //
    // 	if(sha256_file(filename, output) > 0) {
    // 		return NULL;
    // 	}
    //
    // 	return hex_representation(output, 32);
    unimplemented!();
}

// /** Calculates a file's MD5 or SHA-2 digest and compares it to an expected value.
//  * @param filepath path of the file to check
//  * @param expected hash value to compare against
//  * @param type digest type to use
//  * @return 0 if file matches the expected hash, 1 if they do not match, -1 on
//  * error
//  */
// int _test_checksum(const char *filepath, const char *expected,
// 		pkgvalidation_t type)
// {
// 	char *computed;
// 	int ret;
//
// 	if(type == ALPM_PKG_VALIDATION_MD5SUM) {
// 		computed = compute_md5sum(filepath);
// 	} else if(type == ALPM_PKG_VALIDATION_SHA256SUM) {
// 		computed = compute_sha256sum(filepath);
// 	} else {
// 		return -1;
// 	}
//
// 	if(expected == NULL || computed == NULL) {
// 		ret = -1;
// 	} else if(strcmp(expected, computed) != 0) {
// 		ret = 1;
// 	} else {
// 		ret = 0;
// 	}
//
// 	FREE(computed);
// 	return ret;
// }

// /* Note: does NOT handle sparse files on purpose for speed. */
// /** TODO.
//  * Does not handle sparse files on purpose for speed.
//  * @param a
//  * @param b
//  * @return
//  */
// pub fn _archive_fgets(a: &mut FileReader, b: &archive_read_buffer) -> i32 {
//     // 	/* ensure we start populating our line buffer at the beginning */
//     // 	b->line_offset = b->line;
//     //
//     loop {
//         // 		size_t block_remaining;
//         // 		char *eol;
//         //
//         // 		/* have we processed this entire block? */
//         // 		if(b.block + b.block_size == b.block_offset) {
//         // 			int64_t offset;
//         // 			if(b->ret == ARCHIVE_EOF) {
//         // 				/* reached end of archive on the last read, now we are out of data */
//         // 				goto cleanup;
//         // 			}
//         //
//         // 			/* zero-copy - this is the entire next block of data. */
//         // 			b->ret = archive_read_data_block(a, (void *)&b->block,
//         // 					&b->block_size, &offset);
//         // 			b->block_offset = b->block;
//         // 			block_remaining = b->block_size;
//         //
//         // 			/* error, cleanup */
//         // 			if(b->ret < ARCHIVE_OK) {
//         // 				goto cleanup;
//         // 			}
//         // 		} else {
//         // 			block_remaining = b->block + b->block_size - b->block_offset;
//         // 		}
//         //
//         // 		/* look through the block looking for EOL characters */
//         // 		eol = memchr(b->block_offset, '\n', block_remaining);
//         // 		if(!eol) {
//         // 			eol = memchr(b->block_offset, '\0', block_remaining);
//         // 		}
//         //
//         // 		/* allocate our buffer, or ensure our existing one is big enough */
//         // 		if(!b->line) {
//         // 			/* set the initial buffer to the read block_size */
//         // 			CALLOC(b->line, b->block_size + 1, sizeof(char), b->ret = -ENOMEM; goto cleanup);
//         // 			b->line_size = b->block_size + 1;
//         // 			b->line_offset = b->line;
//         // 		} else {
//         // 			/* note: we know eol > b->block_offset and b->line_offset > b->line,
//         // 			 * so we know the result is unsigned and can fit in size_t */
//         // 			size_t new = eol ? (size_t)(eol - b->block_offset) : block_remaining;
//         // 			size_t needed = (size_t)((b->line_offset - b->line) + new + 1);
//         // 			if(needed > b->max_line_size) {
//         // 				b->ret = -ERANGE;
//         // 				goto cleanup;
//         // 			}
//         // 			if(needed > b->line_size) {
//         // 				/* need to realloc + copy data to fit total length */
//         // 				char *new_line;
//         // 				CALLOC(new_line, needed, sizeof(char), b->ret = -ENOMEM; goto cleanup);
//         // 				memcpy(new_line, b->line, b->line_size);
//         // 				b->line_size = needed;
//         // 				b->line_offset = new_line + (b->line_offset - b->line);
//         // 				free(b->line);
//         // 				b->line = new_line;
//         // 			}
//         // 		}
//         //
//         // 		if(eol) {
//         // 			size_t len = (size_t)(eol - b->block_offset);
//         // 			memcpy(b->line_offset, b->block_offset, len);
//         // 			b->line_offset[len] = '\0';
//         // 			b->block_offset = eol + 1;
//         // 			b->real_line_size = b->line_offset + len - b->line;
//         // 			/* this is the main return point; from here you can read b->line */
//         // 			return ARCHIVE_OK;
//         // 		} else {
//         // 			/* we've looked through the whole block but no newline, copy it */
//         // 			size_t len = (size_t)(b->block + b->block_size - b->block_offset);
//         // 			memcpy(b->line_offset, b->block_offset, len);
//         // 			b->line_offset += len;
//         // 			b->block_offset = b->block + b->block_size;
//         // 			/* there was no new data, return what is left; saved ARCHIVE_EOF will be
//         // 			 * returned on next call */
//         // 			if(len == 0) {
//         // 				b->line_offset[0] = '\0';
//         // 				b->real_line_size = b->line_offset - b->line;
//         // 				return ARCHIVE_OK;
//         // 			}
//         // 		}
//     }
//     //
//     // cleanup:
//     // 	{
//     // 		int ret = b->ret;
//     // 		FREE(b->line);
//     // 		memset(b, 0, sizeof(struct archive_read_buffer));
//     // 		return ret;
//     // 	}
//     unimplemented!();
// }

/** Parse a full package specifier.
 * @param target package specifier to parse, such as: "pacman-4.0.1-2",
 * "pacman-4.01-2/", or "pacman-4.0.1-2/desc"
 * @param name to hold package name
 * @param version to hold package version
 * @param name_hash to hold package name hash
 * @return 0 on success, -1 on error
 */
pub fn _splitname(target: &String) -> result::Result<(String, String), ()> {
    /* the format of a db entry is as follows:
     *    package-version-rel/
     *    package-version-rel/desc (we ignore the filename portion)
     * package name can contain hyphens, so parse from the back- go back
     * two hyphens and we have split the version from the name.
     */
    // 	const char *pkgver, *end;

    if target == "" {
        return Err(());
    }
    /* remove anything trailing a '/' */
    let tmp = String::from(target.split('/').collect::<Vec<&str>>()[0]);
    // 	end = strchr(target, '/');
    // 	if(!end) {
    // 		end = target + strlen(target);
    // 	}

    /* do the magic parsing- find the beginning of the version string
     * by doing two iterations of same loop to lop off two hyphens */
    // 	for(pkgver = end - 1; *pkgver && *pkgver != '-'; pkgver--);
    // 	for(pkgver = pkgver - 1; *pkgver && *pkgver != '-'; pkgver--);
    // 	if(*pkgver != '-' || pkgver == target) {
    // 		return -1;
    // 	}
    let temp2: Vec<&str> = tmp.split('-').collect();
    let len = temp2.len();
    if len < 3 {
        return Err(());
    }

    /* copy into fields and return */
    let mut name = String::from(temp2[0]);

    for i in 1..len - 2 {
        name += "-";
        name += temp2[i];
    }
    let version = String::from(temp2[len - 2]) + "-" + temp2[len - 1];

    // 	if(name) {
    // 		if(*name) {
    // 			FREE(*name);
    // 		}
    // 		STRNDUP(*name, target, pkgver - target, return -1);
    // 		if(name_hash) {
    // 			*name_hash = _hash_sdbm(*name);
    // 		}
    // 	}

    return Ok((name, version));
}

#[derive(Default)]
pub struct SdbmHasher {
    // /** Hash the given string to an unsigned long value.
    //  * This is the standard sdbm hashing algorithm.
    //  * @param str string to hash
    //  * @return the hash value of the given string
    //  */
    // unsigned long _hash_sdbm(const char *str)
    // {
    // 	unsigned long hash = 0;
    // 	int c;
    //
    // 	if(!str) {
    // 		return hash;
    // 	}
    // 	while((c = *str++)) {
    // 		hash = c + hash * 65599;
    // 	}
    //
    // 	return hash;
    // }
    hash: Wrapping<u64>,
}
use std::hash::Hasher;
impl Hasher for SdbmHasher {
    fn finish(&self) -> u64 {
        self.hash.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.hash = Wrapping(*byte as u64) + self.hash * Wrapping(65599);
        }
    }
}

/// Convert a string to a file offset.
/// This parses bare positive integers only.
pub fn _strtoofft(line: &String) -> i64 {
    /* we are trying to parse bare numbers only, no leading anything */
    if !line.chars().collect::<Vec<char>>()[0].is_numeric() {
        return -1;
    }
    match i64::from_str_radix(line, 10) {
        Ok(r) => r,
        Err(_) => -1,
    }
}

/// Parses a date into an time_t struct.
/// @param line date to parse
/// @return time struct on success, 0 on error
pub fn _parsedate(line: &str) -> Time {
    match i64::from_str_radix(line, 10) {
        Ok(r) => r,
        Err(_) => 0,
    }
}

// /** Wrapper around access() which takes a dir and file argument
//  * separately and generates an appropriate error message.
//  * If dir is NULL file will be treated as the whole path.
//  * @param handle an alpm handle
//  * @param dir directory path ending with and slash
//  * @param file filename
//  * @param amode access mode as described in access()
//  * @return int value returned by access()
//  */
// pub fn _access(
//     handle: &handle_t,
//     diro: Option<&String>,
//     file: &String,
//     amode: i32,
// ) -> i32 {
//     unimplemented!();
//     // 	size_t len = 0;
//     // 	int ret = 0;
//     let ret;
//     use std::os::unix::fs::PermissionsExt;
//     let dir = match diro {
//         Some(dir) => {
//             let check_path = format!("{}{}", dir, file);
//             ret = std::fs::metadata(check_path).unwrap().permissions().mode() & amode;
//             dir;
//         }
//         _ => {
//             // dir = "";
//             ret = std::fs::metadata(file).unwrap().permissions().mode() & amode;
//             String::from("");
//         }
//     };
//
//     if ret != 0 {
//         // 		if(amode & R_OK) {
//         // 			_log(handle, ALPM_LOG_DEBUG, "\"%s%s\" is not readable: %s\n",
//         // 					dir, file, strerror(errno));
//         // 		}
//         // 		if(amode & W_OK) {
//         // 			_log(handle, ALPM_LOG_DEBUG, "\"%s%s\" is not writable: %s\n",
//         // 					dir, file, strerror(errno));
//         // 		}
//         // 		if(amode & X_OK) {
//         // 			_log(handle, ALPM_LOG_DEBUG, "\"%s%s\" is not executable: %s\n",
//         // 					dir, file, strerror(errno));
//         // 		}
//         // 		if(amode == F_OK) {
//         // 			_log(handle, ALPM_LOG_DEBUG, "\"%s%s\" does not exist: %s\n",
//         // 					dir, file, strerror(errno));
//         // 		}
//     }
//     return ret;
// }

// /** Checks whether a string matches at least one shell wildcard pattern.
//  * Checks for matches with fnmatch. Matches are inverted by prepending
//  * patterns with an exclamation mark. Preceding exclamation marks may be
//  * escaped. Subsequent matches override previous ones.
//  * @param patterns patterns to match against
//  * @param string string to check against pattern
//  * @return 0 if string matches pattern, negative if they don't match and
//  * positive if the last match was inverted
//  */
// int _fnmatch_patterns(list_t *patterns, const char *string)
// {
// 	list_t *i;
// 	char *pattern;
// 	short inverted;
//
// 	for(i = list_last(patterns); i; i = list_previous(i)) {
// 		pattern = i->data;
//
// 		inverted = pattern[0] == '!';
// 		if(inverted || pattern[0] == '\\') {
// 			pattern++;
// 		}
//
// 		if(_fnmatch(pattern, string) == 0) {
// 			return inverted;
// 		}
// 	}
//
// 	return -1;
// }
//
// /** Checks whether a string matches a shell wildcard pattern.
//  * Wrapper around fnmatch.
//  * @param pattern pattern to match against
//  * @param string string to check against pattern
//  * @return 0 if string matches pattern, non-zero if they don't match and on
//  * error
//  */
// int _fnmatch(const void *pattern, const void *string)
// {
// 	return fnmatch(pattern, string, 0);
// }
//
// /** Think of this as realloc with error handling. If realloc fails NULL will be
//  * returned and data will not be changed.
//  *
//  * Newly created memory will be zeroed.
//  *
//  * @param data source memory space
//  * @param current size of the space pointed to by data
//  * @param required size you want
//  * @return new memory; NULL on error
//  */
// void *_realloc(void **data, size_t *current, const size_t required)
// {
// 	char *newdata;
//
// 	newdata = realloc(*data, required);
// 	if(!newdata) {
// 		_alloc_fail(required);
// 		return NULL;
// 	}
//
// 	if (*current < required) {
// 		/* ensure all new memory is zeroed out, in both the initial
// 		 * allocation and later reallocs */
// 		memset(newdata + *current, 0, required - *current);
// 	}
// 	*current = required;
// 	*data = newdata;
// 	return newdata;
// }
//
// /** This automatically grows data based on current/required.
//  *
//  * The memory space will be initialised to required bytes and doubled in size when required.
//  *
//  * Newly created memory will be zeroed.
//  * @param data source memory space
//  * @param current size of the space pointed to by data
//  * @param required size you want
//  * @return new memory if grown; old memory otherwise; NULL on error
//  */
// void *_greedy_grow(void **data, size_t *current, const size_t required)
// {
// 	size_t newsize = 0;
//
// 	if(*current >= required) {
// 		return data;
// 	}
//
// 	if(*current == 0) {
// 		newsize = required;
// 	} else {
// 		newsize = *current * 2;
// 	}
//
// 	/* check for overflows */
// 	if (newsize < required) {
// 		return NULL;
// 	}
//
// 	return _realloc(data, current, newsize);
// }
//
// void _alloc_fail(size_t size)
// {
// 	fprintf(stderr, "alloc failure: could not allocate %zu bytes\n", size);
// }
//
// /* vim: set noet: */
// /*
//  *  util.h
//  *
//  *  Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
//  *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
//  *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
//  *  Copyright (c) 2005 by Christian Hamar <krics@linuxforum.hu>
//  *  Copyright (c) 2006 by David Kimpe <dnaku@frugalware.org>
//  *  Copyright (c) 2005, 2006 by Miklos Vajna <vmiklos@frugalware.org>
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
// #ifndef ALPM_UTIL_H
// #define ALPM_UTIL_H
//
// #include "list.h"
// #include "alpm.h"
// #include "package.h" /* pkg_t */
// #include "handle.h" /* handle_t */
// #include "util-common.h"
//
// #include <stdio.h>
// #include <string.h>
// #include <stdarg.h>
// #include <stddef.h> /* size_t */
// #include <sys/types.h>
// #include <math.h> /* fabs */
// #include <float.h> /* DBL_EPSILON */
// #include <fcntl.h> /* open, close */
//
// #include <archive.h> /* struct archive */
//
// #ifdef ENABLE_NLS
// #include <libintl.h> /* here so it doesn't need to be included elsewhere */
// /* define _() as shortcut for gettext() */
// #define _(str) dgettext ("libalpm", str)
// #else
// #define _(s) (char *)s
// #endif
//
// void _alloc_fail(size_t size);
//
// #define MALLOC(p, s, action) do { p = malloc(s); if(p == NULL) { _alloc_fail(s); action; } } while(0)
// #define CALLOC(p, l, s, action) do { p = calloc(l, s); if(p == NULL) { _alloc_fail(l * s); action; } } while(0)
// /* This strdup macro is NULL safe- copying NULL will yield NULL */
// #define STRDUP(r, s, action) do { if(s != NULL) { r = strdup(s); if(r == NULL) { _alloc_fail(strlen(s)); action; } } else { r = NULL; } } while(0)
// #define STRNDUP(r, s, l, action) do { if(s != NULL) { r = strndup(s, l); if(r == NULL) { _alloc_fail(l); action; } } else { r = NULL; } } while(0)
//
// #define FREE(p) do { free(p); p = NULL; } while(0)
//
// #define ASSERT(cond, action) do { if(!(cond)) { action; } } while(0)

// macro_rules! RET_ERR {
// 	($handle:expr, $err:expr, $ret:expr) => {{
// 		// _log(handle, ALPM_LOG_DEBUG, "returning error %d from %s : %s\n", err, __func__, strerror(err));
// 		 	($handle).pm_errno = $err;
// 		 	return $ret;
// 	}}
// }

// macro_rules! RET_ERR {
// 	($handle:expr, $err:expr, $ret:expr) => {{
// 		// _log(handle, ALPM_LOG_DEBUG, "returning error %d from %s : %s\n", err, __func__, strerror(err));
// 		 	return Err($err);
// 	}}
// }

// #define RET_ERR_VOID(handle, err) do { \
// 	_log(handle, ALPM_LOG_DEBUG, "returning error %d from %s : %s\n", err, __func__, strerror(err)); \
// 	(handle)->pm_errno = (err); \
// 	return; } while(0)
//
// #define RET_ERR(handle, err, ret) do { \
// 	_log(handle, ALPM_LOG_DEBUG, "returning error %d from %s : %s\n", err, __func__, strerror(err)); \
// 	(handle)->pm_errno = (err); \
// 	return (ret); } while(0)
//
// #define RET_ERR_ASYNC_SAFE(handle, err, ret) do { \
// 	(handle)->pm_errno = (err); \
// 	return (ret); } while(0)
//
// #define DOUBLE_EQ(x, y) (fabs((x) - (y)) < DBL_EPSILON)
//
// #define CHECK_HANDLE(handle, action) do { if(!(handle)) { action; } (handle)->pm_errno = ALPM_ERR_OK; } while(0)
//
// /** Standard buffer size used throughout the library. */
// #ifdef BUFSIZ
// #define ALPM_BUFFER_SIZE BUFSIZ
// #else
// #define ALPM_BUFFER_SIZE 8192
// #endif
//
// #ifndef O_BINARY
// #define O_BINARY 0
// #endif
//
// #define OPEN(fd, path, flags) do { fd = open(path, flags | O_BINARY); } while(fd == -1 && errno == EINTR)
//

/// Used as a buffer/state holder for _archive_fgets().
// pub struct archive_read_buffer {
//     line: String,
//     line_offset: String,
//     line_size: usize,
//     max_line_size: usize,
//     real_line_size: usize,
//
//     block: String,
//     block_offset: String,
//     block_size: usize,
//
//     ret: i32,
// }

// int _makepath(const char *path);
// int _makepath_mode(const char *path, mode_t mode);
// int _copyfile(const char *src, const char *dest);
// size_t _strip_newline(char *str, size_t len);
//
// int _open_archive(handle_t *handle, const char *path,
// 		struct stat *buf, struct archive **archive, errno_t error);
// int _unpack_single(handle_t *handle, const char *archive,
// 		const char *prefix, const char *filename);
// int _unpack(handle_t *handle, const char *archive, const char *prefix,
// 		list_t *list, int breakfirst);
//
// ssize_t _files_in_directory(handle_t *handle, const char *path, int full_count);
//
// typedef ssize_t (*_cb_io)(void *buf, ssize_t len, void *ctx);
//
// int _run_chroot(handle_t *handle, const char *cmd, char *const argv[],
// 		_cb_io in_cb, void *in_ctx);
// int _ldconfig(handle_t *handle);
// int _str_cmp(const void *s1, const void *s2);
// char *_filecache_find(handle_t *handle, const char *filename);
// const char *_filecache_setup(handle_t *handle);
// /* Unlike many uses of pkgvalidation_t, _test_checksum expects
//  * an enum value rather than a bitfield. */
// int _test_checksum(const char *filepath, const char *expected, pkgvalidation_t type);
// int _archive_fgets(struct archive *a, struct archive_read_buffer *b);
// int _splitname(const char *target, char **name, char **version,
// 		unsigned long *name_hash);
// unsigned long _hash_sdbm(const char *str);
// off_t _strtoofft(const char *line);
// time_t _parsedate(const char *line);
// int _raw_cmp(const char *first, const char *second);
// int _raw_ncmp(const char *first, const char *second, size_t max);
// int _access(handle_t *handle, const char *dir, const char *file, int amode);
// int _fnmatch_patterns(list_t *patterns, const char *string);
// int _fnmatch(const void *pattern, const void *string);
// void *_realloc(void **data, size_t *current, const size_t required);
// void *_greedy_grow(void **data, size_t *current, const size_t required);
//
// #ifndef HAVE_STRSEP
// char *strsep(char **, const char *);
// #endif
//
// /* check exported library symbols with: nm -C -D <lib> */
// #define SYMEXPORT __attribute__((visibility("default")))
// #define SYMHIDDEN __attribute__((visibility("internal")))
//
// #define UNUSED __attribute__((unused))
//
// #endif /* ALPM_UTIL_H */
//
// /* vim: set noet: */

// macro_rules! EVENT
// { ($h:expr, $e:expr) =>
//     {{
// 	// if(($h).eventcb) {
// 		let f = ($h).eventcb;
//         f(($e));
// 	// }
// }}
// }

pub fn string_display(title: &str, string: &String) {
    let mut output = String::new();
    output += &format!("{:<15}: ", title);
    if string == "" {
        output += "None";
    } else {
        /* compute the length of title + a space */
        output += string;
    }
    info!("{}", output);
}

/// output a string, but wrap words properly with a specified indentation
fn indentprint(sstr: &String, indent: usize) {
    print!("{}", sstr);
    //TODO: actually do this
    // unimplemented!();
    // // 	wchar_t *wcstr;
    // // 	const wchar_t *p;
    // // 	size_t len, cidx;
    // let len;
    // let cidx;

    /* if we're not a tty, or our tty is not wide enough that wrapping even makes
     * sense, print without indenting */
    // if cols == 0 || indent > cols {
    //     print!("{}", sstr);
    //     return;
    // }

    // len = sstr.len() + 1;
    // // 	wcstr = calloc(len, sizeof(wchar_t));
    // // len = mbstowcs(wcstr, sstr, len);
    // // 	p = wcstr;
    // cidx = indent;
    // //
    // // 	if(!p || !len) {
    // // 		free(wcstr);
    // // 		return;
    // // 	}
    // //
    // for p in sstr.chars() {
    //     if p == ' ' {
    //         			// const wchar_t *q, *next;
    //         			p++;
    //         			if(p == NULL || *p == L' ') continue;
    //         			next = wcschr(p, L' ');
    //         			if(next == NULL) {
    //         				next = p + wcslen(p);
    //         			}
    //         			/* len captures # cols */
    //         			len = 0;
    //         			q = p;
    //         			while(q < next) {
    //         				len += wcwidth(*q++);
    //         			}
    //         			if((len + 1) > (cols - cidx)) {
    //         				/* wrap to a newline and reindent */
    //         				printf("\n%-*s", (int)indent, "");
    //         				cidx = indent;
    //         			} else {
    //         				printf(" ");
    //         				cidx++;
    //         			}
    //         			continue;
    //     }
    //     		printf("{}", (p);
    //     // 		cidx += wcwidth(*p);
    //     // 		p++;
    // }
    // // 	free(wcstr);
}

pub fn list_display(title: &str, list: &Vec<String>) {
    let mut output = String::new();
    if title != "" {
        output += &format!("{:15}:", title);
    }
    let mut len = 17;
    if list.is_empty() {
        output += "None";
    } else {
        for (i, item) in list.iter().enumerate() {
            len += item.len() + 1;
            if len > 80 {
                info!("{}", output);
                output = format!("{:17}", "");
                len = 17;
            } else {
                output += " ";
            }
            output += item;
        }
        info!("{}", output);
    }
}

/// Turn a depends list into a text list.
pub fn deplist_display(title: &str, deps: &Vec<Dependency>) {
    let mut text = Vec::new();
    for dep in deps {
        text.push(dep.dep_compute_string());
    }
    list_display(title, &text);
}

/** Converts sizes in bytes into human readable units.
 *
 * @param bytes the size in bytes
 * @param target_unit '\0' or a short label. If equal to one of the short unit
 * labels ('B', 'K', ...) bytes is converted to target_unit; if '\0', the first
 * unit which will bring the value to below a threshold of 2048 will be chosen.
 * @param precision number of decimal places, ensures -0.00 gets rounded to
 * 0.00; -1 if no rounding desired
 * @param label will be set to the appropriate unit label
 *
 * @return the size in the appropriate unit
 */
pub fn humanize_size(bytes: i64, label: &mut String) -> f64 {
    let labels = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"];
    let unitcount = labels.len();

    let mut val = bytes as f64;
    let mut index = 0;

    while index < unitcount - 1 && (val >= 2048.0 || val <= -2048.0) {
        val /= 1024.0;
        index += 1;
    }

    *label = String::from(labels[index]);
    val
}
