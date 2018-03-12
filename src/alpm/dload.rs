use std::path::Path;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::fs::{metadata, remove_file};
use std::time::{Duration, UNIX_EPOCH};
use curl::easy::{Easy2 as Curl, NetRc, TimeCondition};
use std::env;
use {Error, Handle, Result, StdResult};

/*
 *  download.c
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

// #ifdef HAVE_NETINET_IN_H
// #include <netinet/in.h> /* IPPROTO_TCP */
// #endif
// #ifdef HAVE_NETINET_TCP_H
// #include <netinet/tcp.h> /* TCP_KEEPINTVL, TCP_KEEPIDLE */
// #endif
//
// #ifdef HAVE_LIBCURL
// #include <curl/curl.h>
// #endif
//
// /* libalpm */
// #include "dload.h"
// #include "list.h"
// #include "alpm.h"
// #include "log.h"
// #include "util.h"
// #include "handle.h"

#[derive(Debug)]
pub struct DownloadPayload {
    // Handle *handle;
    tempfile_openmode: fs::OpenOptions,
    pub remote_name: OsString,
    pub tempfile_name: String,
    pub destfile_name: String,
    pub content_disp_name: String,
    pub fileurl: String,
    // list_t *servers;
    respcode: u32,
    initial_size: u64,
    pub max_size: u64,
    // off_t prevprogress;
    pub force: bool,
    pub allow_resume: bool,
    pub errors_ok: bool,
    pub unlink_on_fail: bool,
    pub trust_remote_name: bool,
    // #ifdef HAVE_LIBCURL
    // CURLcode curlerr;       /* last error produced by curl */
    // #endif
    disable_timeout: bool,
}

// #ifdef HAVE_LIBCURL
// fn get_filename(url: Path) -> String
// {
// url.split('/').last();
// }

fn get_fullpath(path: &str, filename: &str, suffix: &str) -> String {
    format!("{}{}{}", path, filename, suffix)
}

// static CURL *get_libcurl_handle(Handle *handle)
// {
// 	if(!handle->curl) {
// 		curl_global_init(CURL_GLOBAL_SSL);
// 		handle->curl = curl_easy_init();
// 	}
// 	return handle->curl;
// }
//
// enum {
// 	ABORT_SIGINT = 1,
// 	ABORT_OVER_MAXFILESIZE
// };

// static int dload_interrupted;
// static void inthandler(int UNUSED signum)
// {
// 	dload_interrupted = ABORT_SIGINT;
// }

fn curl_gethost(url: &str) -> Option<String> {
    // 	size_t hostlen;
    // 	char *p, *q;

    if url.starts_with("file://") {
        Some("disk".to_string())
    } else {
        let mut p: Vec<&str> = url.splitn(2, "//").collect();
        if p.len() != 2 {
            return None;
        }

        p = p[1].split("/").collect();

        /* there might be a user:pass@ on the URL. hide it. avoid using memrchr()
         * for portability concerns. */
        p = p[0].split('@').collect();

        Some(p[p.len() - 1].to_string())
    }
}

fn utimes_long(path: &str, seconds: u64) -> i32 {
    // 	if(seconds != -1) {
    // 		struct timeval tv[2];
    // 		memset(&tv, 0, sizeof(tv));
    // 		tv[0].tv_sec = tv[1].tv_sec = seconds;
    // 		return utimes(path, tv);
    // 	}
    // 	return 0;
    unimplemented!();
}

// /* prefix to avoid possible future clash with getumask(3) */
// static mode_t _getumask(void)
// {
// 	mode_t mask = umask(0);
// 	umask(mask);
// 	return mask;
// }

// static void mask_signal(int signum, void (*handler)(int),
// 		struct sigaction *origaction)
// {
// 	struct sigaction newaction;
//
// 	newaction.sa_handler = handler;
// 	sigemptyset(&newaction.sa_mask);
// 	newaction.sa_flags = 0;
//
// 	sigaction(signum, NULL, origaction);
// 	sigaction(signum, &newaction, NULL);
// }

use curl::easy::{Handler, WriteError};

struct Collector {
    pub initial_size: f64,
    localf: fs::File,
}

impl Collector {
    pub fn new(localf: fs::File, initial_size: f64) -> Self {
        Collector {
            initial_size: initial_size,
            localf: localf,
        }
    }
}

impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> StdResult<usize, WriteError> {
        use std::io::Write;
        Ok(self.localf.write(data).unwrap())
    }

    fn progress(&mut self, dltotal: f64, dlnow: f64, ultotal: f64, ulnow: f64) -> bool {
        // 	struct dload_payload *payload = (struct dload_payload *)file;
        // 	off_t current_size, total_size;
        let current_size;
        let total_size;

        // 	/* avoid displaying progress bar for redirects with a body */
        // 	if(payload->respcode >= 300) {
        // 		return 0;
        // 	}

        // 	/* SIGINT sent, abort by alerting curl */
        // 	if(dload_interrupted) {
        // 		return 1;
        // 	}

        current_size = self.initial_size + dlnow;

        // 	/* is our filesize still under any set limit? */
        // 	if(payload->max_size && current_size > payload->max_size) {
        // 		dload_interrupted = ABORT_OVER_MAXFILESIZE;
        // 		return 1;
        // 	}

        // 	/* none of what follows matters if the front end has no callback */
        // 	if(payload->handle->dlcb == NULL) {
        // 		return 0;
        // 	}

        total_size = self.initial_size + dltotal;

        // 	if(dltotal == 0 || payload->prevprogress == total_size) {
        // 		return 0;
        // 	}

        /* initialize the progress bar here to avoid displaying it when
         * a repo is up to date and nothing gets downloaded.
         * payload->handle->dlcb will receive the remote_name
         * and the following arguments:
         * 0, -1: download initialized
         * 0, 0: non-download event
         * x {x>0}, x: download complete
         * x {x>0, x<y}, y {y > 0}: download progress, expected total is known */
        // if(current_size == total_size) {
        // 		payload->handle->dlcb(payload->remote_name, dlnow, dltotal);
        // 	} else if(!payload->prevprogress) {
        // 		payload->handle->dlcb(payload->remote_name, 0, -1);
        // 	} else if(payload->prevprogress == current_size) {
        // 		payload->handle->dlcb(payload->remote_name, 0, 0);
        // 	} else {
        // 	/* do NOT include initial_size since it wasn't part of the package's
        // 	 * download_size (nor included in the total download size callback) */
        // 		payload->handle->dlcb(payload->remote_name, dlnow, dltotal);
        // 	}

        // 	payload->prevprogress = current_size;

        // 	return 0;
        // unimplemented!();
        return true;
    }

    fn header(&mut self, data: &[u8]) -> bool {
        // 	size_t realsize = size * nmemb;
        // 	const char *fptr, *endptr = NULL;
        // 	const char * const cd_header = "Content-Disposition:";
        // 	const char * const fn_key = "filename=";
        // 	struct dload_payload *payload = (struct dload_payload *)user;
        // 	long respcode;
        //
        // 	if(_raw_ncmp(cd_header, ptr, strlen(cd_header)) == 0) {
        // 		if((fptr = strstr(ptr, fn_key))) {
        // 			fptr += strlen(fn_key);
        //
        // 			/* find the end of the field, which is either a semi-colon, or the end of
        // 			 * the data. As per curl_easy_setopt(3), we cannot count on headers being
        // 			 * null terminated, so we look for the closing \r\n */
        // 			endptr = fptr + strcspn(fptr, ";\r\n") - 1;
        //
        // 			/* remove quotes */
        // 			if(*fptr == '"' && *endptr == '"') {
        // 				fptr++;
        // 				endptr--;
        // 			}
        //
        // 			STRNDUP(payload->content_disp_name, fptr, endptr - fptr + 1,
        // 					RET_ERR(payload->handle, ALPM_ERR_MEMORY, realsize));
        // 		}
        // }
        // 	curl_easy_getinfo(payload->handle->curl, CURLINFO_RESPONSE_CODE, &respcode);
        // 	if(payload->respcode != respcode) {
        // 		payload->respcode = respcode;
        // 	}

        // 	return realsize;
        // unimplemented!();
        return true;
    }
}

impl DownloadPayload {
    pub fn new(disable_timeout: bool) -> Self {
        DownloadPayload {
            // Handle *handle;
            tempfile_openmode: fs::OpenOptions::new(),
            remote_name: OsString::new(),
            tempfile_name: String::new(),
            destfile_name: String::new(),
            content_disp_name: String::new(),
            fileurl: String::new(),
            // list_t *servers;
            respcode: 0,
            initial_size: 0,
            max_size: 0,
            // off_t prevprogress;
            force: false,
            allow_resume: false,
            errors_ok: false,
            unlink_on_fail: false,
            trust_remote_name: false,
            disable_timeout: disable_timeout,
        }
    }

    fn create_tempfile(&self, localpath: &str) -> fs::File {
        // 	int fd;
        // 	FILE *fp;
        // 	char *randpath;
        // 	size_t len;
        //
        // 	/* create a random filename, which is opened with O_EXCL */
        // 	len = strlen(localpath) + 14 + 1;
        // 	MALLOC(randpath, len, RET_ERR(payload->handle, ALPM_ERR_MEMORY, NULL));
        // 	snprintf(randpath, len, "%salpmtmp.XXXXXX", localpath);
        // 	if((fd = mkstemp(randpath)) == -1 ||
        // 			fchmod(fd, ~(_getumask()) & 0666) ||
        // 			!(fp = fdopen(fd, payload->tempfile_openmode))) {
        // 		unlink(randpath);
        // 		close(fd);
        // 		_log(payload->handle, ALPM_LOG_ERROR,
        // 				_("failed to create temporary file for download\n"));
        // 		free(randpath);
        // 		return NULL;
        // 	}
        // 	/* fp now points to our alpmtmp.XXXXXX */
        // 	free(payload->tempfile_name);
        // 	payload->tempfile_name = randpath;
        // 	free(payload->remote_name);
        // 	STRDUP(payload->remote_name, strrchr(randpath, '/') + 1,
        // 			fclose(fp); RET_ERR(payload->handle, ALPM_ERR_MEMORY, NULL));
        //
        // 	return fp;
        unimplemented!();
    }

    fn curl_download_internal(&mut self, localpath: &String) -> Result<(String, String, i32)> {
        let mut ret = -1;
        let localf;
        let mut final_file = String::new();
        let effective_url: String;
        let mut hostname;

        self.tempfile_openmode.write(true).create(true);
        if self.remote_name == OsStr::new("") {
            self.remote_name = Path::new(&self.fileurl).file_name().unwrap().to_os_string();
        }

        hostname = match curl_gethost(&self.fileurl) {
            Some(h) => h,
            None => {
                error!("url '{}' is invalid", self.fileurl);
                return Err(Error::ServerBadUrl);
            }
        };

        if self.remote_name.len() > 0 && self.remote_name != OsStr::new(".sig") {
            self.destfile_name =
                format!("{}{}", localpath, self.remote_name.to_str().unwrap_or(""));
            self.tempfile_name = format!(
                "{}{}{}",
                localpath,
                self.remote_name.to_str().unwrap_or(""),
                ".part"
            );
            localf = match self.tempfile_openmode.open(&self.tempfile_name) {
                Ok(f) => f,
                Err(e) => {
                    error!("could not open file {}: {}", self.tempfile_name, e);
                    // goto cleanup;
                    unimplemented!();
                    return Err(Error::Retrive);
                }
            };
        } else {
            /* URL doesn't contain a filename, so make a tempfile. We can't support
             * resuming this kind of download; partial transfers will be destroyed */
            self.unlink_on_fail = true;

            localf = self.create_tempfile(localpath);
            // 		if(localf == NULL) {
            // 			goto cleanup;
            // 		}
        }

        match (self.allow_resume, metadata(&self.tempfile_name)) {
            (true, Ok(st)) => {
                /* a previous partial download exists, resume from end of file. */
                self.tempfile_openmode.append(true);
                self.initial_size = st.len();
            }
            _ => {}
        }

        let collector = Collector::new(localf, self.initial_size as f64);
        let mut curl: Curl<Collector> = Curl::new(collector);

        self.curl_set_handle_opts(&mut curl)?;

        debug!("opened tempfile for download: {}", self.tempfile_name);

        /* perform transfer */
        match curl.perform() {
            Ok(()) => {
                /* get http/ftp response code */
                self.respcode = curl.response_code().unwrap_or(0);
                debug!("response code: {}", self.respcode);
                if self.respcode >= 400 {
                    self.unlink_on_fail = true;
                    // if(!payload->errors_ok) {
                    // 	/* non-translated message is same as libcurl */
                    // 	snprintf(error_buffer, sizeof(error_buffer),
                    // 			"The requested URL returned error: %ld", payload->respcode);
                    // 	_log(handle, ALPM_LOG_ERROR,
                    // 			_("failed retrieving file '%s' from %s : %s\n"),
                    // 			payload->remote_name, hostname, error_buffer);
                    // }
                    // goto cleanup;
                }
            }
            Err(ref e) if e.is_aborted_by_callback() => {
                /* handle the interrupt accordingly */
                // 			if(dload_interrupted == ABORT_OVER_MAXFILESIZE) {
                // 				payload->curlerr = CURLE_FILESIZE_EXCEEDED;
                // 				payload->unlink_on_fail = 1;
                // 				handle->pm_errno = ALPM_ERR_LIBCURL;
                // 				_log(handle, ALPM_LOG_ERROR,
                // 						_("failed retrieving file '%s' from %s : expected download size exceeded\n"),
                // 						payload->remote_name, hostname);
                // 			}
                // 			goto cleanup;
                unimplemented!();
            }
            e => {
                /* delete zero length downloads */
                // 			if(fstat(fileno(localf), &st) == 0 && st.st_size == 0) {
                // 				payload->unlink_on_fail = 1;
                // 			}
                // 			if(!payload->errors_ok) {
                // 				handle->pm_errno = ALPM_ERR_LIBCURL;
                // 				_log(handle, ALPM_LOG_ERROR,
                // 						_("failed retrieving file '%s' from %s : %s\n"),
                // 						payload->remote_name, hostname, error_buffer);
                // 			} else {
                debug!(
                    "failed retrieving file '{}' from {} : {:?}\n",
                    self.remote_name.to_str().unwrap(),
                    hostname,
                    e
                );
                // 			}
                // 			goto cleanup;
                unimplemented!();
            }
        }

        // debug!("curl returned error {} from transfer", payload.curlerr);

        /* disconnect relationships from the curl handle for things that might go out
         * of scope, but could still be touched on connection teardown. This really
         * only applies to FTP transfers. */
        curl.progress(true)?;

        /* retrieve info about the state of the transfer */
        let remote_time = curl.filetime();
        let timecond = curl.time_condition_unmet()?;
        let bytes_dl = curl.download_size()?;
        let mut effective_url = curl.effective_url()?;
        // 	curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &remote_size);

        let final_url;
        if let Some(effective_url) = effective_url {
            final_url = effective_url;
        } else {
            final_url = "";
        }

        /* time condition was met and we didn't download anything. we need to
         * clean up the 0 byte .part file that's left behind. */
        if timecond && bytes_dl == 0f64 {
            debug!("file met time condition");
            remove_file(&self.tempfile_name)?;
            return Ok((final_file, final_url.to_string(), 1));
        }

        /* remote_size isn't necessarily the full size of the file, just what the
         * server reported as remaining to download. compare it to what curl reported
         * as actually being transferred during curl_easy_perform() */
        // if remote_size != -1 && bytes_dl != -1f64 && bytes_dl != remote_size {
        //     		handle->pm_errno = ALPM_ERR_RETRIEVE;
        //     		error("%s appears to be truncated: %jd/%jd bytes",
        //     				payload->remote_name, (intmax_t)bytes_dl, (intmax_t)remote_size);
        //     		goto cleanup;
        // }

        if self.trust_remote_name {
            if self.content_disp_name != "" {
                /* content-disposition header has a better name for our file */
                self.destfile_name = get_fullpath(localpath, &self.content_disp_name, "");
            } else {
                // 			const char *effective_filename = strrchr(effective_url, '/');
                // 			if(effective_filename && strlen(effective_filename) > 2) {
                // 				effective_filename++;

                /* if destfile was never set, we wrote to a tempfile. even if destfile is
                 * set, we may have followed some redirects and the effective url may
                 * have a better suggestion as to what to name our file. in either case,
                 * refactor destfile to this newly derived name. */
                // 				if(!self.destfile_name || strcmp(effective_filename,
                // 							strrchr(self.destfile_name, '/') + 1) != 0) {
                // 					payload->destfile_name = get_fullpath(localpath, effective_filename, "");
                // 				}
                // 			}
            }
        }

        ret = 0;

        /* cleanup: */
        // 		utimes_long(payload->tempfile_name, remote_time);

        if ret == 0 {
            let mut realname = &self.tempfile_name;
            if self.destfile_name != "" {
                realname = &self.destfile_name;
                if let Err(e) = fs::rename(&self.tempfile_name, &self.destfile_name) {
                    error!(
                        "could not rename {} to {} ({})",
                        self.tempfile_name, self.destfile_name, e
                    );
                    ret = -1;
                    final_file = Path::new(realname)
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap_or("")
                        .to_string();
                }
            }
        }

        if ret == -1 && self.unlink_on_fail && self.tempfile_name != "" {
            remove_file(&self.tempfile_name)?;
        }

        // 	return ret;
        return Ok((final_file, final_url.to_string(), ret));
    }

    fn curl_set_handle_opts(
        &self,
        curl: &mut Curl<Collector>, /*char *error_buffer*/
    ) -> Result<()> {
        let useragent = env::var("HTTP_USER_AGENT");

        /* the curl_easy handle is initialized with the alpm handle, so we only need
         * to reset the handle's parameters for each time it's used. */
        curl.reset();
        curl.url(&self.fileurl)?;
        curl.timeout(Duration::from_secs(10))?;
        curl.progress(true)?;
        curl.fetch_filetime(true)?;
        curl.follow_location(true)?;

        if !self.disable_timeout {
            curl.low_speed_limit(1)?;
            curl.low_speed_time(Duration::from_secs(10))?;
        }

        curl.netrc(NetRc::Optional)?;
        curl.tcp_keepalive(true)?;
        curl.tcp_keepidle(Duration::from_secs(60))?;
        curl.tcp_keepintvl(Duration::from_secs(60))?;

        debug!("url: {}", self.fileurl);

        if self.max_size != 0 {
            debug!("maxsize: {}", self.max_size);
            curl.max_filesize(self.max_size)?;
        }

        if let Ok(useragent) = useragent {
            curl.useragent(&useragent)?;
        }

        match (
            self.allow_resume,
            !self.force && self.destfile_name != "",
            metadata(&self.destfile_name),
            metadata(&self.tempfile_name),
        ) {
            (false, true, Ok(st), _) => {
                /* start from scratch, but only download if our local is out of date. */
                curl.time_condition(TimeCondition::IfModifiedSince)?;
                curl.time_value(st.modified()?.duration_since(UNIX_EPOCH)?.as_secs() as i64)?;
                debug!(
                    "using time condition: {}",
                    st.modified()?.duration_since(UNIX_EPOCH)?.as_secs()
                );
            }
            (true, _, _, Ok(st)) => {
                /* a previous partial download exists, resume from end of file. */
                curl.resume_from(st.len())?;
                debug!(
                    "tempfile found, attempting continuation from {} bytes",
                    st.len()
                );
            }
            _ => {}
        }

        Ok(())
    }

    /// Download a file given by a URL to a local directory.
    /// Does not overwrite an existing file if the download fails.
    /// @param payload the payload context
    /// * @param localpath the directory to save the file in
    /// * @param final_file the real name of the downloaded file (may be NULL)
    /// * @return 0 on success, -1 on error (pm_errno is set accordingly if errors_ok == 0)
    pub fn download(&mut self, localpath: &String) -> Result<(String, String, i32)> {
        // 	Handle *handle = payload->handle;

        // if handle.fetchcb == NULL {
        // #ifdef HAVE_LIBCURL
        return self.curl_download_internal(localpath);
        // #else
        // 		/* work around unused warnings when building without libcurl */
        // 		(void)final_file;
        // 		(void)final_url;
        // 		RET_ERR(handle, ALPM_ERR_EXTERNAL_DOWNLOAD, -1);
        // #endif
        // } else {
        // let ret = 0;
        // 		int ret = handle->fetchcb(payload->fileurl, localpath, payload->force);
        // 		if(ret == -1 && !payload->errors_ok) {
        // 			RET_ERR(handle, ALPM_ERR_EXTERNAL_DOWNLOAD, -1);
        // 		}
        // return ret;
        // }
        unimplemented!();
    }

    pub fn reset(&mut self) {
        self.remote_name = OsString::new();
        self.tempfile_name = String::new();
        self.destfile_name = String::new();
        self.content_disp_name = String::new();
        self.fileurl = String::new();
    }
}
// static char *filecache_find_url(Handle *handle, const char *url)
// {
// 	const char *filebase = strrchr(url, '/');
//
// 	if(filebase == NULL) {
// 		return NULL;
// 	}
//
// 	filebase++;
// 	if(*filebase == '\0') {
// 		return NULL;
// 	}
//
// 	return _filecache_find(handle, filebase);
// }

impl Handle {
    /** Fetch a remote pkg. */
    pub fn fetch_pkgurl(&self, url: &String) -> Result<String> {
        unimplemented!();
        // 	char *filepath;
        // 	const char *cachedir, *final_pkg_url = NULL;
        // 	char *final_file = NULL;
        // 	struct dload_payload payload;
        // 	int ret = 0;
        //
        // 	CHECK_HANDLE(handle, return NULL);
        // 	ASSERT(url, RET_ERR(handle, ALPM_ERR_WRONG_ARGS, NULL));
        //
        // 	/* find a valid cache dir to download to */
        // 	cachedir = _filecache_setup(handle);
        //
        // 	memset(&payload, 0, sizeof(struct dload_payload));
        //
        // 	/* attempt to find the file in our pkgcache */
        // 	filepath = filecache_find_url(handle, url);
        // 	if(filepath == NULL) {
        // 		STRDUP(payload.fileurl, url, RET_ERR(handle, ALPM_ERR_MEMORY, NULL));
        // 		payload.allow_resume = 1;
        // 		payload.handle = handle;
        // 		payload.trust_remote_name = 1;
        //
        // 		/* download the file */
        // 		ret = _download(&payload, cachedir, &final_file, &final_pkg_url);
        // 		_dload_payload_reset(&payload);
        // 		if(ret == -1) {
        // 			_log(handle, ALPM_LOG_WARNING, _("failed to download %s\n"), url);
        // 			free(final_file);
        // 			return NULL;
        // 		}
        // 		_log(handle, ALPM_LOG_DEBUG, "successfully downloaded %s\n", url);
        // 	}
        //
        // 	/* attempt to download the signature */
        // 	if(ret == 0 && final_pkg_url && (handle->siglevel & ALPM_SIG_PACKAGE)) {
        // 		char *sig_filepath, *sig_final_file = NULL;
        // 		size_t len;
        //
        // 		len = strlen(final_pkg_url) + 5;
        // 		MALLOC(payload.fileurl, len, free(final_file); RET_ERR(handle, ALPM_ERR_MEMORY, NULL));
        // 		snprintf(payload.fileurl, len, "%s.sig", final_pkg_url);
        //
        // 		sig_filepath = filecache_find_url(handle, payload.fileurl);
        // 		if(sig_filepath == NULL) {
        // 			payload.handle = handle;
        // 			payload.trust_remote_name = 1;
        // 			payload.force = 1;
        // 			payload.errors_ok = (handle->siglevel & ALPM_SIG_PACKAGE_OPTIONAL);
        //
        // 			/* set hard upper limit of 16KiB */
        // 			payload.max_size = 16 * 1024;
        //
        // 			ret = _download(&payload, cachedir, &sig_final_file, NULL);
        // 			if(ret == -1 && !payload.errors_ok) {
        // 				_log(handle, ALPM_LOG_WARNING,
        // 						_("failed to download %s\n"), payload.fileurl);
        // 				/* Warn now, but don't return NULL. We will fail later during package
        // 				 * load time. */
        // 			} else if(ret == 0) {
        // 				_log(handle, ALPM_LOG_DEBUG,
        // 						"successfully downloaded %s\n", payload.fileurl);
        // 			}
        // 			FREE(sig_final_file);
        // 		}
        // 		free(sig_filepath);
        // 		_dload_payload_reset(&payload);
        // 	}
        //
        // 	/* we should be able to find the file the second time around */
        // 	if(filepath == NULL) {
        // 		filepath = _filecache_find(handle, final_file);
        // 	}
        // 	free(final_file);
        //
        // 	return filepath;
    }
}

// void _dload_payload_reset_for_retry(struct dload_payload *payload)
// {
// 	ASSERT(payload, return);
//
// 	FREE(payload->fileurl);
// 	payload->initial_size += payload->prevprogress;
// 	payload->prevprogress = 0;
// 	payload->unlink_on_fail = 0;
// }
//
// /* vim: set noet: */
