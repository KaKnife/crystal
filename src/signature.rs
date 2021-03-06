use std::ops::{BitAnd, BitOr, Not};
use alpm::PgpKey;
use Handle;

/// PGP signature verification options
#[derive(Default, Clone, Debug, Copy)]
pub struct SigLevel {
    pub package: bool,
    pub package_optional: bool,
    pub package_marginal_ok: bool,
    pub package_unknown_ok: bool,

    pub database: bool,
    pub database_optional: bool,
    pub database_marginal_ok: bool,
    pub database_unknown_ok: bool,

    pub use_default: bool,
}

impl BitOr for SigLevel {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        let mut new = SigLevel::default();
        new.package = self.package | rhs.package;
        new.package_optional = self.package_optional | rhs.package_optional;
        new.package_marginal_ok = self.package_marginal_ok | rhs.package_marginal_ok;
        new.package_unknown_ok = self.package_unknown_ok | rhs.package_unknown_ok;

        new.database = self.database | rhs.database;
        new.database_optional = self.database_optional | rhs.database_optional;
        new.database_marginal_ok = self.database_marginal_ok | rhs.database_marginal_ok;
        new.database_unknown_ok = self.database_unknown_ok | rhs.database_unknown_ok;

        new.use_default = self.use_default | rhs.use_default;
        new
    }
}

impl BitAnd for SigLevel {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        let mut new = SigLevel::default();
        new.package = self.package & rhs.package;
        new.package_optional = self.package_optional & rhs.package_optional;
        new.package_marginal_ok = self.package_marginal_ok & rhs.package_marginal_ok;
        new.package_unknown_ok = self.package_unknown_ok & rhs.package_unknown_ok;

        new.database = self.database & rhs.database;
        new.database_optional = self.database_optional & rhs.database_optional;
        new.database_marginal_ok = self.database_marginal_ok & rhs.database_marginal_ok;
        new.database_unknown_ok = self.database_unknown_ok & rhs.database_unknown_ok;

        new.use_default = self.use_default & rhs.use_default;
        new
    }
}

impl Not for SigLevel {
    type Output = Self;
    fn not(self) -> Self {
        let mut new = SigLevel::default();
        new.package = self.package;
        new.package_optional = self.package_optional;
        new.package_marginal_ok = self.package_marginal_ok;
        new.package_unknown_ok = self.package_unknown_ok;

        new.database = self.database;
        new.database_optional = self.database_optional;
        new.database_marginal_ok = self.database_marginal_ok;
        new.database_unknown_ok = self.database_unknown_ok;

        new.use_default = self.use_default;
        new
    }
}

impl SigLevel {
    pub fn not_zero(&self) -> bool {
        !(self.package || self.package_optional || self.package_marginal_ok
            || self.package_unknown_ok || self.database || self.database_optional
            || self.database_marginal_ok || self.database_unknown_ok || self.use_default)
    }
}

/// PGP signature verification status return codes
#[derive(Debug, Clone)]
pub enum SignatureStatus {
    Valid,
    KeyExpired,
    SigExpired,
    Unknown,
    KeyDisabled,
    Invalid,
}
impl Default for SignatureStatus {
    fn default() -> Self {
        SignatureStatus::Valid
    }
}

/// PGP signature verification status return codes
#[derive(Debug, Clone)]
pub enum SigValidity {
    Full,
    Marginal,
    Never,
    Unknown,
}
impl Default for SigValidity {
    fn default() -> Self {
        SigValidity::Unknown
    }
}

/// Signature result. Contains the key, status, and validity of a given
/// signature.
#[derive(Debug, Clone, Default)]
struct SignatureResult {
    key: PgpKey,
    status: SignatureStatus,
    validity: SigValidity,
}

/// Signature list. Contains the number of signatures found and a pointer to an
/// array of results. The array is of size count.
#[derive(Debug, Clone, Default)]
pub struct SignatureList {
    count: usize,
    results: SignatureResult,
}

// #ifdef HAVE_LIBGPGME
// #include <locale.h> /* setlocale() */
// #include <gpgme.h>
// #endif

// /**
//  * Decode a loaded signature in base64 form.
//  * @param base64_data the signature to attempt to decode
//  * @param data the decoded data; must be freed by the caller
//  * @param data_len the length of the returned data
//  * @return 0 on success, -1 on failure to properly decode
//  */
//
// int SYMEXPORT decode_signature(const char *base64_data,
// 		unsigned char **data, size_t *data_len)
// {
// 	size_t len = strlen(base64_data);
// 	unsigned char *usline = (unsigned char *)base64_data;
// 	/* reasonable allocation of expected length is 3/4 of encoded length */
// 	size_t destlen = len * 3 / 4;
// 	MALLOC(*data, destlen, goto error);
// 	if(base64_decode(*data, &destlen, usline, len)) {
// 		free(*data);
// 		goto error;
// 	}
// 	*data_len = destlen;
// 	return 0;
//
// error:
// 	*data = NULL;
// 	*data_len = 0;
// 	return -1;
// }
//
// #ifdef HAVE_LIBGPGME
// #define CHECK_ERR(void) do { \
// 		if(gpg_err_code(gpg_err) != GPG_ERR_NO_ERROR) { goto gpg_error; } \
// 	} while(0)
//
// /**
//  * Return a statically allocated validity string based on the GPGME validity
//  * code. This is mainly for debug purposes and is not translated.
//  * @param validity a validity code returned by GPGME
//  * @return a string such as "marginal"
//  */
// static const char *string_validity(gpgme_validity_t validity)
// {
// 	switch(validity) {
// 		case GPGME_VALIDITY_UNKNOWN:
// 			return "unknown";
// 		case GPGME_VALIDITY_UNDEFINED:
// 			return "undefined";
// 		case GPGME_VALIDITY_NEVER:
// 			return "never";
// 		case GPGME_VALIDITY_MARGINAL:
// 			return "marginal";
// 		case GPGME_VALIDITY_FULL:
// 			return "full";
// 		case GPGME_VALIDITY_ULTIMATE:
// 			return "ultimate";
// 	}
// 	return "???";
// }
//
// static void sigsum_test_bit(gpgme_sigsum_t sigsum, list_t **summary,
// 		gpgme_sigsum_t bit, const char *value)
// {
// 	if(sigsum & bit) {
// 		*summary = list_add(*summary, (void *)value);
// 	}
// }
//
// /**
//  * Calculate a set of strings to represent the given GPGME signature summary
//  * value. This is a bitmask so you may get any number of strings back.
//  * @param sigsum a GPGME signature summary bitmask
//  * @return the list of signature summary strings
//  */
// static list_t *list_sigsum(gpgme_sigsum_t sigsum)
// {
// 	list_t *summary = NULL;
// 	/* The docs say this can be a bitmask...not sure I believe it, but we'll code
// 	 * for it anyway and show all possible flags in the returned string. */
//
// 	/* The signature is fully valid. */
// 	sigsum_test_bit(sigsum, &summary, GPGME_SIGSUM_VALID, "valid");
// 	/* The signature is good. */
// 	sigsum_test_bit(sigsum, &summary, GPGME_SIGSUM_GREEN, "green");
// 	/* The signature is bad. */
// 	sigsum_test_bit(sigsum, &summary, GPGME_SIGSUM_RED, "red");
// 	/* One key has been revoked. */
// 	sigsum_test_bit(sigsum, &summary, GPGME_SIGSUM_KEY_REVOKED, "key revoked");
// 	/* One key has expired. */
// 	sigsum_test_bit(sigsum, &summary, GPGME_SIGSUM_KEY_EXPIRED, "key expired");
// 	/* The signature has expired. */
// 	sigsum_test_bit(sigsum, &summary, GPGME_SIGSUM_SIG_EXPIRED, "sig expired");
// 	/* Can't verify: key missing. */
// 	sigsum_test_bit(sigsum, &summary, GPGME_SIGSUM_KEY_MISSING, "key missing");
// 	/* CRL not available. */
// 	sigsum_test_bit(sigsum, &summary, GPGME_SIGSUM_CRL_MISSING, "crl missing");
// 	/* Available CRL is too old. */
// 	sigsum_test_bit(sigsum, &summary, GPGME_SIGSUM_CRL_TOO_OLD, "crl too old");
// 	/* A policy was not met. */
// 	sigsum_test_bit(sigsum, &summary, GPGME_SIGSUM_BAD_POLICY, "bad policy");
// 	/* A system error occurred. */
// 	sigsum_test_bit(sigsum, &summary, GPGME_SIGSUM_SYS_ERROR, "sys error");
// 	/* Fallback case */
// 	if(!sigsum) {
// 		summary = list_add(summary, (void *)"(empty)");
// 	}
// 	return summary;
// }
//
// /**
//  * Initialize the GPGME library.
//  * This can be safely called multiple times; however it is not thread-safe.
//  * @param handle the context handle
//  * @return 0 on success, -1 on error
//  */
// static int init_gpgme(Handle *handle)
// {
// 	static int init = 0;
// 	const char *version, *sigdir;
// 	gpgme_error_t gpg_err;
// 	gpgme_engine_info_t enginfo;
//
// 	if(init) {
// 		/* we already successfully initialized the library */
// 		return 0;
// 	}
//
// 	sigdir = handle->gpgdir;
//
// 	if(_access(handle, sigdir, "pubring.gpg", R_OK)
// 			|| _access(handle, sigdir, "trustdb.gpg", R_OK)) {
// 		handle->pm_errno = ALPM_ERR_NOT_A_FILE;
// 		_log(handle, ALPM_LOG_DEBUG, "Signature verification will fail!\n");
// 		_log(handle, ALPM_LOG_WARNING,
// 				_("Public keyring not found; have you run '%s'?\n"),
// 				"pacman-key --init");
// 	}
//
// 	/* calling gpgme_check_version() returns the current version and runs
// 	 * some internal library setup code */
// 	version = gpgme_check_version(NULL);
// 	_log(handle, ALPM_LOG_DEBUG, "GPGME version: %s\n", version);
// 	gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
// #ifdef LC_MESSAGES
// 	gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
// #endif
// 	/* NOTE:
// 	 * The GPGME library installs a SIGPIPE signal handler automatically if
// 	 * the default signal hander is in use. The only time we set a handler
// 	 * for SIGPIPE is in dload.c, and we reset it when we are done. Given that
// 	 * we do this, we can let GPGME do its automagic. However, if we install
// 	 * a library-wide SIGPIPE handler, we will have to be careful.
// 	 */
//
// 	/* check for OpenPGP support (should be a no-brainer, but be safe) */
// 	gpg_err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
// 	CHECK_ERR();
//
// 	/* set and check engine information */
// 	gpg_err = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, NULL, sigdir);
// 	CHECK_ERR();
// 	gpg_err = gpgme_get_engine_info(&enginfo);
// 	CHECK_ERR();
// 	_log(handle, ALPM_LOG_DEBUG, "GPGME engine info: file=%s, home=%s\n",
// 			enginfo->file_name, enginfo->home_dir);
//
// 	init = 1;
// 	return 0;
//
// gpg_error:
// 	_log(handle, ALPM_LOG_ERROR, _("GPGME error: %s\n"), gpgme_strerror(gpg_err));
// 	RET_ERR(handle, ALPM_ERR_GPGME, -1);
// }
//
// /**
//  * Determine if we have a key is known in our local keyring.
//  * @param handle the context handle
//  * @param fpr the fingerprint key ID to look up
//  * @return 1 if key is known, 0 if key is unknown, -1 on error
//  */
// int _key_in_keychain(Handle *handle, const char *fpr)
// {
// 	gpgme_error_t gpg_err;
// 	gpgme_ctx_t ctx;
// 	gpgme_key_t key;
// 	int ret = -1;
//
// 	if(list_find_str(handle->known_keys, fpr)) {
// 		_log(handle, ALPM_LOG_DEBUG, "key %s found in cache\n", fpr);
// 		return 1;
// 	}
//
// 	if(init_gpgme(handle)) {
// 		/* pm_errno was set in gpgme_init() */
// 		goto error;
// 	}
//
// 	memset(&ctx, 0, sizeof(ctx));
// 	gpg_err = gpgme_new(&ctx);
// 	CHECK_ERR();
//
// 	_log(handle, ALPM_LOG_DEBUG, "looking up key %s locally\n", fpr);
//
// 	gpg_err = gpgme_get_key(ctx, fpr, &key, 0);
// 	if(gpg_err_code(gpg_err) == GPG_ERR_EOF) {
// 		_log(handle, ALPM_LOG_DEBUG, "key lookup failed, unknown key\n");
// 		ret = 0;
// 	} else if(gpg_err_code(gpg_err) == GPG_ERR_NO_ERROR) {
// 		_log(handle, ALPM_LOG_DEBUG, "key lookup success, key exists\n");
// 		handle->known_keys = list_add(handle->known_keys, strdup(fpr));
// 		ret = 1;
// 	} else {
// 		_log(handle, ALPM_LOG_DEBUG, "gpg error: %s\n", gpgme_strerror(gpg_err));
// 	}
// 	gpgme_key_unref(key);
//
// gpg_error:
// 	gpgme_release(ctx);
//
// error:
// 	return ret;
// }
//
// /**
//  * Search for a GPG key in a remote location.
//  * This requires GPGME to call the gpg binary and have a keyserver previously
//  * defined in a gpg.conf configuration file.
//  * @param handle the context handle
//  * @param fpr the fingerprint key ID to look up
//  * @param pgpkey storage location for the given key if found
//  * @return 1 on success, 0 on key not found, -1 on error
//  */
// static int key_search(Handle *handle, const char *fpr,
// 		pgpkey_t *pgpkey)
// {
// 	gpgme_error_t gpg_err;
// 	gpgme_ctx_t ctx;
// 	gpgme_keylist_mode_t mode;
// 	gpgme_key_t key;
// 	int ret = -1;
// 	size_t fpr_len;
// 	char *full_fpr;
//
// 	/* gpg2 goes full retard here. For key searches ONLY, we need to prefix the
// 	 * key fingerprint with 0x, or the lookup will fail. */
// 	fpr_len = strlen(fpr);
// 	MALLOC(full_fpr, fpr_len + 3, RET_ERR(handle, ALPM_ERR_MEMORY, -1));
// 	sprintf(full_fpr, "0x%s", fpr);
//
// 	memset(&ctx, 0, sizeof(ctx));
// 	gpg_err = gpgme_new(&ctx);
// 	CHECK_ERR();
//
// 	mode = gpgme_get_keylist_mode(ctx);
// 	/* using LOCAL and EXTERN together doesn't work for GPG 1.X. Ugh. */
// 	mode &= ~GPGME_KEYLIST_MODE_LOCAL;
// 	mode |= GPGME_KEYLIST_MODE_EXTERN;
// 	gpg_err = gpgme_set_keylist_mode(ctx, mode);
// 	CHECK_ERR();
//
// 	_log(handle, ALPM_LOG_DEBUG, "looking up key %s remotely\n", fpr);
//
// 	gpg_err = gpgme_get_key(ctx, full_fpr, &key, 0);
// 	if(gpg_err_code(gpg_err) == GPG_ERR_EOF) {
// 		_log(handle, ALPM_LOG_DEBUG, "key lookup failed, unknown key\n");
// 		/* Try an alternate lookup using the 8 character fingerprint value, since
// 		 * busted-ass keyservers can't support lookups using subkeys with the full
// 		 * value as of now. This is why 2012 is not the year of PGP encryption. */
// 		if(fpr_len > 8) {
// 			const char *short_fpr = memcpy(&full_fpr[fpr_len - 8], "0x", 2);
// 			_log(handle, ALPM_LOG_DEBUG,
// 					"looking up key %s remotely\n", short_fpr);
// 			gpg_err = gpgme_get_key(ctx, short_fpr, &key, 0);
// 			if(gpg_err_code(gpg_err) == GPG_ERR_EOF) {
// 				_log(handle, ALPM_LOG_DEBUG, "key lookup failed, unknown key\n");
// 				ret = 0;
// 			}
// 		} else {
// 			ret = 0;
// 		}
// 	}
//
// 	CHECK_ERR();
//
// 	/* should only get here if key actually exists */
// 	pgpkey->data = key;
// 	if(key->subkeys->fpr) {
// 		pgpkey->fingerprint = key->subkeys->fpr;
// 	} else if(key->subkeys->keyid) {
// 		pgpkey->fingerprint = key->subkeys->keyid;
// 	}
// 	pgpkey->uid = key->uids->uid;
// 	pgpkey->name = key->uids->name;
// 	pgpkey->email = key->uids->email;
// 	pgpkey->created = key->subkeys->timestamp;
// 	pgpkey->expires = key->subkeys->expires;
// 	pgpkey->length = key->subkeys->length;
// 	pgpkey->revoked = key->subkeys->revoked;
//
// 	/* Initialize with '?', this is overwritten unless public key
// 	 * algorithm is unknown. */
// 	pgpkey->pubkey_algo = '?';
//
// 	switch(key->subkeys->pubkey_algo) {
// 		case GPGME_PK_RSA:
// 		case GPGME_PK_RSA_E:
// 		case GPGME_PK_RSA_S:
// 			pgpkey->pubkey_algo = 'R';
// 			break;
//
// 		case GPGME_PK_DSA:
// 			pgpkey->pubkey_algo = 'D';
// 			break;
//
// 		case GPGME_PK_ELG_E:
// 		case GPGME_PK_ELG:
// 		case GPGME_PK_ECDSA:
// 		case GPGME_PK_ECDH:
// /* value added in gpgme 1.5.0 */
// #if GPGME_VERSION_NUMBER >= 0x010500
// 		case GPGME_PK_ECC:
// #endif
// /* value added in gpgme 1.7.0 */
// #if GPGME_VERSION_NUMBER >= 0x010700
// 		case GPGME_PK_EDDSA:
// #endif
// 			pgpkey->pubkey_algo = 'E';
// 			break;
// 	}
//
// 	ret = 1;
//
// 	/* We do not want to add a default switch case above to receive
// 	 * compiler error on new public key algorithm in gpgme. So check
// 	 * here if we have a valid pubkey_algo. */
// 	if (pgpkey->pubkey_algo == '?') {
// 		_log(handle, ALPM_LOG_DEBUG,
// 			"unknown public key algorithm: %d\n", key->subkeys->pubkey_algo);
// 	}
//
// gpg_error:
// 	if(ret != 1) {
// 		_log(handle, ALPM_LOG_DEBUG, "gpg error: %s\n", gpgme_strerror(gpg_err));
// 	}
// 	free(full_fpr);
// 	gpgme_release(ctx);
// 	return ret;
// }
//
// /**
//  * Import a key into the local keyring.
//  * @param handle the context handle
//  * @param key the key to import, likely retrieved from #key_search
//  * @return 0 on success, -1 on error
//  */
// static int key_import(Handle *handle, pgpkey_t *key)
// {
// 	gpgme_error_t gpg_err;
// 	gpgme_ctx_t ctx;
// 	gpgme_key_t keys[2];
// 	gpgme_import_result_t result;
// 	int ret = -1;
//
// 	if(_access(handle, handle->gpgdir, "pubring.gpg", W_OK)) {
// 		/* no chance of import succeeding if pubring isn't writable */
// 		_log(handle, ALPM_LOG_ERROR, _("keyring is not writable\n"));
// 		return -1;
// 	}
//
// 	memset(&ctx, 0, sizeof(ctx));
// 	gpg_err = gpgme_new(&ctx);
// 	CHECK_ERR();
//
// 	_log(handle, ALPM_LOG_DEBUG, "importing key\n");
//
// 	keys[0] = key->data;
// 	keys[1] = NULL;
// 	gpg_err = gpgme_op_import_keys(ctx, keys);
// 	CHECK_ERR();
// 	result = gpgme_op_import_result(ctx);
// 	/* we know we tried to import exactly one key, so check for this */
// 	if(result->considered != 1 || !result->imports) {
// 		_log(handle, ALPM_LOG_DEBUG, "could not import key, 0 results\n");
// 		ret = -1;
// 	} else if(result->imports->result != GPG_ERR_NO_ERROR) {
// 		_log(handle, ALPM_LOG_DEBUG, "gpg error: %s\n", gpgme_strerror(gpg_err));
// 		ret = -1;
// 	} else {
// 		ret = 0;
// 	}
//
// gpg_error:
// 	gpgme_release(ctx);
// 	return ret;
// }
//
// /**
//  * Import a key defined by a fingerprint into the local keyring.
//  * @param handle the context handle
//  * @param fpr the fingerprint key ID to import
//  * @return 0 on success, -1 on error
//  */
// int _key_import(Handle *handle, const char *fpr)
// {
// 	int ret = -1;
// 	pgpkey_t fetch_key;
// 	memset(&fetch_key, 0, sizeof(fetch_key));
//
// 	if(key_search(handle, fpr, &fetch_key) == 1) {
// 		_log(handle, ALPM_LOG_DEBUG,
// 				"unknown key, found %s on keyserver\n", fetch_key.uid);
// 		if(!_access(handle, handle->gpgdir, "pubring.gpg", W_OK)) {
// 			question_import_key_t question = {
// 				.type = ALPM_QUESTION_IMPORT_KEY,
// 				.import = 0,
// 				.key = &fetch_key
// 			};
// 			QUESTION(handle, &question);
// 			if(question.import) {
// 				if(key_import(handle, &fetch_key) == 0) {
// 					ret = 0;
// 				} else {
// 					_log(handle, ALPM_LOG_ERROR,
// 							_("key \"%s\" could not be imported\n"), fetch_key.uid);
// 				}
// 			}
// 		} else {
// 			/* keyring directory was not writable, so we don't even try */
// 			_log(handle, ALPM_LOG_WARNING,
// 					_("key %s, \"%s\" found on keyserver, keyring is not writable\n"),
// 					fetch_key.fingerprint, fetch_key.uid);
// 		}
// 	} else {
// 		_log(handle, ALPM_LOG_ERROR,
// 				_("key \"%s\" could not be looked up remotely\n"), fpr);
// 	}
// 	gpgme_key_unref(fetch_key.data);
//
// 	return ret;
// }
//
// /**
//  * Check the PGP signature for the given file path.
//  * If base64_sig is provided, it will be used as the signature data after
//  * decoding. If base64_sig is NULL, expect a signature file next to path
//  * (e.g. "%s.sig").
//  *
//  * The return value will be 0 if nothing abnormal happened during the signature
//  * check, and -1 if an error occurred while checking signatures or if a
//  * signature could not be found; pm_errno will be set. Note that "abnormal"
//  * does not include a failed signature; the value in siglist should be checked
//  * to determine if the signature(s) are good.
//  * @param handle the context handle
//  * @param path the full path to a file
//  * @param base64_sig optional PGP signature data in base64 encoding
//  * @param siglist a pointer to storage for signature results
//  * @return 0 in normal cases, -1 if the something failed in the check process
//  */
// int _gpgme_checksig(Handle *handle, const char *path,
// 		const char *base64_sig, siglist_t *siglist)
// {
// 	int ret = -1, sigcount;
// 	gpgme_error_t gpg_err = 0;
// 	gpgme_ctx_t ctx;
// 	gpgme_data_t filedata, sigdata;
// 	gpgme_verify_result_t verify_result;
// 	gpgme_signature_t gpgsig;
// 	char *sigpath = NULL;
// 	unsigned char *decoded_sigdata = NULL;
// 	FILE *file = NULL, *sigfile = NULL;
//
// 	if(!path || _access(handle, NULL, path, R_OK) != 0) {
// 		RET_ERR(handle, ALPM_ERR_NOT_A_FILE, -1);
// 	}
//
// 	if(!siglist) {
// 		RET_ERR(handle, ALPM_ERR_WRONG_ARGS, -1);
// 	}
// 	siglist->count = 0;
//
// 	if(!base64_sig) {
// 		sigpath = _sigpath(handle, path);
// 		if(_access(handle, NULL, sigpath, R_OK) != 0
// 				|| (sigfile = fopen(sigpath, "rb")) == NULL) {
// 			_log(handle, ALPM_LOG_DEBUG, "sig path %s could not be opened\n",
// 					sigpath);
// 			handle->pm_errno = ALPM_ERR_SIG_MISSING;
// 			goto error;
// 		}
// 	}
//
// 	/* does the file we are verifying exist? */
// 	file = fopen(path, "rb");
// 	if(file == NULL) {
// 		handle->pm_errno = ALPM_ERR_NOT_A_FILE;
// 		goto error;
// 	}
//
// 	if(init_gpgme(handle)) {
// 		/* pm_errno was set in gpgme_init() */
// 		goto error;
// 	}
//
// 	_log(handle, ALPM_LOG_DEBUG, "checking signature for %s\n", path);
//
// 	memset(&ctx, 0, sizeof(ctx));
// 	memset(&sigdata, 0, sizeof(sigdata));
// 	memset(&filedata, 0, sizeof(filedata));
//
// 	gpg_err = gpgme_new(&ctx);
// 	CHECK_ERR();
//
// 	/* create our necessary data objects to verify the signature */
// 	gpg_err = gpgme_data_new_from_stream(&filedata, file);
// 	CHECK_ERR();
//
// 	/* next create data object for the signature */
// 	if(base64_sig) {
// 		/* memory-based, we loaded it from a sync DB */
// 		size_t data_len;
// 		int decode_ret = decode_signature(base64_sig,
// 				&decoded_sigdata, &data_len);
// 		if(decode_ret) {
// 			handle->pm_errno = ALPM_ERR_SIG_INVALID;
// 			goto gpg_error;
// 		}
// 		gpg_err = gpgme_data_new_from_mem(&sigdata,
// 				(char *)decoded_sigdata, data_len, 0);
// 	} else {
// 		/* file-based, it is on disk */
// 		gpg_err = gpgme_data_new_from_stream(&sigdata, sigfile);
// 	}
// 	CHECK_ERR();
//
// 	/* here's where the magic happens */
// 	gpg_err = gpgme_op_verify(ctx, sigdata, filedata, NULL);
// 	CHECK_ERR();
// 	verify_result = gpgme_op_verify_result(ctx);
// 	CHECK_ERR();
// 	if(!verify_result || !verify_result->signatures) {
// 		_log(handle, ALPM_LOG_DEBUG, "no signatures returned\n");
// 		handle->pm_errno = ALPM_ERR_SIG_MISSING;
// 		goto gpg_error;
// 	}
// 	for(gpgsig = verify_result->signatures, sigcount = 0;
// 			gpgsig; gpgsig = gpgsig->next, sigcount++);
// 	_log(handle, ALPM_LOG_DEBUG, "%d signatures returned\n", sigcount);
//
// 	CALLOC(siglist->results, sigcount, sizeof(sigresult_t),
// 			handle->pm_errno = ALPM_ERR_MEMORY; goto gpg_error);
// 	siglist->count = sigcount;
//
// 	for(gpgsig = verify_result->signatures, sigcount = 0; gpgsig;
// 			gpgsig = gpgsig->next, sigcount++) {
// 		list_t *summary_list, *summary;
// 		sigstatus_t status;
// 		sigvalidity_t validity;
// 		gpgme_key_t key;
// 		sigresult_t *result;
//
// 		_log(handle, ALPM_LOG_DEBUG, "fingerprint: %s\n", gpgsig->fpr);
// 		summary_list = list_sigsum(gpgsig->summary);
// 		for(summary = summary_list; summary; summary = summary->next) {
// 			_log(handle, ALPM_LOG_DEBUG, "summary: %s\n", (const char *)summary->data);
// 		}
// 		list_free(summary_list);
// 		_log(handle, ALPM_LOG_DEBUG, "status: %s\n", gpgme_strerror(gpgsig->status));
// 		_log(handle, ALPM_LOG_DEBUG, "timestamp: %lu\n", gpgsig->timestamp);
//
// 		if((time_t)gpgsig->timestamp > time(NULL)) {
// 			_log(handle, ALPM_LOG_DEBUG,
// 					"signature timestamp is greater than system time.\n");
// 		}
//
// 		_log(handle, ALPM_LOG_DEBUG, "exp_timestamp: %lu\n", gpgsig->exp_timestamp);
// 		_log(handle, ALPM_LOG_DEBUG, "validity: %s; reason: %s\n",
// 				string_validity(gpgsig->validity),
// 				gpgme_strerror(gpgsig->validity_reason));
//
// 		result = siglist->results + sigcount;
// 		gpg_err = gpgme_get_key(ctx, gpgsig->fpr, &key, 0);
// 		if(gpg_err_code(gpg_err) == GPG_ERR_EOF) {
// 			_log(handle, ALPM_LOG_DEBUG, "key lookup failed, unknown key\n");
// 			gpg_err = GPG_ERR_NO_ERROR;
// 			/* we dupe the fpr in this case since we have no key to point at */
// 			STRDUP(result->key.fingerprint, gpgsig->fpr,
// 					handle->pm_errno = ALPM_ERR_MEMORY; goto gpg_error);
// 		} else {
// 			CHECK_ERR();
// 			if(key->uids) {
// 				result->key.data = key;
// 				result->key.fingerprint = key->subkeys->fpr;
// 				result->key.uid = key->uids->uid;
// 				result->key.name = key->uids->name;
// 				result->key.email = key->uids->email;
// 				result->key.created = key->subkeys->timestamp;
// 				result->key.expires = key->subkeys->expires;
// 				_log(handle, ALPM_LOG_DEBUG,
// 						"key: %s, %s, owner_trust %s, disabled %d\n",
// 						key->subkeys->fpr, key->uids->uid,
// 						string_validity(key->owner_trust), key->disabled);
// 			}
// 		}
//
// 		switch(gpg_err_code(gpgsig->status)) {
// 			/* good cases */
// 			case GPG_ERR_NO_ERROR:
// 				status = ALPM_SIGSTATUS_VALID;
// 				break;
// 			case GPG_ERR_KEY_EXPIRED:
// 				status = ALPM_SIGSTATUS_KEY_EXPIRED;
// 				break;
// 			/* bad cases */
// 			case GPG_ERR_SIG_EXPIRED:
// 				status = ALPM_SIGSTATUS_SIG_EXPIRED;
// 				break;
// 			case GPG_ERR_NO_PUBKEY:
// 				status = ALPM_SIGSTATUS_KEY_UNKNOWN;
// 				break;
// 			case GPG_ERR_BAD_SIGNATURE:
// 			default:
// 				status = ALPM_SIGSTATUS_INVALID;
// 				break;
// 		}
// 		/* special case: key disabled is not returned in above status code */
// 		if(result->key.data && key->disabled) {
// 			status = ALPM_SIGSTATUS_KEY_DISABLED;
// 		}
//
// 		switch(gpgsig->validity) {
// 			case GPGME_VALIDITY_ULTIMATE:
// 			case GPGME_VALIDITY_FULL:
// 				validity = ALPM_SIGVALIDITY_FULL;
// 				break;
// 			case GPGME_VALIDITY_MARGINAL:
// 				validity = ALPM_SIGVALIDITY_MARGINAL;
// 				break;
// 			case GPGME_VALIDITY_NEVER:
// 				validity = ALPM_SIGVALIDITY_NEVER;
// 				break;
// 			case GPGME_VALIDITY_UNKNOWN:
// 			case GPGME_VALIDITY_UNDEFINED:
// 			default:
// 				validity = ALPM_SIGVALIDITY_UNKNOWN;
// 				break;
// 		}
//
// 		result->status = status;
// 		result->validity = validity;
// 	}
//
// 	ret = 0;
//
// gpg_error:
// 	gpgme_data_release(sigdata);
// 	gpgme_data_release(filedata);
// 	gpgme_release(ctx);
//
// error:
// 	if(sigfile) {
// 		fclose(sigfile);
// 	}
// 	if(file) {
// 		fclose(file);
// 	}
// 	FREE(sigpath);
// 	FREE(decoded_sigdata);
// 	if(gpg_err_code(gpg_err) != GPG_ERR_NO_ERROR) {
// 		_log(handle, ALPM_LOG_ERROR, _("GPGME error: %s\n"), gpgme_strerror(gpg_err));
// 		RET_ERR(handle, ALPM_ERR_GPGME, -1);
// 	}
// 	return ret;
// }
//
// #else /* HAVE_LIBGPGME */
// int _key_in_keychain(Handle UNUSED *handle, const char UNUSED *fpr)
// {
// 	return -1;
// }
//
// int _key_import(Handle UNUSED *handle, const char UNUSED *fpr)
// {
// 	return -1;
// }
//
// int _gpgme_checksig(Handle UNUSED *handle, const char UNUSED *path,
// 		const char UNUSED *base64_sig, siglist_t UNUSED *siglist)
// {
// 	return -1;
// }
// #endif /* HAVE_LIBGPGME */

// /**
//  * Helper for checking the PGP signature for the given file path.
//  * This wraps #_gpgme_checksig in a slightly friendlier manner to simplify
//  * handling of optional signatures and marginal/unknown trust levels and
//  * handling the correct error code return values.
//  * @param handle the context handle
//  * @param path the full path to a file
//  * @param base64_sig optional PGP signature data in base64 encoding
//  * @param optional whether signatures are optional (e.g., missing OK)
//  * @param marginal whether signatures with marginal trust are acceptable
//  * @param unknown whether signatures with unknown trust are acceptable
//  * @param sigdata a pointer to storage for signature results
//  * @return 0 on success, -1 on error (consult pm_errno or sigdata)
//  */
pub fn check_pgp_helper(
    handle: &Handle,
    path: &String,
    base64_sig: Option<&String>,
    optional: bool,
    marginal: bool,
    unknown: bool,
    sigdata: &SignatureList,
) -> i32 {
    unimplemented!();
    // 	siglist_t *siglist;
    // 	int ret;
    //
    // 	CALLOC(siglist, 1, sizeof(siglist_t),
    // 			RET_ERR(handle, ALPM_ERR_MEMORY, -1));
    //
    // 	ret = _gpgme_checksig(handle, path, base64_sig, siglist);
    // 	if(ret && handle->pm_errno == ALPM_ERR_SIG_MISSING) {
    // 		if(optional) {
    // 			_log(handle, ALPM_LOG_DEBUG, "missing optional signature\n");
    // 			handle->pm_errno = ALPM_ERR_OK;
    // 			ret = 0;
    // 		} else {
    // 			_log(handle, ALPM_LOG_DEBUG, "missing required signature\n");
    // 			/* ret will already be -1 */
    // 		}
    // 	} else if(ret) {
    // 		_log(handle, ALPM_LOG_DEBUG, "signature check failed\n");
    // 		/* ret will already be -1 */
    // 	} else {
    // 		size_t num;
    // 		for(num = 0; !ret && num < siglist->count; num++) {
    // 			switch(siglist->results[num].status) {
    // 				case ALPM_SIGSTATUS_VALID:
    // 				case ALPM_SIGSTATUS_KEY_EXPIRED:
    // 					_log(handle, ALPM_LOG_DEBUG, "signature is valid\n");
    // 					switch(siglist->results[num].validity) {
    // 						case ALPM_SIGVALIDITY_FULL:
    // 							_log(handle, ALPM_LOG_DEBUG, "signature is fully trusted\n");
    // 							break;
    // 						case ALPM_SIGVALIDITY_MARGINAL:
    // 							_log(handle, ALPM_LOG_DEBUG, "signature is marginal trust\n");
    // 							if(!marginal) {
    // 								ret = -1;
    // 							}
    // 							break;
    // 						case ALPM_SIGVALIDITY_UNKNOWN:
    // 							_log(handle, ALPM_LOG_DEBUG, "signature is unknown trust\n");
    // 							if(!unknown) {
    // 								ret = -1;
    // 							}
    // 							break;
    // 						case ALPM_SIGVALIDITY_NEVER:
    // 							_log(handle, ALPM_LOG_DEBUG, "signature should never be trusted\n");
    // 							ret = -1;
    // 							break;
    // 					}
    // 					break;
    // 				case ALPM_SIGSTATUS_SIG_EXPIRED:
    // 				case ALPM_SIGSTATUS_KEY_UNKNOWN:
    // 				case ALPM_SIGSTATUS_KEY_DISABLED:
    // 				case ALPM_SIGSTATUS_INVALID:
    // 					_log(handle, ALPM_LOG_DEBUG, "signature is not valid\n");
    // 					ret = -1;
    // 					break;
    // 			}
    // 		}
    // 	}
    //
    // 	if(sigdata) {
    // 		*sigdata = siglist;
    // 	} else {
    // 		siglist_cleanup(siglist);
    // 		free(siglist);
    // 	}
    //
    // 	return ret;
}

// /**
//  * Examine a signature result list and take any appropriate or necessary
//  * actions. This may include asking the user to import a key or simply printing
//  * helpful failure messages so the user can take action out of band.
//  * @param handle the context handle
//  * @param identifier a friendly name for the signed resource; usually a
//  * database or package name
//  * @param siglist a pointer to storage for signature results
//  * @param optional whether signatures are optional (e.g., missing OK)
//  * @param marginal whether signatures with marginal trust are acceptable
//  * @param unknown whether signatures with unknown trust are acceptable
//  * @return 0 if all signatures are OK, -1 on errors, 1 if we should retry the
//  * validation process
//  */
pub fn process_siglist(
    handle: &Handle,
    identifier: &String,
    siglist: &SignatureList,
    optional: bool,
    marginal: bool,
    unknown: bool,
) -> i32 {
    unimplemented!();
    // 	size_t i;
    // 	int retry = 0;
    //
    // 	if(!optional && siglist->count == 0) {
    // 		_log(handle, ALPM_LOG_ERROR,
    // 				_("%s: missing required signature\n"), identifier);
    // 	}
    //
    // 	for(i = 0; i < siglist->count; i++) {
    // 		sigresult_t *result = siglist->results + i;
    // 		const char *name = result->key.uid ? result->key.uid : result->key.fingerprint;
    // 		switch(result->status) {
    // 			case ALPM_SIGSTATUS_VALID:
    // 			case ALPM_SIGSTATUS_KEY_EXPIRED:
    // 				switch(result->validity) {
    // 					case ALPM_SIGVALIDITY_FULL:
    // 						break;
    // 					case ALPM_SIGVALIDITY_MARGINAL:
    // 						if(!marginal) {
    // 							_log(handle, ALPM_LOG_ERROR,
    // 									_("%s: signature from \"%s\" is marginal trust\n"),
    // 									identifier, name);
    // 							/* QUESTION(handle, ALPM_QUESTION_EDIT_KEY_TRUST, &result->key, NULL, NULL, &answer); */
    // 						}
    // 						break;
    // 					case ALPM_SIGVALIDITY_UNKNOWN:
    // 						if(!unknown) {
    // 							_log(handle, ALPM_LOG_ERROR,
    // 									_("%s: signature from \"%s\" is unknown trust\n"),
    // 									identifier, name);
    // 							/* QUESTION(handle, ALPM_QUESTION_EDIT_KEY_TRUST, &result->key, NULL, NULL, &answer); */
    // 						}
    // 						break;
    // 					case ALPM_SIGVALIDITY_NEVER:
    // 						_log(handle, ALPM_LOG_ERROR,
    // 								_("%s: signature from \"%s\" should never be trusted\n"),
    // 								identifier, name);
    // 						break;
    // 				}
    // 				break;
    // 			case ALPM_SIGSTATUS_KEY_UNKNOWN:
    // 				/* ensure this key is still actually unknown; we may have imported it
    // 				 * on an earlier call to this function. */
    // 				if(_key_in_keychain(handle, result->key.fingerprint) == 1) {
    // 					break;
    // 				}
    // 				_log(handle, ALPM_LOG_ERROR,
    // 						_("%s: key \"%s\" is unknown\n"), identifier, name);
    //
    // 				if(_key_import(handle, result->key.fingerprint) == 0) {
    // 					retry = 1;
    // 				}
    //
    // 				break;
    // 			case ALPM_SIGSTATUS_KEY_DISABLED:
    // 				_log(handle, ALPM_LOG_ERROR,
    // 						_("%s: key \"%s\" is disabled\n"), identifier, name);
    // 				break;
    // 			case ALPM_SIGSTATUS_SIG_EXPIRED:
    // 				_log(handle, ALPM_LOG_ERROR,
    // 						_("%s: signature from \"%s\" is expired\n"), identifier, name);
    // 				break;
    // 			case ALPM_SIGSTATUS_INVALID:
    // 				_log(handle, ALPM_LOG_ERROR,
    // 						_("%s: signature from \"%s\" is invalid\n"),
    // 						identifier, name);
    // 				break;
    // 		}
    // 	}
    //
    // 	return retry;
}

// /**
//  * Check the PGP signature for the given package file.
//  * @param pkg the package to check
//  * @param siglist a pointer to storage for signature results
//  * @return a int value : 0 (valid), 1 (invalid), -1 (an error occurred)
//  */
// int SYMEXPORT pkg_check_pgp_signature(pkg_t *pkg,
// 		siglist_t *siglist)
// {
// 	ASSERT(pkg != NULL, return -1);
// 	ASSERT(siglist != NULL, RET_ERR(pkg->handle, ALPM_ERR_WRONG_ARGS, -1));
// 	pkg->handle->pm_errno = ALPM_ERR_OK;
//
// 	return _gpgme_checksig(pkg->handle, pkg->filename,
// 			pkg->base64_sig, siglist);
// }
//
// /**
//  * Check the PGP signature for the given database.
//  * @param db the database to check
//  * @param siglist a pointer to storage for signature results
//  * @return a int value : 0 (valid), 1 (invalid), -1 (an error occurred)
//  */
// int SYMEXPORT db_check_pgp_signature(db_t *db,
// 		siglist_t *siglist)
// {
// 	ASSERT(db != NULL, return -1);
// 	ASSERT(siglist != NULL, RET_ERR(db->handle, ALPM_ERR_WRONG_ARGS, -1));
// 	db->handle->pm_errno = ALPM_ERR_OK;
//
// 	return _gpgme_checksig(db->handle, _db_path(db), NULL, siglist);
// }
//
// /**
//  * Clean up and free a signature result list.
//  * Note that this does not free the siglist object itself in case that
//  * was allocated on the stack; this is the responsibility of the caller.
//  * @param siglist a pointer to storage for signature results
//  * @return 0 on success, -1 on error
//  */
// int SYMEXPORT siglist_cleanup(siglist_t *siglist)
// {
// 	ASSERT(siglist != NULL, return -1);
// 	size_t num;
// 	for(num = 0; num < siglist->count; num++) {
// 		sigresult_t *result = siglist->results + num;
// 		if(result->key.data) {
// #ifdef HAVE_LIBGPGME
// 			gpgme_key_unref(result->key.data);
// #endif
// 		} else {
// 			free(result->key.fingerprint);
// 		}
// 	}
// 	if(siglist->count) {
// 		free(siglist->results);
// 	}
// 	siglist->results = NULL;
// 	siglist->count = 0;
// 	return 0;
// }
//
// /**
//  * Extract the Issuer Key ID from a signature
//  * @param sig PGP signature
//  * @param len length of signature
//  * @param keys a pointer to storage for key IDs
//  * @return 0 on success, -1 on error
//  */
// int SYMEXPORT extract_keyid(Handle *handle, const char *identifier,
// 		const unsigned char *sig, const size_t len, list_t **keys)
// {
// 	size_t pos, spos, blen, hlen, ulen, slen;
// 	pos = 0;
//
// 	while(pos < len) {
// 		if(!(sig[pos] & 0x80)) {
// 			_log(handle, ALPM_LOG_ERROR,
// 					_("%s: signature format error\n"), identifier);
// 			return -1;
// 		}
//
// 		if(sig[pos] & 0x40) {
// 			/* "new" packet format is not supported */
// 			_log(handle, ALPM_LOG_ERROR,
// 					_("%s: unsupported signature format\n"), identifier);
// 			return -1;
// 		}
//
// 		if(((sig[pos] & 0x3f) >> 2) != 2) {
// 			/* signature is not a "Signature Packet" */
// 			_log(handle, ALPM_LOG_ERROR,
// 					_("%s: signature format error\n"), identifier);
// 			return -1;
// 		}
//
// 		switch(sig[pos] & 0x03) {
// 			case 0:
// 				blen = sig[pos + 1];
// 				pos = pos + 2;
// 				break;
//
// 			case 1:
// 				blen = (sig[pos + 1] << 8) | sig[pos + 2];
// 				pos = pos + 3;
// 				break;
//
// 			case 2:
// 				blen = (sig[pos + 1] << 24) | (sig[pos + 2] << 16) | (sig[pos + 3] << 8) | sig[pos + 4];
// 				pos = pos + 5;
// 				break;
//
// 			case 3:
// 				/* partial body length not supported */
// 				_log(handle, ALPM_LOG_ERROR,
// 					_("%s: unsupported signature format\n"), identifier);
// 				return -1;
// 		}
//
// 		if(sig[pos] != 4) {
// 			/* only support version 4 signature packet format */
// 			_log(handle, ALPM_LOG_ERROR,
// 					_("%s: unsupported signature format\n"), identifier);
// 			return -1;
// 		}
//
// 		if(sig[pos + 1] != 0x00) {
// 			/* not a signature of a binary document */
// 			_log(handle, ALPM_LOG_ERROR,
// 					_("%s: signature format error\n"), identifier);
// 			return -1;
// 		}
//
// 		pos = pos + 4;
//
// 		hlen = (sig[pos] << 8) | sig[pos + 1];
// 		pos = pos + hlen + 2;
//
// 		ulen = (sig[pos] << 8) | sig[pos + 1];
// 		pos = pos + 2;
//
// 		spos = pos;
//
// 		while(spos < pos + ulen) {
// 			if(sig[spos] < 192) {
// 				slen = sig[spos];
// 				spos = spos + 1;
// 			} else if(sig[spos] < 255) {
// 				slen = (sig[spos] << 8) | sig[spos + 1];
// 				spos = spos + 2;
// 			} else {
// 				slen = (sig[spos + 1] << 24) | (sig[spos + 2] << 16) | (sig[spos + 3] << 8) | sig[spos + 4];
// 				spos = spos + 5;
// 			}
//
// 			if(sig[spos] == 16) {
// 				/* issuer key ID */
// 				char key[17];
// 				size_t i;
// 				for (i = 0; i < 8; i++) {
// 					sprintf(&key[i * 2], "%02X", sig[spos + i + 1]);
// 				}
// 				*keys = list_add(*keys, strdup(key));
// 				break;
// 			}
//
// 			spos = spos + slen;
// 		}
//
// 		pos = pos + (blen - hlen - 8);
// 	}
//
// 	return 0;
// }
//
// /* vim: set noet: */
