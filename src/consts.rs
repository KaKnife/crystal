pub const PACKAGE_VERSION: &str = "0.0.1";
pub const DEBUG: bool = true;
pub const CONFFILE: &str = "/etc/pacman.conf";
pub const ROOTDIR: &str = "/";
pub const DBPATH: &str = "/var/lib/pacman/";
pub const LOGFILE: &str = "/var/log/crystal.log";
pub const CACHEDIR: &str = "/var/cache/pacman/pkg/";
pub const GPGDIR: &str = "/etc/pacman.d/gnupg/";
pub const HOOKDIR: &str = "/etc/pacman.d/hooks/";
pub const SYSHOOKDIR: &str = "/usr/local/share/libalpm/hooks/";
pub const LOCAL_PREFIX: &str = "local/";

pub const ALPM_LOCAL_DB_VERSION: usize = 9;

/// Database entries
pub const INFRQ_BASE: i32 = (1 << 0);
pub const INFRQ_DESC: i32 = (1 << 1);
pub const INFRQ_FILES: i32 = (1 << 2);
pub const INFRQ_SCRIPTLET: i32 = (1 << 3);
pub const INFRQ_DSIZE: i32 = (1 << 4);
/// ALL should be info stored in the package or database
pub const INFRQ_ALL: i32 = INFRQ_BASE | INFRQ_DESC | INFRQ_FILES | INFRQ_SCRIPTLET | INFRQ_DSIZE;
pub const INFRQ_ERROR: i32 = (1 << 30);

#[cfg(target_arch = "x86_64")]
pub const OS_ARCH: &str = "x86_64";

#[cfg(target_arch = "x86")]
pub const OS_ARCH: &str = "x86";

/// package locality
pub const PKG_LOCALITY_UNSET: usize = 0;
pub const PKG_LOCALITY_NATIVE: usize = (1 << 0);
pub const PKG_LOCALITY_FOREIGN: usize = (1 << 1);

pub const LDCONFIG: &str = "/sbin/ldconfig";
