use std::fs::File;
use std::io::Read;
use Config;
use Result;
use Database;
use SigLevel;
use glob;
use Error;
use alpm::capabilities;
use alpm::DatabaseUsage;
use Handle;
use ConfigRepo;

pub type IniParserFn =
    Fn(&String, usize, &String, &Option<String>, &Option<String>, &mut Section, &mut Config)
        -> Result<()>;

/// Allows parsing in advance of an entire config section before we start
/// calling library methods.
#[derive(Default, Debug)]
pub struct Section {
    name: String,
    repo: Option<ConfigRepo>,
    depth: i32,
}

/// Merge the package entries of two signature verification levels.
pub fn merge_siglevel(base: SigLevel, over: SigLevel, mask: SigLevel) -> SigLevel {
    return if mask.not_zero() {
        (over & mask) | (base & !mask)
    } else {
        over
    };
}

/// Parse a configuration file.
pub fn parseconfig(file: &String, config: &mut Config) -> Result<()> {
    let mut sec = Section::default();
    debug!("config: attempting to read file {}", file);
    parse_ini(file, &parse_directive, &mut sec, config)?;
    debug!("config: finished parsing {}", file);
    Ok(())
}

pub fn register_repo(
    repo: &ConfigRepo,
    handle: &mut Handle,
    config_siglevel: SigLevel,
    arch: &String,
) -> Result<()> {
    let siglevel = merge_siglevel(config_siglevel, repo.siglevel, repo.siglevel_mask);
    let name = &repo.name;
    let servers = &repo.servers;
    let mut usage = repo.usage;
    let mut db = match handle.register_syncdb(name, siglevel) {
        Err(e) => {
            error!("could not register '{}' database ({})", name, e);
            return Err(e);
        }
        Ok(db) => db,
    };

    debug!("setting usage for {} repository", name);
    if usage.is_zero() {
        usage.set_all();
    }
    db.set_usage(usage);

    for ref server in servers {
        if let Err(e) = add_mirror(&mut db, server, arch) {
            error!(
                "could not add mirror '{}' to database '{}' ({})",
                server, name, e
            );
            return Err(e);
        }
    }

    handle.dbs_sync.push(db);
    return Ok(());
}

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
fn parse_ini(
    file: &String,
    cb: &IniParserFn,
    data: &mut Section,
    config: &mut Config,
) -> Result<()> {
    let mut section_name = String::new();
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

fn process_usage(
    values: &Vec<String>,
    usage: &mut DatabaseUsage,
    file: &String,
    linenum: usize,
) -> Result<()> {
    let mut level = *usage;
    let mut ret = Ok(());

    for key in values {
        if key == "Sync" {
            level.sync = true;
        } else if key == "Search" {
            level.search = true;
        } else if key == "Install" {
            level.install = true;
        } else if key == "Upgrade" {
            level.upgrade = true;
        } else if key == "All" {
            level.set_all();
        } else {
            error!(
                "config file {}, line {}: '{}' option '{}' not recognized",
                file, linenum, "Usage", key
            );
            ret = Err(Error::WrongArgs);
        }
    }
    if ret.is_ok() {
        *usage = level;
    }
    ret
}

fn parse_repo(
    key: &Option<String>,
    value: &Option<String>,
    file: &String,
    line: usize,
    section: &mut Section,
) -> Result<()> {
    let mut ret = Ok(());
    match (&mut section.repo, key) {
        (&mut Some(ref mut repo), &Some(ref key)) => {
            if key == "Server" {
                match value {
                    &None => {
                        error!(
                            "config file {}, line {}: directive '{}' needs a value",
                            file, line, key
                        );
                        ret = Err(Error::WrongArgs);
                    }
                    &Some(ref value) => {
                        repo.servers.push(value.clone());
                    }
                }
            } else if key == "SigLevel" {
                match value {
                    &None => {
                        error!(
                            "config file {}, line {}: directive '{}' needs a value",
                            file, line, key,
                        );
                    }
                    &Some(ref value) => {
                        let mut values = Vec::new();
                        setrepeatingoption(value, "SigLevel", &mut values);
                        if !values.is_empty() {
                            ret = process_siglevel(
                                values,
                                &mut repo.siglevel,
                                &mut repo.siglevel_mask,
                                file,
                                line,
                            );
                        }
                    }
                }
            } else if key == "Usage" {
                match value {
                    &Some(ref value) => {
                        let mut values = Vec::new();
                        setrepeatingoption(&value, "Usage", &mut values);
                        if !values.is_empty() {
                            process_usage(&values, &mut repo.usage, file, line)?;
                        }
                    }
                    &None => panic!(),
                }
            } else {
                warn!(
                    "config file {}, line {}: directive '{}' in section '{}' not recognized.",
                    file, line, key, repo.name,
                );
            }
        }
        (_, _) => panic!("Should not get here"),
    }
    ret
}

fn process_include(
    value: &Option<String>,
    section: &mut Section,
    file: &String,
    linenum: usize,
    config: &mut Config,
) -> Result<()> {
    let globret;
    let config_max_recursion = 10;

    match value {
        &None => {
            error!(
                "config file {}, line {}: directive '{}' needs a value",
                file, linenum, "Include"
            );
            return Err(Error::WrongArgs);
        }
        &Some(ref value) => {
            if section.depth >= config_max_recursion {
                error!(
                    "config parsing exceeded max recursion depth of {}.",
                    config_max_recursion
                );
                return Err(Error::Other);
            }

            section.depth += 1;

            /* Ignore include failures... assume non-critical */
            globret = glob::glob(&value);
            if let Ok(items) = globret {
                for item in items {
                    let item = item.unwrap().into_os_string().into_string()?;
                    debug!(
                        "config file {}, line {}: including {}",
                        file, linenum, &item
                    );
                    if let Err(e) = parse_ini(&item, &parse_directive, section, config) {
                        section.depth -= 1;
                        return Err(e);
                    }
                }
            }
        }
    }

    section.depth -= 1;
    Ok(())
}

fn parse_directive(
    file: &String,
    linenum: usize,
    name: &String,
    key: &Option<String>,
    value: &Option<String>,
    section: &mut Section,
    config: &mut Config,
) -> Result<()> {
    if key.is_none() && value.is_none() {
        if let Some(ref repo) = section.repo {
            config.repos.push(repo.clone());
        }

        section.name = name.clone();
        debug!("config: new section '{}'", name);
        if name == "options" {
            section.repo = None;
        } else {
            let mut repo = ConfigRepo::default();
            repo.name = name.clone();
            repo.siglevel.use_default = true;
            section.repo = Some(repo);
        }
        return Ok(());
    }

    match key {
        &Some(ref k) => if k == "Include" {
            return process_include(value, section, &file, linenum, config);
        },
        &None => {}
    }

    if section.name == "" {
        error!(
            "config file {}, line {}: All directives must belong to a section.",
            file, linenum
        );
        return Err(Error::WrongArgs);
    }

    if section.repo.is_none() {
        /* we are either in options ... */
        parse_options(key, value, file, linenum, config)
    } else {
        parse_repo(key, value, file, linenum, section)
    }
}

/// Parse a signature verification level line.
/// @param values the list of parsed option values
/// @param storage location to store the derived signature level; any existing
/// value here is used as a starting point
/// @param file path to the config file
/// @param linenum current line number in file
/// @return 0 on success, 1 on any parsing error
fn process_siglevel(
    values: Vec<String>,
    storage: &mut SigLevel,
    storage_mask: &mut SigLevel,
    file: &String,
    linenum: usize,
) -> Result<()> {
    let mut level = storage.clone();
    let mut mask = storage_mask.clone();
    let mut ret = Ok(());

    /* Collapse the option names into a single bitmasked value */
    for original in values {
        let value;
        // 		const char *original = i.data, *value;
        // 		int package = 0, database = 0;
        let mut package = false;
        let mut db = false;

        if original.starts_with("Package") {
            /* only packages are affected, don't flip flags for databases */
            value = String::from(original.trim_left_matches("Package"));
            package = true;
        } else if original.starts_with("Database") {
            /* only databases are affected, don't flip flags for packages */
            value = String::from(original.trim_left_matches("Database"));
            db = true;
        } else {
            /* no prefix, so anything found will affect both packages and dbs */
            value = original.clone();
            package = true;
            db = true;
        }

        /* now parse out and store actual flag if it is valid */
        if value == "Never" {
            if package {
                level.package = false;
                mask.package = false;
            }
            if db {
                level.database = false;
                mask.database = false;
            }
        } else if value == "Optional" {
            if package {
                level.database = true;
                mask.database = true;

                level.package_optional = true;
                mask.package_optional = true;
            }
            if db {
                level.database = true;
                mask.database = true;

                level.database_optional = true;
                mask.database_optional = true;
            }
        } else if value == "Required" {
            if package {
                level.package = true;
                mask.package = true;

                level.package_optional = false;
                mask.package_optional = false;
            }
            if db {
                level.database = true;
                mask.database = true;

                level.database_optional = false;
                mask.database_optional = false;
            }
        } else if value == "TrustedOnly" {
            if package {
                level.package_marginal_ok = false;
                mask.package_marginal_ok = false;

                level.package_unknown_ok = false;
                mask.package_unknown_ok = false;
            }
            if db {
                level.database_marginal_ok = false;
                mask.database_marginal_ok = false;

                level.database_unknown_ok = false;
                mask.database_unknown_ok = false;
            }
        } else if value == "TrustAll" {
            if package {
                level.package_marginal_ok = true;
                mask.package_marginal_ok = true;

                level.package_unknown_ok = true;
                mask.package_unknown_ok = true;
            }
            if db {
                level.database_marginal_ok = true;
                mask.database_marginal_ok = true;

                level.database_unknown_ok = true;
                mask.database_unknown_ok = true;
            }
        } else {
            error!(
                "config file {}, line {}: invalid value for '{}' : '{}'",
                file, linenum, "SigLevel", original
            );
            ret = Err(Error::WrongArgs);
        }
        level.use_default = false;
    }

    /* ensure we have sig checking ability and are actually turning it on */
    if !(capabilities().signatures && level.package || level.database) {
        error!(
            "config file {}, line {}: '{}' option invalid, no signature support",
            file, linenum, "SigLevel"
        );
        ret = Err(Error::WrongArgs);
    }

    if ret.is_ok() {
        *storage = level;
        *storage_mask = mask;
    }
    return ret;
}

fn process_cleanmethods(
    values: Vec<String>,
    file: &String,
    linenum: usize,
    config: &mut Config,
) -> Result<()> {
    for value in values {
        if value == "KeepInstalled" {
            config.cleanmethod.keepinst = true;
        } else if value == "KeepCurrent" {
            config.cleanmethod.keepcur = true;
        } else {
            error!(
                "config file {}, line {}: invalid value for '{}' : '{}'",
                file, linenum, "CleanMethod", value
            );
            return Err(Error::WrongArgs);
        }
    }
    return Ok(());
}

/// Add repeating options such as NoExtract, NoUpgrade, etc to libalpm
/// settings. Refactored out of the parseconfig code since all of them did
/// the exact same thing and duplicated code.
fn setrepeatingoption(options: &String, option_name: &str, list: &mut Vec<String>) {
    let vals = options.split_whitespace();
    for val in vals {
        list.push(String::from(val));
        debug!("config: {}: {}", option_name, val);
    }
}

fn parse_options(
    key: &Option<String>,
    value: &Option<String>,
    file: &String,
    linenum: usize,
    config: &mut Config,
) -> Result<()> {
    let key = match key {
        &Some(ref k) => k,
        &None => unimplemented!(),
    };
    match value {
        &None => {
            /* options without settings */
            if key == "UseSyslog" {
                config.usesyslog = 1;
                debug!("config: usesyslog");
            } else if key == "ILoveCandy" {
                config.chomp = 1;
                debug!("config: chomp");
            } else if key == "VerbosePkgLists" {
                config.verbosepkglists = 1;
                debug!("config: verbosepkglists");
            } else if key == "UseDelta" {
                config.deltaratio = 0.7;
                debug!("config: usedelta (default 0.7)");
            } else if key == "TotalDownload" {
                config.totaldownload = 1;
                debug!("config: totaldownload");
            } else if key == "CheckSpace" {
                config.checkspace = true;
            } else if key == "Color" {
            } else if key == "DisableDownloadTimeout" {
                config.disable_dl_timeout = true;
            } else {
                warn!(
                    "config file {}, line {}: directive '{}' in section '{}' not recognized.",
                    file, linenum, key, "options"
                );
            }
        }
        &Some(ref value) => {
            /* options with settings */
            if key == "NoUpgrade" {
                setrepeatingoption(value, "NoUpgrade", &mut config.noupgrade);
            } else if key == "NoExtract" {
                setrepeatingoption(value, "NoExtract", &mut config.noextract);
            } else if key == "IgnorePkg" {
                setrepeatingoption(value, "IgnorePkg", &mut config.ignorepkg);
            } else if key == "IgnoreGroup" {
                setrepeatingoption(value, "IgnoreGroup", &mut config.ignoregrp);
            } else if key == "HoldPkg" {
                setrepeatingoption(value, "HoldPkg", &mut config.holdpkg);
            } else if key == "CacheDir" {
                setrepeatingoption(value, "CacheDir", &mut config.cachedirs);
            } else if key == "HookDir" {
                setrepeatingoption(value, "HookDir", &mut config.hookdirs);
            } else if key == "Architecture" {
                if config.arch == "" {
                    config.config_set_arch(value);
                }
            } else if key == "UseDelta" {
                unimplemented!();
            // double ratio;
            // char *endptr;
            // const char *oldlocale;
            // /* set the locale to 'C' for consistent decimal parsing (0.7 and never
            //  * 0,7) from config files, then restore old setting when we are done */
            // oldlocale = setlocale(LC_NUMERIC, NULL);
            // setlocale(LC_NUMERIC, "C");
            // ratio = strtod(value, &endptr);
            // setlocale(LC_NUMERIC, oldlocale);
            //
            // if (*endptr != '\0' || ratio < 0.0 || ratio > 2.0) {
            //     error!(
            //         "config file {}, line {}: invalid value for '{}' : '{}'",
            //         file, linenum, "UseDelta", value
            //     );
            //     return 1;
            // }
            // config.deltaratio = ratio;
            // debug!("config: usedelta = {}\n", ratio);
            } else if key == "DBPath" {
                /* don't overwrite a path specified on the command line */
                if config.dbpath == "" {
                    config.dbpath = value.clone();
                    debug!("config: dbpath: {}", value);
                }
            } else if key == "RootDir" {
                /* don't overwrite a path specified on the command line */
                if config.rootdir == "" {
                    config.rootdir = value.clone();
                    debug!("config: rootdir: {}", value);
                }
            } else if key == "GPGDir" {
                if config.gpgdir == "" {
                    config.gpgdir = value.clone();
                    debug!("config: gpgdir: {}", value);
                }
            } else if key == "LogFile" {
                if config.logfile == "" {
                    config.logfile = value.clone();
                    debug!("config: logfile: {}", value);
                }
            } else if key == "XferCommand" {
                config.xfercommand = value.clone();
                debug!("config: xfercommand: {}", value);
            } else if key == "CleanMethod" {
                let mut methods = Vec::new();
                setrepeatingoption(value, "CleanMethod", &mut methods);
                process_cleanmethods(methods, file, linenum, config)?;
            } else if key == "SigLevel" {
                let mut values = Vec::new();
                setrepeatingoption(value, "SigLevel", &mut values);
                process_siglevel(
                    values,
                    &mut config.siglevel,
                    &mut config.siglevel_mask,
                    file,
                    linenum,
                )?;
            } else if key == "LocalFileSigLevel" {
                let mut values = Vec::new();
                setrepeatingoption(value, "LocalFileSigLevel", &mut values);
                process_siglevel(
                    values,
                    &mut config.localfilesiglevel,
                    &mut config.localfilesiglevel_mask,
                    file,
                    linenum,
                )?;
            } else if key == "RemoteFileSigLevel" {
                let mut values = Vec::new();
                setrepeatingoption(value, "RemoteFileSigLevel", &mut values);
                process_siglevel(
                    values,
                    &mut config.remotefilesiglevel,
                    &mut config.remotefilesiglevel_mask,
                    file,
                    linenum,
                )?;
            } else {
                warn!(
                    "config file {}, line {}: directive '{}' in section '{}' not recognized.",
                    file, linenum, key, "options"
                );
            }
        }
    }
    return Ok(());
}

fn add_mirror(db: &mut Database, value: &String, arch: &String) -> Result<()> {
    let dbname = db.get_name().clone();
    /* let's attempt a replacement for the current repo */
    let temp = value.replace("$repo", &dbname);
    /* let's attempt a replacement for the arch */
    let server = if arch != "" {
        temp.replace("$arch", arch)
    } else {
        if temp.contains("$arch") {
            error!(
                "mirror '{}' contains the '$arch' variable, but no 'Architecture' is defined.",
                value
            );
            return Err(Error::Other);
        }
        temp
    };

    if let Err(e) = db.add_server(&server) {
        error!(
            "could not add server URL to database '{}': {} ({})",
            dbname, server, e
        );
        return Err(e);
    }
    Ok(())
}
