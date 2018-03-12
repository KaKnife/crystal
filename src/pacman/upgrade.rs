use pacman::trans_init;
use pacman::sync_prepare_execute;
use Config;
use Error;
use Result;
use Handle;

/// Upgrade a specified list of packages.
pub fn pacman_upgrade(
    mut targets: Vec<String>,
    mut config: Config,
    mut handle: Handle,
) -> Result<()> {
    let mut retval = Ok(());
    let mut file_is_remote: Vec<bool>;
    if targets.is_empty() {
        error!("no targets specified (use -h for help)");
        return Err(Error::WrongArgs);
    }

    file_is_remote = Vec::new();

    for target in &mut targets {
        if target.contains("://") {
            match handle.fetch_pkgurl(&target) {
                Err(e) => {
                    error!("'{}': {}\n", target, e);
                    retval = Err(e);
                    file_is_remote.push(false);
                }
                Ok(url) => {
                    *target = url;
                    file_is_remote.push(true);
                }
            }
        } else {
            file_is_remote.push(false);
        }
    }

    if retval.is_err() {
        return retval;
    }

    /* Step 1: create a new transaction */
    trans_init(&config.flags.clone(), true, &mut handle)?;

    print!("loading packages...\n");
    /* add targets to the created transaction */
    for (n, targ) in targets.iter().enumerate() {
        let mut pkg;
        let siglevel;

        if file_is_remote[n] {
            siglevel = handle.get_remote_file_siglevel();
        } else {
            siglevel = handle.get_local_file_siglevel();
        }
        pkg = match handle.pkg_load(targ, 1, &siglevel) {
            Err(e) => {
                error!("'{}': {}", targ, e);
                retval = Err(e);
                continue;
            }
            Ok(p) => p.clone(),
        };
        if let Err(e) = handle.add_pkg(&mut pkg) {
            error!("'{}': {}", targ, e);
            retval = Err(e);
            continue;
        }
        // config.explicit_adds.push(pkg);
    }

    if retval.is_err() {
        return retval;
    }

    /* now that targets are resolved, we can hand it all off to the sync code */
    sync_prepare_execute(&mut config, &mut handle)
}
