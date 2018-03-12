use super::Config;
use Handle;
use find_satisfier;
use Error;
use Result;

pub fn pacman_deptest(targets: Vec<String>, config: Config, mut handle: Handle) -> Result<()> {
    let mut deps: Vec<String> = Vec::new();
    let handle_clone = &handle.clone();
    let localdb = handle.get_localdb_mut();

    for target in targets {
        // unimplemented!();
        if find_satisfier(&localdb.get_pkgcache()?, &target).is_none() {
            deps.push(target);
        }
    }

    if deps.is_empty() {
        return Ok(());
    }

    for dep in deps {
        print!("{}\n", dep);
    }
    return Err(Error::Other);
}
