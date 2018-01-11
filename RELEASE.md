The following checklist should be used for making a pacman release.

- Ensure `cargo test` succeeds
- Call a freeze to development.
- Update NEWS and README files
- Update version in Cargo.toml as described in file
- Create a signed git tag `git tag -x vX.Y.Z -m "[commit message]"`
