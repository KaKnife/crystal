/// Package install reasons.
#[derive(Debug, Clone, Copy)]
pub enum PackageReason {
    /// Explicitly requested by the user.
    Explicit = 0,
    /// Installed as a dependency for another package.
    Dependency = 1,
}
impl Default for PackageReason {
    fn default() -> Self {
        PackageReason::Explicit
    }
}
impl From<u8> for PackageReason {
    fn from(n: u8) -> PackageReason {
        match n {
            0 => PackageReason::Explicit,
            1 => PackageReason::Dependency,
            _ => unimplemented!(),
        }
    }
}
