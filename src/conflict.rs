use Dependency;

/// Conflict
pub struct Conflict<'a> {
    package1_hash: u64,
    package2_hash: u64,
    pub package1: String,
    pub package2: String,
    reason: &'a Dependency,
}
