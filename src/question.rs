use alpm::Conflict;
use {Database, Package};

/// Type of questions.
/// Unlike the events or progress enumerations, this enum has bitmask values
/// so a frontend can use a bitmask map to supply preselected answers to the
/// different types of questions.
pub enum QuestionType {
    InstallIgnorepkg = (1 << 0),
    ReplacePkg = (1 << 1),
    ConflictPkg = (1 << 2),
    CorruptedPkg = (1 << 3),
    RemovePkgs = (1 << 4),
    SelectProvider = (1 << 5),
    ImportKey = (1 << 6),
}

pub struct QuestionAny {
    /// Type of question.
    qtype: QuestionType,
    /// Answer.
    answer: bool,
}

pub struct QuestionInstallIgnorePackage<'a> {
    /// Type of question.
    qtype: QuestionType,
    /// Answer: whether or not to install pkg anyway.
    install: bool,
    /// Package in IgnorePkg/IgnoreGroup.
    pkg: &'a Package,
}

pub struct QuestionReplace<'a> {
    /// Type of question.
    pub qtype: QuestionType,
    /// Answer: whether or not to replace oldpkg with newpkg.
    pub replace: bool,
    /// Package to be replaced.
    pub oldpkg: &'a Package,
    /// Package to replace with.
    pub newpkg: &'a Package,
    /// DB of newpkg
    pub newdb: &'a Database,
}

pub struct QuestionConflict<'a> {
    /// Type of question.
    qtype: QuestionType,
    /// Answer: whether or not to remove conflict->package2.
    remove: bool,
    /// Conflict info.
    conflict: &'a Conflict<'a>,
}

pub struct QuestionCorrupted {
    /// Type of question.
    qtype: QuestionType,
    /// Answer: whether or not to remove filepath.
    remove: bool,
    /// Filename to remove
    filepath: String,
    // 	/// Error code indicating the reason for package invalidity
    // 	errno reason;
}

pub struct QuestionRemovePkgs {
// 	/// Type of question.
// 	questionype type;
// 	/// Answer: whether or not to skip packages.
// 	int skip;
// 	/// List of Package* with unresolved dependencies.
// 	list *packages;
}

struct QuestionSelectProvider {
// 	/// Type of question.
// 	questionype type;
// 	/// Answer: which provider to use (index from providers).
// 	int use_index;
// 	/// List of Package* as possible providers.
// 	list *providers;
// 	/// What providers provide for.
// 	Dependency *depend;
}

// typedef struct _question_import_key {
// 	/// Type of question.
// 	questionype type;
// 	/// Answer: whether or not to import key.
// 	int import;
// 	/// The key to import.
// 	pgpkey *key;
// } question_import_key;

/// Questions.
/// This is an union passed to the callback, that allows the frontend to know
/// which type of question was triggered (via type). It is then possible to
/// typecast the pointer to the right structure, or use the union field, in order
/// to access question-specific data.
pub enum Question<'a> {
    // 	questionype type;
    Any(QuestionAny),
    InstallIgnorepkg(&'a QuestionInstallIgnorePackage<'a>),
    Replace(&'a QuestionReplace<'a>),
    // 	question_conflict conflict;
    // 	question_corrupted corrupted;
    // 	question_remove_pkgs remove_pkgs;
    // 	question_select_provider select_provider;
    // 	question_import_key import_key;
}

/// Question callback
pub type CbQuestion = Option<fn(&Question)>;
