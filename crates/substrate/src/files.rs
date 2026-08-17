//! File-integrity state providers for the snapshot service. Like the package
//! providers, OS access is isolated behind a trait so the rest of the system
//! depends only on the seam. P2 ships a static fixture provider; real filesystem
//! hashing (walking a watch set, computing SHA-256) lands with the real substrate
//! behind this same trait, touching no module.

/// The observed integrity state of one watched file. `sha256` is the lowercase
/// hex digest of the file contents; `exists` is false for a tracked-but-deleted
/// path (in which case `sha256` is empty).
#[derive(Clone, Debug, PartialEq)]
pub struct FileState {
    pub path: String,
    pub sha256: String,
    pub exists: bool,
}

impl FileState {
    pub fn present(path: impl Into<String>, sha256: impl Into<String>) -> FileState {
        FileState {
            path: path.into(),
            sha256: sha256.into(),
            exists: true,
        }
    }
    pub fn deleted(path: impl Into<String>) -> FileState {
        FileState {
            path: path.into(),
            sha256: String::new(),
            exists: false,
        }
    }
}

/// Produces the current integrity state of the monitored files. One
/// implementation per collection strategy; the snapshot service depends only on
/// this trait.
pub trait FileHashProvider: Send + Sync {
    fn files(&self) -> Vec<FileState>;
}

/// A fixed-fixture provider — the P2 stub, and a test fake. Real hashing replaces
/// it behind the trait later. `sshd_config` is returned intact against the P2a-4
/// example watchlist; `passwd`'s digest differs, so a live `cargo run` shows one
/// integrity violation end to end.
pub struct StaticFileProvider(pub Vec<FileState>);
impl FileHashProvider for StaticFileProvider {
    fn files(&self) -> Vec<FileState> {
        self.0.clone()
    }
}

/// Fallback provider: no file state (unsupported hosts / test fake).
pub struct EmptyFileProvider;
impl FileHashProvider for EmptyFileProvider {
    fn files(&self) -> Vec<FileState> {
        Vec::new()
    }
}

/// The default P2 provider: a static fixture. `1111…` matches the example
/// watchlist's `sshd_config` entry (intact); `3333…` differs from the watchlist's
/// `passwd` entry (violation), so the vertical is demonstrable on any host.
pub fn default_file_provider() -> Box<dyn FileHashProvider> {
    Box::new(StaticFileProvider(vec![
        FileState::present(
            "/etc/ssh/sshd_config",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ),
        FileState::present(
            "/etc/passwd",
            "3333333333333333333333333333333333333333333333333333333333333333",
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn present_and_deleted_constructors() {
        let p = FileState::present("/a", "ab");
        assert!(p.exists);
        assert_eq!(p.sha256, "ab");
        let d = FileState::deleted("/b");
        assert!(!d.exists);
        assert!(d.sha256.is_empty());
    }

    #[test]
    fn static_provider_returns_its_states() {
        let states = vec![FileState::present("/x", "aa"), FileState::deleted("/y")];
        assert_eq!(StaticFileProvider(states.clone()).files(), states);
    }

    #[test]
    fn empty_provider_returns_nothing() {
        assert!(EmptyFileProvider.files().is_empty());
    }

    #[test]
    fn default_provider_is_well_formed() {
        let files = default_file_provider().files();
        assert_eq!(files.len(), 2);
        for f in &files {
            assert!(!f.path.is_empty());
            assert!(f.exists, "default fixtures are present files");
            assert_eq!(f.sha256.len(), 64, "sha256 hex digest length");
        }
    }

    #[test]
    fn default_fixtures_have_the_expected_demo_digests() {
        // These exact digests define the FIM demo contract against the compliance
        // watchlist: sshd matches (intact), passwd differs (violation). See
        // torda_compliance::fim::builtin_watchlist.
        let files = default_file_provider().files();
        let sshd = files
            .iter()
            .find(|f| f.path == "/etc/ssh/sshd_config")
            .unwrap();
        assert_eq!(
            sshd.sha256,
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        let passwd = files.iter().find(|f| f.path == "/etc/passwd").unwrap();
        assert_eq!(
            passwd.sha256,
            "3333333333333333333333333333333333333333333333333333333333333333"
        );
    }
}
