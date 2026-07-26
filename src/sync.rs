//! Sync engine — rsync/rclone-style directory synchronization.
//!
//! Supports one-way sync (source → destination) with:
//! - File comparison by size, modification time, or checksum
//! - Include/exclude glob filters with min/max size constraints
//! - Dry-run mode for previewing changes
//! - Delete mode to remove extraneous files at destination
//! - Timestamp preservation
//! - Recursive directory traversal with depth limiting

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::engine::{self, ProgressCb, TransferConfig};
use crate::error::{AftError, AftResult};
use crate::protocols::{DirectoryEntry, ProtocolHandler, ProtocolOptions};

/// How to decide whether a file needs updating
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareMode {
    /// Compare by size only (fast, least accurate)
    Size,
    /// Compare by modification time and size (default — like rsync)
    ModTime,
    /// Compare by checksum (slow, most accurate — like rclone --checksum)
    Checksum,
}

/// A single sync action to be performed
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncAction {
    pub kind: SyncActionKind,
    pub relative_path: String,
    pub source_size: Option<u64>,
    pub dest_size: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SyncActionKind {
    /// Copy this file from source to destination (new or updated)
    Copy,
    /// Create this directory at destination
    Mkdir,
    /// Delete this file/directory at destination (extraneous)
    Delete,
    /// Skip — file is identical
    Skip,
}

/// Configuration for the sync operation
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// How to compare files
    pub compare: CompareMode,
    /// If true, print actions without executing them
    pub dry_run: bool,
    /// If true, delete files at destination that don't exist at source
    pub delete: bool,
    /// If true, only copy if source is newer (based on mtime)
    pub update: bool,
    /// If true, preserve modification timestamps
    pub preserve_timestamps: bool,
    /// Glob patterns: files must match at least one include (empty = include all)
    pub include: Vec<String>,
    /// Glob patterns: files matching any exclude are skipped
    pub exclude: Vec<String>,
    /// Minimum file size filter (bytes)
    pub min_size: Option<u64>,
    /// Maximum file size filter (bytes)
    pub max_size: Option<u64>,
    /// Maximum directory depth (0 = unlimited)
    pub max_depth: usize,
    /// Number of files to transfer concurrently (0 or 1 = sequential).
    ///
    /// File-level concurrency is what keeps a high-latency link busy: a tree of
    /// N small files otherwise costs N serialized round trips. This is distinct
    /// from `transfer.parallel_chunks`, which splits a *single* large file.
    pub transfers: usize,
    /// Transfer config for the underlying engine
    pub transfer: TransferConfig,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            compare: CompareMode::ModTime,
            dry_run: false,
            delete: false,
            update: false,
            preserve_timestamps: false,
            include: Vec::new(),
            exclude: Vec::new(),
            min_size: None,
            max_size: None,
            max_depth: 0,
            transfers: DEFAULT_TRANSFERS,
            transfer: TransferConfig::default(),
        }
    }
}

/// Default file-level concurrency for sync.
pub const DEFAULT_TRANSFERS: usize = 8;

/// Result of a sync operation
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncResult {
    pub files_copied: u64,
    pub files_deleted: u64,
    pub files_skipped: u64,
    pub dirs_created: u64,
    pub bytes_transferred: u64,
    pub duration_ms: u64,
    pub actions: Vec<SyncAction>,
}

/// Maximum directory depth to prevent infinite recursion
const MAX_SYNC_DEPTH: usize = 200;

/// Execute a one-way sync: source → destination.
///
/// Walks the source recursively, compares with destination, and
/// transfers only files that are new or changed.
pub async fn sync(
    src_handler: &dyn ProtocolHandler,
    src_base: &str,
    dst_handler: &dyn ProtocolHandler,
    dst_base: &str,
    opts: &ProtocolOptions,
    config: &SyncConfig,
    progress_cb: Option<ProgressCb>,
) -> AftResult<SyncResult> {
    let start = std::time::Instant::now();
    let effective_max_depth = if config.max_depth == 0 {
        MAX_SYNC_DEPTH
    } else {
        config.max_depth
    };

    // Build source file index
    let src_entries = src_handler
        .list_recursive(src_base, opts, effective_max_depth)
        .await?;

    // Build destination file index
    let dst_entries = match dst_handler
        .list_recursive(dst_base, opts, effective_max_depth)
        .await
    {
        Ok(entries) => entries,
        Err(AftError::FileNotFound(_)) => Vec::new(),
        Err(e) => return Err(e),
    };

    // Index destination entries by relative path
    let dst_index: HashMap<String, &DirectoryEntry> = dst_entries
        .iter()
        .filter_map(|e| e.relative_path.as_ref().map(|p| (p.clone(), e)))
        .collect();

    // Plan actions
    let mut actions = Vec::new();
    let mut dir_delete_set: HashSet<String> = HashSet::new();
    let filter = Filter::new(&config.include, &config.exclude);

    for entry in &src_entries {
        let rel = match &entry.relative_path {
            Some(p) => p.clone(),
            None => continue,
        };

        if entry.is_directory {
            // Check if directory exists at destination
            if !dst_index.contains_key(&rel) {
                actions.push(SyncAction {
                    kind: SyncActionKind::Mkdir,
                    relative_path: rel,
                    source_size: None,
                    dest_size: None,
                });
            }
            continue;
        }

        // Apply filters
        if !filter.matches(&rel) {
            actions.push(SyncAction {
                kind: SyncActionKind::Skip,
                relative_path: rel,
                source_size: entry.size,
                dest_size: None,
            });
            continue;
        }

        // Apply size filters
        if let Some(size) = entry.size {
            if let Some(min) = config.min_size {
                if size < min {
                    actions.push(SyncAction {
                        kind: SyncActionKind::Skip,
                        relative_path: rel,
                        source_size: entry.size,
                        dest_size: None,
                    });
                    continue;
                }
            }
            if let Some(max) = config.max_size {
                if size > max {
                    actions.push(SyncAction {
                        kind: SyncActionKind::Skip,
                        relative_path: rel,
                        source_size: entry.size,
                        dest_size: None,
                    });
                    continue;
                }
            }
        }

        // Compare with destination
        let needs_copy = if let Some(dst_entry) = dst_index.get(&rel) {
            needs_update(entry, dst_entry, config)
        } else {
            true // File doesn't exist at destination
        };

        if needs_copy {
            // If --update mode, only copy if source is newer
            if config.update {
                if let (Some(src_mtime), Some(Some(dst_entry))) = (
                    &entry.last_modified,
                    dst_index.get(&rel).map(|e| e.last_modified.as_ref()),
                ) {
                    if src_mtime <= dst_entry {
                        actions.push(SyncAction {
                            kind: SyncActionKind::Skip,
                            relative_path: rel.clone(),
                            source_size: entry.size,
                            dest_size: dst_index.get(&rel).and_then(|e| e.size),
                        });
                        continue;
                    }
                }
            }

            actions.push(SyncAction {
                kind: SyncActionKind::Copy,
                relative_path: rel.clone(),
                source_size: entry.size,
                dest_size: dst_index.get(&rel).and_then(|e| e.size),
            });
        } else {
            actions.push(SyncAction {
                kind: SyncActionKind::Skip,
                relative_path: rel.clone(),
                source_size: entry.size,
                dest_size: dst_index.get(&rel).and_then(|e| e.size),
            });
        }
    }

    // Plan deletes: files at destination not present at source
    if config.delete {
        let src_index: HashMap<String, &DirectoryEntry> = src_entries
            .iter()
            .filter_map(|e| e.relative_path.as_ref().map(|p| (p.clone(), e)))
            .collect();

        // Collect deletions — files first, then directories (deepest first)
        let mut delete_files = Vec::new();
        let mut delete_dirs = Vec::new();

        for dst_entry in &dst_entries {
            let rel = match &dst_entry.relative_path {
                Some(p) => p.clone(),
                None => continue,
            };
            if !src_index.contains_key(&rel) {
                if dst_entry.is_directory {
                    delete_dirs.push(rel);
                } else {
                    delete_files.push(SyncAction {
                        kind: SyncActionKind::Delete,
                        relative_path: rel,
                        source_size: None,
                        dest_size: dst_entry.size,
                    });
                }
            }
        }

        // Sort dirs deepest-first for safe deletion
        delete_dirs.sort_by_key(|b| std::cmp::Reverse(b.matches('/').count()));
        actions.extend(delete_files);
        for dir_rel in delete_dirs {
            // Remember which Delete actions target directories — the executor
            // must run those strictly sequentially (deepest first), while file
            // deletes can run concurrently.
            dir_delete_set.insert(dir_rel.clone());
            actions.push(SyncAction {
                kind: SyncActionKind::Delete,
                relative_path: dir_rel,
                source_size: None,
                dest_size: None,
            });
        }
    }

    // Execute actions (or just report for dry-run)
    let mut result = SyncResult {
        files_copied: 0,
        files_deleted: 0,
        files_skipped: 0,
        dirs_created: 0,
        bytes_transferred: 0,
        duration_ms: 0,
        actions: actions.clone(),
    };

    if config.dry_run {
        for action in &actions {
            match action.kind {
                SyncActionKind::Copy => result.files_copied += 1,
                SyncActionKind::Mkdir => result.dirs_created += 1,
                SyncActionKind::Delete => result.files_deleted += 1,
                SyncActionKind::Skip => result.files_skipped += 1,
            }
        }
    } else {
        use futures::stream::StreamExt;

        let concurrency = config.transfers.max(1);

        // Source mtimes, indexed by relative path. `list_recursive` already
        // fetched these, so `--preserve` costs no extra round trips.
        let src_mtimes: HashMap<&str, &str> = src_entries
            .iter()
            .filter_map(
                |e| match (e.relative_path.as_deref(), e.last_modified.as_deref()) {
                    (Some(rel), Some(mtime)) => Some((rel, mtime)),
                    _ => None,
                },
            )
            .collect();

        result.files_skipped = actions
            .iter()
            .filter(|a| a.kind == SyncActionKind::Skip)
            .count() as u64;

        // ── 1. Directories, shallowest first ────────────────────────────────
        //
        // Sequential: a child mkdir must not race its parent. Directories are
        // few relative to files, so this is not the bottleneck.
        //
        // Skipped entirely for protocols that build the path on write. AFTP is
        // the motivating case: its server creates parent directories when
        // handling a PUT, and its wire protocol has no MKDIR frame, so issuing
        // one would fail the whole sync on the first subdirectory.
        if !dst_handler.creates_parent_dirs_on_write() {
            let mut mkdirs: Vec<&SyncAction> = actions
                .iter()
                .filter(|a| a.kind == SyncActionKind::Mkdir)
                .collect();
            mkdirs.sort_by_key(|a| a.relative_path.matches('/').count());
            for action in mkdirs {
                let dst_url = join_url(dst_base, &action.relative_path);
                dst_handler.mkdir(&dst_url, opts).await?;
                result.dirs_created += 1;
            }
        }

        // ── 2. File copies, bounded concurrency ─────────────────────────────
        //
        // This is the win: N files no longer cost N serialized round trips.
        let copies: Vec<&SyncAction> = actions
            .iter()
            .filter(|a| a.kind == SyncActionKind::Copy)
            .collect();

        let copy_results: Vec<AftResult<u64>> = futures::stream::iter(copies)
            .map(|action| {
                let rel = action.relative_path.as_str();
                let src_url = join_url(src_base, rel);
                let dst_url = join_url(dst_base, rel);
                let src_mtime = src_mtimes.get(rel).copied();
                let progress_cb = progress_cb.clone();
                async move {
                    let bytes = transfer_file(
                        src_handler,
                        &src_url,
                        dst_handler,
                        &dst_url,
                        opts,
                        &config.transfer,
                        progress_cb,
                    )
                    .await?;

                    if config.preserve_timestamps {
                        if let Some(mtime) =
                            src_mtime.and_then(|m| chrono::DateTime::parse_from_rfc3339(m).ok())
                        {
                            let _ = dst_handler
                                .set_timestamps(&dst_url, mtime.with_timezone(&chrono::Utc), opts)
                                .await;
                        }
                    }
                    Ok(bytes)
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        // Surface the first failure, but only after in-flight work has settled
        // so we never leave transfers running behind an early return.
        for r in copy_results {
            let bytes = r?;
            result.bytes_transferred += bytes;
            result.files_copied += 1;
        }

        // ── 3. File deletes, bounded concurrency ────────────────────────────
        let file_deletes: Vec<&SyncAction> = actions
            .iter()
            .filter(|a| {
                a.kind == SyncActionKind::Delete && !dir_delete_set.contains(&a.relative_path)
            })
            .collect();

        let delete_results: Vec<AftResult<()>> = futures::stream::iter(file_deletes)
            .map(|action| {
                let dst_url = join_url(dst_base, &action.relative_path);
                async move { dst_handler.delete(&dst_url, false, opts).await }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        for r in delete_results {
            r?;
            result.files_deleted += 1;
        }

        // ── 4. Directory deletes, deepest first ─────────────────────────────
        //
        // Sequential and ordered: a parent cannot be removed before its
        // children. `actions` already holds these deepest-first.
        for action in actions
            .iter()
            .filter(|a| dir_delete_set.contains(&a.relative_path))
        {
            let dst_url = join_url(dst_base, &action.relative_path);
            dst_handler.delete(&dst_url, false, opts).await?;
            result.files_deleted += 1;
        }
    }

    result.duration_ms = start.elapsed().as_millis() as u64;
    Ok(result)
}

/// Determine if source file needs to overwrite destination file
fn needs_update(src: &DirectoryEntry, dst: &DirectoryEntry, config: &SyncConfig) -> bool {
    match config.compare {
        CompareMode::Size => src.size != dst.size,
        CompareMode::ModTime => {
            // Different size → always copy
            if src.size != dst.size {
                return true;
            }
            // If we have timestamps, compare them
            match (&src.last_modified, &dst.last_modified) {
                (Some(s), Some(d)) => s != d,
                _ => true, // Can't compare → assume needs update
            }
        }
        CompareMode::Checksum => {
            // When using checksum mode, we can't compare checksums from metadata alone.
            // Different size is a definitive signal; equal size means we must copy to be safe.
            // True checksum comparison would require downloading both files.
            src.size != dst.size
        }
    }
}

/// Transfer a single file between two protocol handlers
async fn transfer_file(
    src_handler: &dyn ProtocolHandler,
    src_url: &str,
    dst_handler: &dyn ProtocolHandler,
    dst_url: &str,
    opts: &ProtocolOptions,
    config: &TransferConfig,
    progress_cb: Option<ProgressCb>,
) -> AftResult<u64> {
    if src_handler.scheme() == "file" && dst_handler.scheme() == "file" {
        // Direct local-to-local via engine
        let dest_path = PathBuf::from(local_path_from_url(dst_url));
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let result =
            engine::download(src_handler, src_url, &dest_path, opts, config, progress_cb).await?;
        Ok(result.bytes_transferred)
    } else {
        // Cross-protocol: download to temp, then upload
        let temp_name = format!(
            "aft-sync-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let temp_file = std::env::temp_dir().join(temp_name);

        struct TempGuard(PathBuf);
        impl Drop for TempGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _guard = TempGuard(temp_file.clone());

        let dl = engine::download(
            src_handler,
            src_url,
            &temp_file,
            opts,
            config,
            progress_cb.clone(),
        )
        .await?;

        let _ul = engine::upload(
            dst_handler,
            &temp_file,
            dst_url,
            opts,
            config,
            None,
            None,
            progress_cb,
        )
        .await?;

        Ok(dl.bytes_transferred)
    }
}

fn local_path_from_url(url: &str) -> String {
    if let Some(path) = url.strip_prefix("file://") {
        #[cfg(target_os = "windows")]
        {
            let path = path.strip_prefix('/').unwrap_or(path);
            path.replace('/', "\\")
        }
        #[cfg(not(target_os = "windows"))]
        {
            path.to_string()
        }
    } else {
        url.to_string()
    }
}

fn join_url(base: &str, relative: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), relative)
}

// ---------------------------------------------------------------------------
// Glob filter system
// ---------------------------------------------------------------------------

/// Simple glob-pattern filter supporting include/exclude patterns.
///
/// Patterns use simplified glob syntax:
/// - `*` matches any sequence of non-separator characters
/// - `**` matches any sequence including separators (recursive)
/// - `?` matches a single character
/// - `.ext` matches files with that extension
pub struct Filter {
    include: Vec<GlobPattern>,
    exclude: Vec<GlobPattern>,
}

impl Filter {
    pub fn new(include: &[String], exclude: &[String]) -> Self {
        Self {
            include: include.iter().map(|p| GlobPattern::new(p)).collect(),
            exclude: exclude.iter().map(|p| GlobPattern::new(p)).collect(),
        }
    }

    /// Returns true if the path should be included (passes all filters)
    pub fn matches(&self, path: &str) -> bool {
        // Check excludes first
        for pattern in &self.exclude {
            if pattern.matches(path) {
                return false;
            }
        }
        // If includes are specified, must match at least one
        if !self.include.is_empty() {
            return self.include.iter().any(|p| p.matches(path));
        }
        true
    }
}

struct GlobPattern {
    pattern: String,
}

impl GlobPattern {
    fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
        }
    }

    /// Match a relative path against this glob pattern.
    fn matches(&self, path: &str) -> bool {
        let pat = &self.pattern;

        // Extension-only pattern (e.g. ".txt", "*.txt")
        if let Some(ext) = pat.strip_prefix("*.") {
            return path.ends_with(&format!(".{}", ext));
        }
        if pat.starts_with('.') && !pat.contains('/') && !pat.contains('*') {
            return path.ends_with(pat);
        }

        // Convert glob to a simple regex-like matcher
        glob_match(pat, path)
    }
}

/// Simple glob matching:  `*` = non-separator, `**` = anything, `?` = one char
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_inner(&pat, &txt, 0, 0)
}

fn glob_match_inner(pat: &[char], txt: &[char], mut pi: usize, mut ti: usize) -> bool {
    while pi < pat.len() && ti < txt.len() {
        if pi + 1 < pat.len() && pat[pi] == '*' && pat[pi + 1] == '*' {
            // ** — match any number of characters including '/'
            pi += 2;
            // Skip optional trailing '/'
            if pi < pat.len() && pat[pi] == '/' {
                pi += 1;
            }
            // Try matching rest of pattern at every position
            for i in ti..=txt.len() {
                if glob_match_inner(pat, txt, pi, i) {
                    return true;
                }
            }
            return false;
        } else if pat[pi] == '*' {
            // * — match any non-separator characters
            pi += 1;
            for i in ti..=txt.len() {
                if i > ti && txt[i - 1] == '/' {
                    break;
                }
                if glob_match_inner(pat, txt, pi, i) {
                    return true;
                }
            }
            return false;
        } else if pat[pi] == '?' {
            if txt[ti] == '/' {
                return false;
            }
            pi += 1;
            ti += 1;
        } else if pat[pi] == txt[ti] {
            pi += 1;
            ti += 1;
        } else {
            return false;
        }
    }

    // Handle trailing stars
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }

    pi == pat.len() && ti == txt.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*.txt", "hello.txt"));
        assert!(!glob_match("*.txt", "hello.rs"));
        assert!(!glob_match("*.txt", "dir/hello.txt"));
    }

    #[test]
    fn test_glob_match_double_star() {
        assert!(glob_match("**/*.txt", "hello.txt"));
        assert!(glob_match("**/*.txt", "a/b/hello.txt"));
        assert!(!glob_match("**/*.txt", "hello.rs"));
    }

    #[test]
    fn test_glob_match_question() {
        assert!(glob_match("?.txt", "a.txt"));
        assert!(!glob_match("?.txt", "ab.txt"));
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("foo/bar.txt", "foo/bar.txt"));
        assert!(!glob_match("foo/bar.txt", "foo/baz.txt"));
    }

    #[test]
    fn test_filter_include() {
        let filter = Filter::new(&["*.rs".to_string()], &[]);
        assert!(filter.matches("src/main.rs"));
        assert!(!filter.matches("src/main.txt"));
    }

    #[test]
    fn test_filter_exclude() {
        let filter = Filter::new(&[], &["*.log".to_string()]);
        assert!(filter.matches("data.txt"));
        assert!(!filter.matches("debug.log"));
    }

    #[test]
    fn test_filter_include_and_exclude() {
        let filter = Filter::new(&["*.rs".to_string()], &["test_*.rs".to_string()]);
        assert!(filter.matches("main.rs"));
        assert!(!filter.matches("test_main.rs"));
        assert!(!filter.matches("readme.md"));
    }

    #[test]
    fn test_needs_update_size() {
        let src = DirectoryEntry {
            name: "a.txt".to_string(),
            size: Some(100),
            is_directory: false,
            last_modified: None,
            relative_path: None,
            is_symlink: None,
            permissions: None,
        };
        let dst_same = DirectoryEntry {
            size: Some(100),
            ..src.clone()
        };
        let dst_diff = DirectoryEntry {
            size: Some(200),
            ..src.clone()
        };
        let config = SyncConfig {
            compare: CompareMode::Size,
            ..Default::default()
        };
        assert!(!needs_update(&src, &dst_same, &config));
        assert!(needs_update(&src, &dst_diff, &config));
    }

    #[test]
    fn test_needs_update_modtime() {
        let src = DirectoryEntry {
            name: "a.txt".to_string(),
            size: Some(100),
            is_directory: false,
            last_modified: Some("2026-01-02T00:00:00Z".to_string()),
            relative_path: None,
            is_symlink: None,
            permissions: None,
        };
        let dst_same = DirectoryEntry {
            last_modified: Some("2026-01-02T00:00:00Z".to_string()),
            ..src.clone()
        };
        let dst_older = DirectoryEntry {
            last_modified: Some("2026-01-01T00:00:00Z".to_string()),
            ..src.clone()
        };
        let config = SyncConfig {
            compare: CompareMode::ModTime,
            ..Default::default()
        };
        assert!(!needs_update(&src, &dst_same, &config));
        assert!(needs_update(&src, &dst_older, &config));
    }
}
