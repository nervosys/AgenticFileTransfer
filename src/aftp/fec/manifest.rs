//! Whole-tree packing for the FEC data plane.
//!
//! The data plane in [`super::transfer`] moves exactly one contiguous object.
//! That is the right primitive for a single large file, but a directory tree is
//! the common case — and decomposing it into one FEC transfer per file throws
//! away everything the data plane is good at: each file pays its own handshake
//! and offer round trip, and any file under [`super::FEC_MIN_TRANSFER`] silently
//! falls back to the reliable path, so a tree of ten thousand small files never
//! touches the fountain code at all.
//!
//! Whole-tree packing collapses the tree into a single logical object. The file
//! contents are concatenated, in a deterministic order, into one **packed
//! stream**; a **manifest** records where each file lives in that stream, its
//! size and mode, and the SHA-256 of its contents. The packed stream is then
//! moved by the *unchanged* FEC scheduler, and the receiver splits it back into
//! files using the manifest.
//!
//! ## Integrity: a Merkle root over the tree
//!
//! Every file's content hash is a leaf of a binary Merkle tree whose root
//! (`merkle_root`) authenticates the *entire* tree — the set of files, their
//! order, their sizes, and their bytes — in 32 bytes. On an authenticated
//! connection the manifest travels on the TLS-protected control plane and the
//! packed stream is AES-GCM'd symbol by symbol, so the root is a belt to the
//! data plane's braces: it catches a receiver that reassembles the stream
//! wrongly, a manifest that disagrees with the bytes, and any single file that
//! decoded to the wrong content, without trusting the order symbols happened to
//! arrive in.
//!
//! ## Memory and disk
//!
//! The sender never materializes the packed stream: [`PackedTreeReader`] is a
//! virtual [`BlockReader`] that maps a byte range in the stream onto reads of
//! the underlying files, so sender memory stays at `window × block_size` exactly
//! as for a single file. The receiver writes the packed stream to one temporary
//! file, verifies the whole-object SHA-256 and the Merkle root, and only then
//! unpacks it into place — the same fail-closed, atomic pattern the single-file
//! download uses, extended to a tree.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::aftp::frame::{
    get_bytes, get_str, get_u32, get_u64, get_u8, put_bytes, put_str, put_u32, put_u64, put_u8,
};
use crate::error::{AftError, AftResult};

use super::transfer::BlockReader;

/// Manifest wire format version. Bumped on any incompatible layout change.
pub const MANIFEST_VERSION: u8 = 1;

/// Upper bound on a serialized manifest, so a hostile or corrupt peer cannot
/// drive an unbounded allocation when we read one off the control plane. 64 MiB
/// holds on the order of a million entries — far past any real transfer, and
/// still a bounded buffer.
pub const MANIFEST_MAX_BYTES: u32 = 64 << 20;

/// Cap on the number of entries in a tree. A guard against a manifest that
/// claims an absurd entry count to exhaust memory before its bytes are read.
pub const MANIFEST_MAX_ENTRIES: u32 = 4_000_000;

/// What a manifest entry describes. Symlinks are intentionally absent: packing
/// them would let a tree recreate a link that escapes the destination root on
/// unpack, so the walker skips them (and reports how many) rather than trust a
/// link target across a security boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file. Contributes `size` bytes to the packed stream.
    File,
    /// A directory. Carried so that empty directories and directory modes
    /// survive the transfer; contributes no bytes.
    Dir,
}

impl EntryKind {
    fn to_u8(self) -> u8 {
        match self {
            EntryKind::File => 0,
            EntryKind::Dir => 1,
        }
    }

    fn from_u8(v: u8) -> AftResult<Self> {
        match v {
            0 => Ok(EntryKind::File),
            1 => Ok(EntryKind::Dir),
            other => Err(AftError::Other(format!(
                "manifest: unknown entry kind {other}"
            ))),
        }
    }
}

/// One node of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    /// Path relative to the tree root, always `/`-separated with no `.` or `..`
    /// components and never absolute. Validated on both build and parse.
    pub path: String,
    /// Unix permission bits (low 12), informational on platforms without them.
    pub mode: u32,
    /// Content length. Zero for directories.
    pub size: u64,
    /// Byte offset of this file's contents within the packed stream. Zero for
    /// directories. Files are laid out contiguously in manifest order.
    pub offset: u64,
    /// SHA-256 of the file contents. All-zero for directories.
    pub sha256: [u8; 32],
}

/// The full description of a packed tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub entries: Vec<Entry>,
    /// Total length of the packed stream: the sum of all file sizes. This is
    /// the `total_len` the FEC offer carries.
    pub total_len: u64,
    /// Merkle root over the entry leaves — authenticates the whole tree.
    pub merkle_root: [u8; 32],
}

/// Reject a path that is absolute, empty, or contains a `.`/`..`/empty
/// component. Used on both ends: when building (so we never advertise a path we
/// could not safely reconstruct) and when parsing a peer's manifest (so a
/// hostile manifest cannot write outside the destination root — the tree
/// analogue of zip-slip).
fn validate_rel_path(path: &str) -> AftResult<()> {
    if path.is_empty() {
        return Err(AftError::Other("manifest: empty path".into()));
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(AftError::Other(format!(
            "manifest: absolute path not allowed: {path}"
        )));
    }
    // A Windows drive prefix (`C:`) is absolute in effect.
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        return Err(AftError::Other(format!(
            "manifest: drive-qualified path not allowed: {path}"
        )));
    }
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Err(AftError::Other(format!(
                "manifest: unsafe path component in {path}"
            )));
        }
        // Backslashes are separators on Windows; a manifest path is always
        // `/`-separated, so an embedded backslash is an attempt to smuggle one.
        if comp.contains('\\') {
            return Err(AftError::Other(format!(
                "manifest: backslash in path component of {path}"
            )));
        }
    }
    Ok(())
}

// ── Merkle tree ─────────────────────────────────────────────────────────────

const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

/// Leaf hash for one entry. Domain-separated from internal nodes by `LEAF_TAG`,
/// and length-prefixed so no two distinct entries can collide by field-boundary
/// ambiguity. Binds kind, path, size, and content hash — everything that must
/// match for the reconstructed file to be the intended one.
fn leaf_hash(e: &Entry) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_TAG]);
    h.update([e.kind.to_u8()]);
    h.update((e.path.len() as u64).to_le_bytes());
    h.update(e.path.as_bytes());
    h.update(e.mode.to_le_bytes());
    h.update(e.size.to_le_bytes());
    h.update(e.sha256);
    h.finalize().into()
}

/// Combine two child hashes. `NODE_TAG` keeps an internal node from ever
/// equalling a leaf (second-preimage resistance across the two levels).
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_TAG]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Merkle root over the entry leaves. An empty tree hashes to the tag alone so
/// that "no files" still has a well-defined, non-zero root. An odd level
/// promotes its last node unchanged (a common, unambiguous convention here
/// because the leaf count is fixed by the manifest the root is bound to).
fn merkle_root(entries: &[Entry]) -> [u8; 32] {
    if entries.is_empty() {
        let mut h = Sha256::new();
        h.update([NODE_TAG]);
        return h.finalize().into();
    }
    let mut level: Vec<[u8; 32]> = entries.iter().map(leaf_hash).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(node_hash(&level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(level[i]);
                i += 1;
            }
        }
        level = next;
    }
    level[0]
}

// ── Building a manifest from a directory tree ───────────────────────────────

/// Outcome of walking a directory tree.
#[derive(Debug)]
pub struct BuildResult {
    pub manifest: Manifest,
    /// Number of symlinks skipped during the walk. Surfaced so a caller can
    /// warn rather than silently drop links.
    pub symlinks_skipped: u64,
}

/// Walk `root` and build a manifest describing every regular file and directory
/// beneath it. Files are hashed as they are visited and assigned contiguous,
/// non-overlapping offsets in manifest order; the entries are sorted by path so
/// that both ends of a transfer agree on the layout and the Merkle root is
/// stable regardless of directory-read order.
pub async fn build_manifest(root: &Path) -> AftResult<BuildResult> {
    let mut files: Vec<(String, u32, u64, [u8; 32])> = Vec::new();
    let mut dirs: Vec<(String, u32)> = Vec::new();
    let mut symlinks_skipped: u64 = 0;

    // Iterative walk: an explicit stack avoids async recursion and its boxing.
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut rd = tokio::fs::read_dir(&dir).await?;
        while let Some(ent) = rd.next_entry().await? {
            let path = ent.path();
            let meta = tokio::fs::symlink_metadata(&path).await?;
            let rel = rel_path(root, &path)?;
            if meta.file_type().is_symlink() {
                symlinks_skipped += 1;
                continue;
            }
            let mode = mode_of(&meta);
            if meta.is_dir() {
                dirs.push((rel, mode));
                stack.push(path);
            } else if meta.is_file() {
                let (size, sha) = hash_file(&path).await?;
                files.push((rel, mode, size, sha));
            }
            // Anything else (sockets, fifos, devices) has nothing to transfer.
        }
    }

    // Deterministic order: directories first (so parents are created before the
    // files that land in them on unpack), each group sorted by path.
    dirs.sort_by(|a, b| a.0.cmp(&b.0));
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut entries = Vec::with_capacity(dirs.len() + files.len());
    for (path, mode) in dirs {
        validate_rel_path(&path)?;
        entries.push(Entry {
            kind: EntryKind::Dir,
            path,
            mode,
            size: 0,
            offset: 0,
            sha256: [0u8; 32],
        });
    }
    let mut offset: u64 = 0;
    for (path, mode, size, sha256) in files {
        validate_rel_path(&path)?;
        entries.push(Entry {
            kind: EntryKind::File,
            path,
            mode,
            size,
            offset,
            sha256,
        });
        offset += size;
    }

    let manifest = Manifest {
        merkle_root: merkle_root(&entries),
        entries,
        total_len: offset,
    };
    Ok(BuildResult {
        manifest,
        symlinks_skipped,
    })
}

fn rel_path(root: &Path, path: &Path) -> AftResult<String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| AftError::Other("manifest: entry outside tree root".into()))?;
    let mut out = String::new();
    for comp in rel.components() {
        use std::path::Component;
        match comp {
            Component::Normal(s) => {
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(&s.to_string_lossy());
            }
            // The tree walk only ever produces normal components below `root`.
            _ => {
                return Err(AftError::Other(
                    "manifest: unexpected path component".into(),
                ))
            }
        }
    }
    validate_rel_path(&out)?;
    Ok(out)
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(_meta: &std::fs::Metadata) -> u32 {
    0
}

async fn hash_file(path: &Path) -> AftResult<(u64, [u8; 32])> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut size: u64 = 0;
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((size, hasher.finalize().into()))
}

// ── Serialization ───────────────────────────────────────────────────────────

impl Manifest {
    /// Recompute the Merkle root from the entries. Used after parsing to reject
    /// a manifest whose advertised root does not match its own contents.
    pub fn computed_root(&self) -> [u8; 32] {
        merkle_root(&self.entries)
    }

    /// Serialize to the binary wire form:
    /// `[version:1][entry_count:4][total_len:8][merkle_root:32] then entries`,
    /// each entry `[kind:1][mode:4][size:8][offset:8][sha256:32][path]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(45 + self.entries.len() * 96);
        put_u8(&mut buf, MANIFEST_VERSION);
        put_u32(&mut buf, self.entries.len() as u32);
        put_u64(&mut buf, self.total_len);
        put_bytes(&mut buf, &self.merkle_root);
        for e in &self.entries {
            put_u8(&mut buf, e.kind.to_u8());
            put_u32(&mut buf, e.mode);
            put_u64(&mut buf, e.size);
            put_u64(&mut buf, e.offset);
            put_bytes(&mut buf, &e.sha256);
            put_str(&mut buf, &e.path);
        }
        buf
    }

    /// Parse a manifest and validate it end to end: version, entry count cap,
    /// every path safe, files laid out contiguously with no gaps or overlaps,
    /// `total_len` consistent with the file sizes, and the Merkle root matching
    /// the recomputed one. A manifest that survives this is safe to unpack.
    pub fn decode(buf: &[u8]) -> AftResult<Self> {
        let mut off = 0usize;
        let version = get_u8(buf, &mut off)?;
        if version != MANIFEST_VERSION {
            return Err(AftError::Other(format!(
                "manifest: unsupported version {version}"
            )));
        }
        let count = get_u32(buf, &mut off)?;
        if count > MANIFEST_MAX_ENTRIES {
            return Err(AftError::Other(format!(
                "manifest: entry count {count} exceeds cap {MANIFEST_MAX_ENTRIES}"
            )));
        }
        let total_len = get_u64(buf, &mut off)?;
        let root = get_bytes(buf, &mut off)?;
        if root.len() != 32 {
            return Err(AftError::Other("manifest: bad merkle root length".into()));
        }
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&root);

        let mut entries = Vec::with_capacity((count as usize).min(65_536));
        let mut expected_offset: u64 = 0;
        for _ in 0..count {
            let kind = EntryKind::from_u8(get_u8(buf, &mut off)?)?;
            let mode = get_u32(buf, &mut off)?;
            let size = get_u64(buf, &mut off)?;
            let offset = get_u64(buf, &mut off)?;
            let sha_raw = get_bytes(buf, &mut off)?;
            if sha_raw.len() != 32 {
                return Err(AftError::Other("manifest: bad sha256 length".into()));
            }
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&sha_raw);
            let path = get_str(buf, &mut off)?;
            validate_rel_path(&path)?;

            match kind {
                EntryKind::Dir => {
                    if size != 0 || offset != 0 {
                        return Err(AftError::Other(
                            "manifest: directory entry with nonzero size/offset".into(),
                        ));
                    }
                }
                EntryKind::File => {
                    if offset != expected_offset {
                        return Err(AftError::Other(format!(
                            "manifest: file {path} offset {offset} not contiguous (expected {expected_offset})"
                        )));
                    }
                    expected_offset = expected_offset.checked_add(size).ok_or_else(|| {
                        AftError::Other("manifest: packed length overflow".into())
                    })?;
                }
            }
            entries.push(Entry {
                kind,
                path,
                mode,
                size,
                offset,
                sha256,
            });
        }

        if expected_offset != total_len {
            return Err(AftError::Other(format!(
                "manifest: total_len {total_len} disagrees with summed file sizes {expected_offset}"
            )));
        }

        let m = Manifest {
            entries,
            total_len,
            merkle_root,
        };
        if m.computed_root() != m.merkle_root {
            return Err(AftError::Other(
                "manifest: merkle root does not match entries".into(),
            ));
        }
        Ok(m)
    }
}

// ── Virtual packed-stream reader (sender side) ──────────────────────────────

/// A [`BlockReader`] over the *virtual* packed stream, backed by the real files
/// on disk. The sender never writes an archive: a read of `[start, start+len)`
/// in the stream is serviced by reading the corresponding byte ranges out of
/// however many files that window spans. Memory stays bounded by the block
/// size, exactly as [`super::transfer::FileBlocks`] does for a single file.
///
/// The stream begins with an in-memory `prefix` — the length-prefixed,
/// serialized manifest — so the whole tree, its structure *and* its bytes, is a
/// single FEC object. Carrying the manifest in-band (rather than as a control
/// frame) means an arbitrarily large tree is not bounded by any frame-size
/// limit, and the manifest travels under the same per-symbol encryption as the
/// data. File offsets in the manifest are relative to the file region, so the
/// reader shifts them past the prefix.
pub struct PackedTreeReader {
    root: PathBuf,
    prefix: Vec<u8>,
    /// File entries only, in ascending offset order: `(offset, size, path)`.
    /// Offsets are relative to the file region (i.e. after `prefix`).
    files: Vec<(u64, u64, String)>,
    total_len: u64,
}

/// Serialize a manifest into the length-prefixed blob that leads the packed
/// stream: `[manifest_len:8][manifest bytes]`.
pub fn manifest_prefix(manifest: &Manifest) -> Vec<u8> {
    let encoded = manifest.encode();
    let mut prefix = Vec::with_capacity(8 + encoded.len());
    prefix.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    prefix.extend_from_slice(&encoded);
    prefix
}

impl PackedTreeReader {
    /// Build a reader over `root`'s files, led by `prefix` (from
    /// [`manifest_prefix`]). The FEC object length is `prefix.len() +
    /// manifest.total_len`.
    pub fn new(root: impl Into<PathBuf>, manifest: &Manifest, prefix: Vec<u8>) -> Self {
        let mut files: Vec<(u64, u64, String)> = manifest
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File && e.size > 0)
            .map(|e| (e.offset, e.size, e.path.clone()))
            .collect();
        files.sort_by_key(|f| f.0);
        let total_len = prefix.len() as u64 + manifest.total_len;
        Self {
            root: root.into(),
            prefix,
            files,
            total_len,
        }
    }

    /// Total length of the packed FEC object (prefix + all file bytes).
    pub fn total_len(&self) -> u64 {
        self.total_len
    }
}

#[async_trait::async_trait]
impl BlockReader for PackedTreeReader {
    async fn read_block(&self, start: u64, len: usize) -> AftResult<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let end = start
            .checked_add(len as u64)
            .filter(|e| *e <= self.total_len)
            .ok_or_else(|| AftError::Other("packed read out of bounds".into()))?;

        let mut out = vec![0u8; len];
        let mut cursor = start;
        let plen = self.prefix.len() as u64;

        // Serve any part of the window that falls in the manifest prefix.
        if cursor < plen {
            let take = (end.min(plen) - cursor) as usize;
            let ps = cursor as usize;
            out[..take].copy_from_slice(&self.prefix[ps..ps + take]);
            cursor += take as u64;
        }
        if cursor >= end {
            return Ok(out);
        }

        // The rest falls in the file region; `files` offsets are region-local,
        // so shift by the prefix length. A partition point on the end offset
        // finds the starting file in log time.
        let fstart = cursor - plen;
        let fend = end - plen;
        let mut idx = self
            .files
            .partition_point(|(off, size, _)| off + size <= fstart);
        let mut fcur = fstart;
        while fcur < fend {
            let (foff, fsize, fpath) = self
                .files
                .get(idx)
                .ok_or_else(|| AftError::Other("packed read past end of files".into()))?;
            let within = fcur - foff; // offset inside this file
            let avail = fsize - within; // bytes left in this file
            let want = (fend - fcur).min(avail) as usize;

            let mut f = tokio::fs::File::open(self.root.join(fpath)).await?;
            f.seek(std::io::SeekFrom::Start(within)).await?;
            let dst_start = (plen + fcur - start) as usize;
            f.read_exact(&mut out[dst_start..dst_start + want]).await?;

            fcur += want as u64;
            idx += 1;
        }
        Ok(out)
    }
}

/// Read and validate the length-prefixed manifest from the front of a received
/// packed file, returning the manifest and the byte offset at which the file
/// region begins (`8 + manifest_len`). The length is bounded by
/// [`MANIFEST_MAX_BYTES`] so a corrupt or hostile prefix cannot drive an
/// unbounded read before [`Manifest::decode`] gets to validate the rest.
pub async fn read_manifest_prefix(packed_path: &Path) -> AftResult<(Manifest, u64)> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(packed_path).await?;
    let mut len_buf = [0u8; 8];
    f.read_exact(&mut len_buf).await?;
    let mlen = u64::from_le_bytes(len_buf);
    if mlen > MANIFEST_MAX_BYTES as u64 {
        return Err(AftError::Other(format!(
            "packed manifest length {mlen} exceeds cap {MANIFEST_MAX_BYTES}"
        )));
    }
    let mut mbuf = vec![0u8; mlen as usize];
    f.read_exact(&mut mbuf).await?;
    let manifest = Manifest::decode(&mbuf)?;
    Ok((manifest, 8 + mlen))
}

// ── Unpacking (receiver side) ───────────────────────────────────────────────

/// Split a fully received, digest-verified packed file into a directory tree
/// rooted at `dest_root`.
///
/// Runs only after the whole-object SHA-256 and the Merkle root have already
/// been checked, so this is the trusted-bytes phase — but it still re-derives
/// each destination path through the same validation the manifest parser used
/// and refuses anything that would escape `dest_root`, because the cost of a
/// second check is nothing against the cost of a directory traversal.
///
/// Per-file SHA-256 is re-verified as each file is written, and every
/// destination is created via a temp-then-rename so a crash mid-unpack cannot
/// leave a half-written file where a whole one is expected.
pub async fn unpack_tree(
    packed_path: &Path,
    manifest: &Manifest,
    dest_root: &Path,
    data_base: u64,
) -> AftResult<u64> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

    tokio::fs::create_dir_all(dest_root).await?;
    let canonical_root = tokio::fs::canonicalize(dest_root).await?;

    // Directories first (the build order guarantees this, but do not rely on
    // it): create every directory so files have somewhere to land.
    for e in manifest.entries.iter().filter(|e| e.kind == EntryKind::Dir) {
        let target = safe_join(&canonical_root, &e.path)?;
        tokio::fs::create_dir_all(&target).await?;
        apply_mode(&target, e.mode).await;
    }

    let mut packed = tokio::fs::File::open(packed_path).await?;
    let mut files_written: u64 = 0;
    let mut buf = vec![0u8; 1 << 20];

    for e in manifest
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::File)
    {
        let target = safe_join(&canonical_root, &e.path)?;
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut name = target
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(".aftp-unpack");
        let tmp = target.with_file_name(name);

        packed
            .seek(std::io::SeekFrom::Start(data_base + e.offset))
            .await?;
        let mut remaining = e.size;
        let mut hasher = Sha256::new();
        let mut out = tokio::fs::File::create(&tmp).await?;
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            packed.read_exact(&mut buf[..want]).await?;
            hasher.update(&buf[..want]);
            out.write_all(&buf[..want]).await?;
            remaining -= want as u64;
        }
        out.flush().await?;
        drop(out);

        let got: [u8; 32] = hasher.finalize().into();
        if got != e.sha256 {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(AftError::ChecksumMismatch {
                expected: hex::encode(e.sha256),
                actual: hex::encode(got),
            });
        }
        tokio::fs::rename(&tmp, &target).await?;
        apply_mode(&target, e.mode).await;
        files_written += 1;
    }

    Ok(files_written)
}

/// Join a validated relative manifest path onto the canonical destination root
/// and confirm the result stays inside it. `validate_rel_path` already rejects
/// `..` and absolute paths, so this is defense in depth against any component we
/// failed to anticipate on the current platform.
fn safe_join(canonical_root: &Path, rel: &str) -> AftResult<PathBuf> {
    validate_rel_path(rel)?;
    let mut target = canonical_root.to_path_buf();
    for comp in rel.split('/') {
        target.push(comp);
    }
    // A lexical check: every component is a plain name (validated above), so the
    // joined path cannot ascend above the root without a `..` we already
    // rejected. We confirm the prefix relationship directly rather than
    // canonicalize, because the target does not exist yet.
    if !target.starts_with(canonical_root) {
        return Err(AftError::PermissionDenied(format!(
            "manifest path {rel} escapes destination root"
        )));
    }
    Ok(target)
}

#[cfg(unix)]
async fn apply_mode(path: &Path, mode: u32) {
    if mode != 0 {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await;
    }
}

#[cfg(not(unix))]
async fn apply_mode(_path: &Path, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_entry(path: &str, size: u64, offset: u64) -> Entry {
        Entry {
            kind: EntryKind::File,
            path: path.into(),
            mode: 0o644,
            size,
            offset,
            sha256: [7u8; 32],
        }
    }

    #[test]
    fn path_validation_rejects_traversal() {
        assert!(validate_rel_path("a/b/c").is_ok());
        assert!(validate_rel_path("../etc/passwd").is_err());
        assert!(validate_rel_path("a/../../b").is_err());
        assert!(validate_rel_path("/abs").is_err());
        assert!(validate_rel_path("C:/win").is_err());
        assert!(validate_rel_path("a//b").is_err());
        assert!(validate_rel_path("a/./b").is_err());
        assert!(validate_rel_path("a\\b").is_err());
        assert!(validate_rel_path("").is_err());
    }

    #[test]
    fn merkle_root_is_order_sensitive_and_stable() {
        let a = vec![file_entry("a", 10, 0), file_entry("b", 5, 10)];
        let b = vec![file_entry("b", 5, 0), file_entry("a", 10, 5)];
        assert_eq!(merkle_root(&a), merkle_root(&a), "stable");
        assert_ne!(merkle_root(&a), merkle_root(&b), "order matters");
    }

    #[test]
    fn merkle_root_detects_content_change() {
        let base = vec![file_entry("a", 10, 0)];
        let mut tampered = base.clone();
        tampered[0].sha256 = [8u8; 32];
        assert_ne!(merkle_root(&base), merkle_root(&tampered));
    }

    #[test]
    fn empty_tree_has_defined_root() {
        let r = merkle_root(&[]);
        assert_ne!(r, [0u8; 32]);
    }

    #[test]
    fn encode_decode_round_trips() {
        let entries = vec![
            Entry {
                kind: EntryKind::Dir,
                path: "sub".into(),
                mode: 0o755,
                size: 0,
                offset: 0,
                sha256: [0u8; 32],
            },
            file_entry("sub/a.txt", 4, 0),
            file_entry("sub/b.txt", 6, 4),
        ];
        let m = Manifest {
            merkle_root: merkle_root(&entries),
            entries,
            total_len: 10,
        };
        let bytes = m.encode();
        let back = Manifest::decode(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn decode_rejects_noncontiguous_offsets() {
        let entries = vec![file_entry("a", 4, 0), file_entry("b", 6, 100)];
        let m = Manifest {
            merkle_root: merkle_root(&entries),
            entries,
            total_len: 10,
        };
        let err = Manifest::decode(&m.encode()).unwrap_err();
        assert!(format!("{err}").contains("contiguous"));
    }

    #[test]
    fn decode_rejects_total_len_mismatch() {
        let entries = vec![file_entry("a", 4, 0)];
        let m = Manifest {
            merkle_root: merkle_root(&entries),
            entries,
            total_len: 999,
        };
        let err = Manifest::decode(&m.encode()).unwrap_err();
        assert!(format!("{err}").contains("total_len"));
    }

    #[test]
    fn decode_rejects_forged_root() {
        let entries = vec![file_entry("a", 4, 0)];
        let m = Manifest {
            merkle_root: [0xAAu8; 32],
            entries,
            total_len: 4,
        };
        let err = Manifest::decode(&m.encode()).unwrap_err();
        assert!(format!("{err}").contains("merkle root"));
    }

    #[test]
    fn decode_rejects_unsafe_path() {
        // Hand-craft a manifest whose path escapes, bypassing build validation.
        let mut buf = Vec::new();
        put_u8(&mut buf, MANIFEST_VERSION);
        put_u32(&mut buf, 1);
        put_u64(&mut buf, 0);
        put_bytes(&mut buf, &[0u8; 32]);
        put_u8(&mut buf, EntryKind::Dir.to_u8());
        put_u32(&mut buf, 0);
        put_u64(&mut buf, 0);
        put_u64(&mut buf, 0);
        put_bytes(&mut buf, &[0u8; 32]);
        put_str(&mut buf, "../escape");
        assert!(Manifest::decode(&buf).is_err());
    }

    #[tokio::test]
    async fn build_pack_unpack_round_trips() {
        let tmp = std::env::temp_dir().join(format!("aftp-manifest-test-{}", std::process::id()));
        let src = tmp.join("src");
        let dst = tmp.join("dst");
        let _ = tokio::fs::remove_dir_all(&tmp).await;
        tokio::fs::create_dir_all(src.join("nested")).await.unwrap();
        tokio::fs::create_dir_all(src.join("empty")).await.unwrap();
        tokio::fs::write(src.join("root.bin"), vec![1u8; 3000])
            .await
            .unwrap();
        tokio::fs::write(src.join("nested/a.txt"), b"hello world")
            .await
            .unwrap();
        tokio::fs::write(src.join("nested/zero.bin"), b"")
            .await
            .unwrap();

        let built = build_manifest(&src).await.unwrap();
        let manifest = built.manifest;
        assert_eq!(manifest.total_len, 3000 + 11);

        // Pack via the virtual reader across a boundary-spanning window,
        // including the in-band manifest prefix.
        let prefix = manifest_prefix(&manifest);
        let data_base = prefix.len() as u64;
        let reader = PackedTreeReader::new(&src, &manifest, prefix);
        let total = reader.total_len();
        let mut packed = Vec::new();
        let block = 1024usize;
        let mut pos = 0u64;
        while pos < total {
            let want = (block as u64).min(total - pos) as usize;
            packed.extend_from_slice(&reader.read_block(pos, want).await.unwrap());
            pos += want as u64;
        }
        assert_eq!(packed.len() as u64, total);

        // Whole-object digest, as the download path checks.
        let packed_file = tmp.join("packed.bin");
        tokio::fs::write(&packed_file, &packed).await.unwrap();

        // Recover the manifest from the front, as the receiver does.
        let (recovered, base) = read_manifest_prefix(&packed_file).await.unwrap();
        assert_eq!(recovered, manifest);
        assert_eq!(base, data_base);

        let n = unpack_tree(&packed_file, &manifest, &dst, data_base)
            .await
            .unwrap();
        assert_eq!(n, 3, "root.bin, nested/a.txt, nested/zero.bin");

        assert_eq!(
            tokio::fs::read(dst.join("root.bin")).await.unwrap(),
            vec![1u8; 3000]
        );
        assert_eq!(
            tokio::fs::read(dst.join("nested/a.txt")).await.unwrap(),
            b"hello world"
        );
        assert!(dst.join("empty").is_dir());
        assert!(dst.join("nested/zero.bin").is_file());

        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }
}
