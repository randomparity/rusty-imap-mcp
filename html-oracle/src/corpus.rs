//! Corpus loader: raw HTML fuzz seeds + text/html parts from injection .eml
//! fixtures, plus an optional external `.eml` dataset tree (EPVME). Each input
//! carries its raw bytes + declared charset so the runner can decode
//! identically for both engines.

use std::path::{Path, PathBuf};

use mail_parser::{MessageParser, MimeHeaders as _};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug)]
pub struct CorpusInput {
    pub id: String,
    pub raw: Vec<u8>,
    pub charset: Option<String>,
    /// Hardening families this input exercises, from its sibling `meta.toml`
    /// (`--corpus-root` inputs only; empty for in-repo and `--epvme-dir` inputs).
    pub probes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Meta {
    #[serde(default)]
    probes: Vec<String>,
}

pub fn load(repo_root: &Path) -> Result<Vec<CorpusInput>, CorpusError> {
    let mut inputs = Vec::new();
    load_fuzz_seeds(repo_root, &mut inputs)?;
    load_injection_parts(repo_root, &mut inputs)?;
    Ok(inputs)
}

/// Load an external tree of `.eml` files (e.g. the EPVME dataset), extracting
/// each message's text/html parts the *same* way [`load_injection_parts`] does
/// so the differential stays fair. Absent/unreadable dir is not an error.
///
/// Ids are `id_prefix/<file-stem>`. This assumes stems are unique across the
/// tree; EPVME satisfies this because its filenames are content hashes (a shared
/// stem means identical bytes, so the collision is a benign duplicate). A caller
/// with non-unique stems across subdirectories would see ids alias.
///
/// `limit` bounds the number of source `.eml` *files* processed (files are
/// sorted first, so the cap is deterministic), not the number of html parts
/// produced — a capped run may yield more inputs than `limit` when files are
/// multipart. This matches the `epvme_runner` `--limit` semantics.
pub fn load_eml_tree(
    dir: &Path,
    id_prefix: &str,
    limit: Option<usize>,
) -> Result<Vec<CorpusInput>, CorpusError> {
    let mut files = Vec::new();
    collect_eml_files(dir, &mut files);
    files.sort();
    if let Some(limit) = limit {
        files.truncate(limit);
    }
    let mut out = Vec::new();
    for eml in &files {
        let stem = eml
            .file_stem()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        extract_html_parts(eml, &format!("{id_prefix}/{stem}"), &mut out)?;
    }
    Ok(out)
}

/// Load an external corpus tree the same way [`load_eml_tree`] does (walk, sort,
/// deterministic `limit`), keyed under `corpus/…`, additionally attaching each
/// input's sibling `<stem>.meta.toml` `probes` families. A missing/unparseable
/// meta yields empty `probes` (the input still loads) and logs a warning — the
/// corpus repo's self-validation (issue #549) is the gate that guarantees valid
/// metadata at the pinned SHA.
pub fn load_corpus_tree(dir: &Path, limit: Option<usize>) -> Result<Vec<CorpusInput>, CorpusError> {
    let mut files = Vec::new();
    collect_eml_files(dir, &mut files);
    files.sort();
    if let Some(limit) = limit {
        files.truncate(limit);
    }
    let mut out = Vec::new();
    for eml in &files {
        let stem = eml
            .file_stem()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let first = out.len();
        extract_html_parts(eml, &format!("corpus/{stem}"), &mut out)?;
        let probes = read_probes(eml);
        for input in &mut out[first..] {
            input.probes = probes.clone();
        }
    }
    Ok(out)
}

fn read_probes(eml: &Path) -> Vec<String> {
    let meta_path = eml.with_extension("meta.toml");
    let Ok(text) = std::fs::read_to_string(&meta_path) else {
        return Vec::new();
    };
    match toml::from_str::<Meta>(&text) {
        Ok(meta) => meta.probes,
        Err(e) => {
            eprintln!("html-oracle: unparsable {}: {e}", meta_path.display());
            Vec::new()
        }
    }
}

fn collect_eml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return; // absent tree is not an error
    };
    for entry in entries.flatten() {
        // Use the entry's own file type, which does NOT follow symlinks, so a
        // symlinked directory cycle cannot drive unbounded recursion. Symlinks
        // are skipped entirely (neither is_dir nor is_file for a symlink).
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if file_type.is_dir() {
            collect_eml_files(&path, out);
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("eml"))
        {
            out.push(path);
        }
    }
}

fn load_fuzz_seeds(repo_root: &Path, out: &mut Vec<CorpusInput>) -> Result<(), CorpusError> {
    let dir = repo_root.join("fuzz/corpus/content_html");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(()), // absent corpus is not an error
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let raw = std::fs::read(&path).map_err(|source| CorpusError::Io {
            path: path.clone(),
            source,
        })?;
        if let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) {
            out.push(CorpusInput {
                id: format!("content_html/{name}"),
                raw,
                charset: None,
                probes: Vec::new(),
            });
        }
    }
    Ok(())
}

fn load_injection_parts(repo_root: &Path, out: &mut Vec<CorpusInput>) -> Result<(), CorpusError> {
    let dir = repo_root.join("tests/injection-corpus");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let fixture = entry.path();
        let eml = fixture.join("input.eml");
        if !eml.is_file() {
            continue;
        }
        let dir_name = fixture
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        extract_html_parts(&eml, &format!("injection/{dir_name}"), out)?;
    }
    Ok(())
}

/// Parse one `.eml` and push each of its text/html parts as a [`CorpusInput`],
/// keyed by `id_base` (with a `/partN` suffix for the 2nd+ part). Shared by the
/// injection corpus and the external `.eml` tree so both feed the engines the
/// exact same bytes production's `bodies.rs` would.
fn extract_html_parts(
    eml: &Path,
    id_base: &str,
    out: &mut Vec<CorpusInput>,
) -> Result<(), CorpusError> {
    let bytes = std::fs::read(eml).map_err(|source| CorpusError::Io {
        path: eml.to_path_buf(),
        source,
    })?;
    let Some(msg) = MessageParser::default().parse(&bytes) else {
        return Ok(());
    };
    for (part_no, part) in msg.html_bodies().enumerate() {
        let charset = part
            .content_type()
            .and_then(|c| c.attribute("charset"))
            .map(|s| s.to_string());
        let raw = part.contents().to_vec();
        let id = if part_no == 0 {
            id_base.to_string()
        } else {
            format!("{id_base}/part{part_no}")
        };
        out.push(CorpusInput {
            id,
            raw,
            charset,
            probes: Vec::new(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn extracts_html_part_from_eml() {
        let dir = tempfile::tempdir().unwrap();
        let corpus = dir.path().join("tests/injection-corpus/sample");
        std::fs::create_dir_all(&corpus).unwrap();
        let eml = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>hello</p>\r\n";
        let mut f = std::fs::File::create(corpus.join("input.eml")).unwrap();
        f.write_all(eml.as_bytes()).unwrap();
        // no fuzz corpus dir -> that source contributes nothing, not an error.
        let inputs = load(dir.path()).unwrap();
        let sample = inputs
            .iter()
            .find(|i| i.id.starts_with("injection/sample"))
            .expect("html part extracted");
        assert!(String::from_utf8_lossy(&sample.raw).contains("hello"));
    }

    #[test]
    fn load_corpus_tree_reads_probes_and_prefixes_ids() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("corpus");
        std::fs::create_dir_all(root.join("wave1")).unwrap();
        let eml = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>hi</p>\r\n";
        std::fs::write(root.join("wave1/aa11.eml"), eml).unwrap();
        std::fs::write(
            root.join("wave1/aa11.meta.toml"),
            "probes = [\"stray-tag-boundary\", \"entity-href\"]\n",
        )
        .unwrap();

        let inputs = load_corpus_tree(&root, None).unwrap();
        let got = inputs
            .iter()
            .find(|i| i.id == "corpus/aa11")
            .expect("loaded");
        assert_eq!(got.probes, vec!["stray-tag-boundary", "entity-href"]);
    }

    #[test]
    fn load_corpus_tree_tolerates_missing_meta() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("corpus");
        std::fs::create_dir_all(&root).unwrap();
        let eml = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>hi</p>\r\n";
        std::fs::write(root.join("bb22.eml"), eml).unwrap();
        // No sibling meta.toml.
        let inputs = load_corpus_tree(&root, None).unwrap();
        let got = inputs
            .iter()
            .find(|i| i.id == "corpus/bb22")
            .expect("loaded");
        assert!(got.probes.is_empty());
    }

    #[test]
    fn load_eml_tree_walks_nested_and_prefixes_ids() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("epvme");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let eml = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>hello</p>\r\n";
        std::fs::write(root.join("aa11.eml"), eml).unwrap();
        std::fs::write(root.join("sub/bb22.eml"), eml).unwrap();
        std::fs::write(root.join("note.txt"), b"not an eml").unwrap();

        let inputs = load_eml_tree(&root, "epvme", None).unwrap();

        let ids: std::collections::BTreeSet<_> = inputs.iter().map(|i| i.id.clone()).collect();
        assert!(ids.contains("epvme/aa11"), "ids: {ids:?}");
        assert!(ids.contains("epvme/bb22"), "ids: {ids:?}");
        assert_eq!(inputs.len(), 2, "only .eml files, txt ignored");
        assert!(String::from_utf8_lossy(&inputs[0].raw).contains("hello"));
    }

    #[test]
    #[cfg(unix)]
    fn load_eml_tree_skips_symlink_cycles() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("epvme");
        std::fs::create_dir_all(&root).unwrap();
        let eml = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>hi</p>\r\n";
        std::fs::write(root.join("real.eml"), eml).unwrap();
        // A symlink pointing back at the root would recurse forever if followed.
        std::os::unix::fs::symlink(&root, root.join("loop")).unwrap();

        // Must terminate (no stack overflow) and find only the real file.
        let inputs = load_eml_tree(&root, "epvme", None).unwrap();
        assert_eq!(inputs.len(), 1, "symlink cycle must not be followed");
        assert!(inputs[0].id.ends_with("real"));
    }

    #[test]
    fn load_eml_tree_honors_limit_and_absent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("epvme");
        std::fs::create_dir_all(&root).unwrap();
        let eml = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>x</p>\r\n";
        for name in ["a.eml", "b.eml", "c.eml"] {
            std::fs::write(root.join(name), eml).unwrap();
        }
        // Files are sorted before truncation, so the limit is deterministic.
        let limited = load_eml_tree(&root, "epvme", Some(2)).unwrap();
        assert_eq!(limited.len(), 2);

        // Absent tree contributes nothing and is not an error.
        let absent = load_eml_tree(&dir.path().join("missing"), "epvme", None).unwrap();
        assert!(absent.is_empty());
    }

    #[test]
    fn charset_is_carried_and_contents_are_predecoded() {
        // mail-parser charset-decodes text parts to UTF-8 BEFORE storage, so
        // `part.contents()` is already UTF-8 and the declared charset is carried
        // verbatim. This is faithful to production: `bodies.rs` passes exactly
        // `cow.as_bytes()` (the decoded UTF-8) + the declared charset to
        // `html::sanitize`, so the oracle feeds both engines the same bytes
        // production's real pipeline does.
        let dir = tempfile::tempdir().unwrap();
        let corpus = dir.path().join("tests/injection-corpus/w1252");
        std::fs::create_dir_all(&corpus).unwrap();
        // 0xE9 is 'é' in Windows-1252; mail-parser decodes it to UTF-8 'é'.
        let mut eml = b"Content-Type: text/html; charset=windows-1252\r\n\r\n".to_vec();
        eml.extend_from_slice(b"<p>caf\xE9</p>");
        std::fs::write(corpus.join("input.eml"), &eml).unwrap();
        let inputs = load(dir.path()).unwrap();
        let sample = inputs
            .iter()
            .find(|i| i.id.starts_with("injection/w1252"))
            .unwrap();
        assert_eq!(sample.charset.as_deref(), Some("windows-1252"));
        // contents() is already decoded to UTF-8 'é' by mail-parser.
        assert!(
            String::from_utf8_lossy(&sample.raw).contains('é'),
            "raw should be pre-decoded UTF-8: {:?}",
            sample.raw
        );
    }
}
