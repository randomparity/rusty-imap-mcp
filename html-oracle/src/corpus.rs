//! Corpus loader: raw HTML fuzz seeds + text/html parts from injection .eml
//! fixtures. Each input carries its raw bytes + declared charset so the runner
//! can decode identically for both engines.

use std::path::{Path, PathBuf};

use mail_parser::{MessageParser, MimeHeaders as _};

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
}

pub fn load(repo_root: &Path) -> Result<Vec<CorpusInput>, CorpusError> {
    let mut inputs = Vec::new();
    load_fuzz_seeds(repo_root, &mut inputs)?;
    load_injection_parts(repo_root, &mut inputs)?;
    Ok(inputs)
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
        let bytes = std::fs::read(&eml).map_err(|source| CorpusError::Io {
            path: eml.clone(),
            source,
        })?;
        let Some(msg) = MessageParser::default().parse(&bytes) else {
            continue;
        };
        let dir_name = fixture
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut part_no = 0usize;
        for part in msg.html_bodies() {
            let charset = part
                .content_type()
                .and_then(|c| c.attribute("charset"))
                .map(|s| s.to_string());
            let raw = part.contents().to_vec();
            let id = if part_no == 0 {
                format!("injection/{dir_name}")
            } else {
                format!("injection/{dir_name}/part{part_no}")
            };
            out.push(CorpusInput { id, raw, charset });
            part_no += 1;
        }
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
