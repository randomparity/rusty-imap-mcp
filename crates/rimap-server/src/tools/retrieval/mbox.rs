//! mboxrd framing codec for the `export_messages` tool.
//!
//! Self-contained serializer that assembles raw RFC822 message bodies into
//! a single `git am`-able mboxrd buffer. It knows nothing about IMAP,
//! accounts, sandboxes, or MCP — the only input is already-fetched message
//! bytes — so the `From`-line escaping security property is independently
//! testable here without the export orchestration around it.

/// Pinned mboxrd separator. `git am`/`mailsplit` use it only as a delimiter
/// and take real authorship from each message's own `From:` header.
const MBOX_SEPARATOR: &[u8] = b"From mboxrd@rusty-imap-mcp Thu Jan  1 00:00:00 1970\n";

/// Assemble raw RFC822 messages into a single mboxrd byte buffer suitable
/// for `git am`. Each message is preceded by [`MBOX_SEPARATOR`] at column 0;
/// every line matching `^>*From ` is escaped with one extra leading `>`;
/// CRLF is preserved verbatim.
///
/// Callers pass already-fetched, non-empty message bodies. The handler never calls this
/// with an empty vec (it short-circuits a zero-success export before building), and
/// per-body emptiness isn't expected from a real BODY.PEEK[] fetch.
///
/// Takes the bodies by value and drops each as it is framed, so the raw bodies
/// are freed while the framed buffer grows — the framed mbox is the only
/// `max_total_bytes`-scale allocation held at once, rather than the raw bodies
/// *plus* a separate framing copy (#318).
pub(super) fn build_mbox(messages: Vec<Vec<u8>>) -> Vec<u8> {
    // Pre-size to one allocation: raw body bytes + a separator and a possible
    // padding newline per message. This keeps the framed buffer a single
    // ~`max_total_bytes` allocation, avoiding the transient ~2x spike a growing
    // `Vec` would incur while copying the large body bytes (#318). `From`-line
    // escaping may add a few bytes beyond this; that is negligible and at most
    // one small growth.
    let raw_total: usize = messages.iter().map(Vec::len).sum();
    let framing = messages
        .len()
        .saturating_mul(MBOX_SEPARATOR.len().saturating_add(1));
    let mut out = Vec::with_capacity(raw_total.saturating_add(framing).saturating_add(1));
    for msg in messages {
        // Ensure the previous message ended with a line feed so this
        // separator starts at column 0.
        if let Some(&last) = out.last()
            && last != b'\n'
        {
            out.push(b'\n');
        }
        out.extend_from_slice(MBOX_SEPARATOR);
        escape_from_lines_into(&mut out, &msg);
        // `msg` is dropped here, freeing this body before the next is framed.
    }
    // Trailing newline for a well-formed final message.
    if let Some(&last) = out.last()
        && last != b'\n'
    {
        out.push(b'\n');
    }
    out
}

/// Append `msg` to `out`, escaping each `^>*From ` line with one extra `>`.
fn escape_from_lines_into(out: &mut Vec<u8>, msg: &[u8]) {
    let mut line_start = 0;
    for i in 0..msg.len() {
        if msg[i] == b'\n' {
            write_mbox_line(out, &msg[line_start..=i]);
            line_start = i + 1;
        }
    }
    if line_start < msg.len() {
        write_mbox_line(out, &msg[line_start..]);
    }
}

/// Append `line` to `out`, prefixing it with `>` when it matches `^>*From `.
fn write_mbox_line(out: &mut Vec<u8>, line: &[u8]) {
    if line_is_from(line) {
        out.push(b'>');
    }
    out.extend_from_slice(line);
}

/// Whether `line` (from column 0) matches `^>*From ` — any run of `>` then
/// the literal `From `.
fn line_is_from(line: &[u8]) -> bool {
    let mut j = 0;
    while j < line.len() && line[j] == b'>' {
        j += 1;
    }
    line[j..].starts_with(b"From ")
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod build_mbox_tests {
    use super::build_mbox;

    const SEP: &[u8] = b"From mboxrd@rusty-imap-mcp Thu Jan  1 00:00:00 1970\n";

    #[test]
    fn single_message_gets_separator_and_trailing_newline() {
        let out = build_mbox(vec![b"Subject: hi\r\n\r\nbody".to_vec()]);
        assert!(out.starts_with(SEP), "missing leading separator");
        assert!(out.ends_with(b"\n"), "must end with newline");
        assert!(out.ends_with(b"body\n"));
    }

    #[test]
    fn missing_terminal_newline_padded_before_next_separator() {
        // First message has no trailing newline; the second separator must
        // still start at column 0.
        let out = build_mbox(vec![
            b"a: 1\r\n\r\nno-newline".to_vec(),
            b"b: 2\r\n\r\nx\n".to_vec(),
        ]);
        let text = String::from_utf8(out).unwrap();
        // Exactly two separators, each at the start of a line.
        let seps: Vec<_> = text.match_indices("From mboxrd@").collect();
        assert_eq!(seps.len(), 2);
        for (idx, _) in &seps {
            assert!(
                *idx == 0 || text.as_bytes()[idx - 1] == b'\n',
                "separator not at col 0"
            );
        }
    }

    #[test]
    fn escapes_every_from_line_including_nested_and_header_position() {
        let msg = b"From the desk of X\r\n>From already escaped\r\nFrom \r\nnormal\n".to_vec();
        let out = build_mbox(vec![msg]);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(">From the desk of X"));
        assert!(text.contains(">>From already escaped"));
        assert!(text.contains(">From \r\n"));
        assert!(text.contains("\nnormal"));
    }

    #[test]
    fn preserves_crlf_verbatim_in_body() {
        let out = build_mbox(vec![b"H: 1\r\n\r\nline1\r\nline2\r\n".to_vec()]);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("line1\r\nline2\r\n"));
    }

    #[test]
    fn split_back_round_trips_messages() {
        // Build, then split on separator lines and un-escape; must equal inputs.
        let inputs = vec![
            b"A: 1\r\n\r\nFrom space\r\nbody1\r\n".to_vec(),
            b"B: 2\r\n\r\nbody2\n".to_vec(),
        ];
        let mbox = build_mbox(inputs.clone());
        let recovered = split_and_unescape(&mbox);
        assert_eq!(recovered.len(), inputs.len());
        // Compare ignoring a single trailing newline build_mbox may add.
        for (got, want) in recovered.iter().zip(inputs.iter()) {
            assert_eq!(trim_one_trailing_nl(got), trim_one_trailing_nl(want));
        }
    }

    fn trim_one_trailing_nl(b: &[u8]) -> &[u8] {
        b.strip_suffix(b"\n").unwrap_or(b)
    }

    // Test-only inverse of build_mbox's framing: split on separator lines,
    // strip one leading '>' from each `^>+From ` line.
    fn split_and_unescape(mbox: &[u8]) -> Vec<Vec<u8>> {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut cur: Option<Vec<u8>> = None;
        for line in split_keep_newlines(mbox) {
            if line == SEP {
                if let Some(c) = cur.take() {
                    parts.push(c);
                }
                cur = Some(Vec::new());
            } else if let Some(c) = cur.as_mut() {
                c.extend_from_slice(&unescape_line(line));
            }
        }
        if let Some(c) = cur.take() {
            parts.push(c);
        }
        parts
    }

    fn unescape_line(line: &[u8]) -> Vec<u8> {
        // If line is `>+From `, drop one leading '>'.
        let mut j = 0;
        while j < line.len() && line[j] == b'>' {
            j += 1;
        }
        if j >= 1 && line[j..].starts_with(b"From ") {
            line[1..].to_vec()
        } else {
            line.to_vec()
        }
    }

    fn split_keep_newlines(b: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut start = 0;
        for i in 0..b.len() {
            if b[i] == b'\n' {
                out.push(&b[start..=i]);
                start = i + 1;
            }
        }
        if start < b.len() {
            out.push(&b[start..]);
        }
        out
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod git_am_tests {
    use super::build_mbox;
    use std::process::Command;

    fn git(args: &[&str], cwd: &std::path::Path) -> std::process::Output {
        Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            // Isolate from host config so commit.gpgsign / global hooks /
            // templates / init.defaultBranch cannot spuriously fail git am.
            // The identity env vars above are load-bearing once global
            // user.name/email is suppressed.
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("git runs")
    }

    /// Emits CRLF (`\r\n`) line endings deliberately, mirroring raw RFC822
    /// bytes; the format string mixes `\r\n` with line-continuation backslashes.
    fn patch(n: u32, body_extra: &str) -> Vec<u8> {
        // A minimal git-format-patch-style message: From/Subject/Date headers,
        // then a unified diff creating file_<n>.txt.
        format!(
            "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\r\n\
             From: Dev <dev@example.com>\r\n\
             Date: Mon, 1 Jan 2024 0{n}:00:00 +0000\r\n\
             Subject: [PATCH {n}/2] add file {n}{body_extra}\r\n\
             \r\n\
             ---\r\n \
             file_{n}.txt | 1 +\r\n \
             1 file changed, 1 insertion(+)\r\n\
             \r\n\
             diff --git a/file_{n}.txt b/file_{n}.txt\r\n\
             new file mode 100644\r\n\
             index 0000000..0000001\r\n\
             --- /dev/null\r\n\
             +++ b/file_{n}.txt\r\n\
             @@ -0,0 +1 @@\r\n\
             +content {n}\r\n\
             -- \r\n\
             2.40.0\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn git_am_applies_generated_mbox() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        assert!(git(&["init", "-q"], repo).status.success());

        // A spurious `From `-leading line in the message (here in the header
        // region) must be escaped by build_mbox, or git's mbox splitter would
        // wrongly split the series there.
        let mbox = build_mbox(vec![patch(1, "\r\nFrom the author: note"), patch(2, "")]);
        let mbox_path = repo.join("series.mbox");
        std::fs::write(&mbox_path, &mbox).unwrap();

        let out = git(&["am", mbox_path.to_str().unwrap()], repo);
        assert!(
            out.status.success(),
            "git am failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        let log = git(&["rev-list", "--count", "HEAD"], repo);
        let count = String::from_utf8_lossy(&log.stdout).trim().to_string();
        assert_eq!(count, "2", "expected 2 commits from a 2-patch series");
        assert!(repo.join("file_1.txt").exists());
        assert!(repo.join("file_2.txt").exists());
    }
}
