# README Landing Page and GitHub Pages Design

**Status:** Approved 2026-08-28

## Goal

Make the repository README a useful first page for someone evaluating or installing
`rusty-imap-mcp`, and publish that same content at the repository's GitHub Pages URL.

## Scope

- Put the project logo, plain-language introduction, concise feature list, and quick start before
  contributor or reference material.
- Cover Claude Code, Codex, Cursor, VS Code/GitHub Copilot, and IBM Bob with configurations that
  start the installed `rusty-imap-mcp` binary over stdio. The basic path tells readers to choose
  one client; concurrent clients require separate server configs and audit paths.
- Keep provider-specific account setup in the existing Gmail and Proton Bridge guides.
- Generate a single-page site from `README.md` with Pandoc on pushes to `main` and manual runs.
- Keep generated HTML out of the repository. Commit only the Pandoc template, stylesheet, link
  filter, and deployment workflow.

## Content structure

The README leads with the logo and a two-paragraph explanation of the prompt-injection problem.
It then presents the security and email capabilities in a compact feature list. The quick start
has three steps: install, configure an email account, and connect a coding agent. Detailed
configuration, tool inventories, compatibility notes, packaging details, troubleshooting, and
development commands follow as links or short reference sections.

Client examples use the client-native configuration surface documented by each vendor. JSON
clients share the same server command but retain their required top-level object name. Codex and
Claude Code use their supported CLI registration commands. The examples do not embed credentials;
the server reads its own configuration and resolves credentials from the OS keychain.
Each example links to the vendor's current MCP documentation. JSON and TOML snippets are parsed
during focused verification; CLI forms are checked against the cited command grammar. IBM Bob uses
the project-level `.bob/mcp.json` surface from the current IBM Bob MCP guide.

The quick start explicitly says to choose one client. A reader who wants several clients running
at once is sent to the existing multi-client audit guidance, which requires a separate
`rusty-imap-mcp --config ...` process and audit path for each client.

## Site generation

The implementation first uses the GitHub Pages API, under the user's explicit request to enable a
github.io site, to set the repository's Pages source to GitHub Actions. This one-time repository
setting is verified with a read-back before the workflow is considered deployable.

The workflow checks out the repository, configures Pages, installs Pandoc, converts `README.md` to
`_site/index.html`, copies the stylesheet and logo into `_site`, uploads the Pages artifact, and
deploys it. The deploy job depends on the build job and uses the `github-pages` environment with
its URL taken from the deployment action output. A small HTML template supplies metadata and a
canonical repository link.

`docs/site/rewrite-links.lua` owns generated-site URL handling. Fragment-only links stay local;
the copied logo and stylesheet stay artifact-relative; repository file links become canonical
GitHub `/blob/main/` URLs and directory links become `/tree/main/` URLs while preserving
fragments; already absolute URLs remain unchanged. The filter is exercised against representative
links of each class.

The workflow uses least-privilege permissions: the build job reads repository contents, while the
deploy job alone receives `pages: write` and `id-token: write`. Every GitHub Action is pinned to a
full commit SHA.

## Verification

- A focused shell check asserts the README contains the logo, the three landing-page sections,
  all five coding-client names, and the concurrent-client audit warning.
- JSON and TOML client examples parse successfully. CLI examples match their vendors' cited
  registration grammar.
- Pandoc must produce a standalone HTML document containing the title, logo path, and client
  headings. A generated-site check verifies copied asset targets exist, fragment-only links match
  generated IDs, repository paths were rewritten to canonical GitHub URLs with fragments intact,
  and no other relative URL remains.
- `actionlint`, `zizmor`, markdown hooks, and typo checks cover the workflow and prose.

## Exclusions

This change does not add a multi-page documentation generator, change application behavior, add
an MCP transport, publish the site from pull requests, or create client-specific configuration
files in the repository.
