# ADR-0030: README is the GitHub Pages source

## Status

Accepted

## Context

New users encounter the repository README first, while a project website offers a cleaner URL and
presentation. Maintaining separate landing-page content would let installation and security
guidance drift.

## Decision

`README.md` is the sole landing-page content source. GitHub Actions runs Pandoc with GitHub
Flavored Markdown input and deploys one generated `index.html` to GitHub Pages. A Pandoc filter
rewrites links to repository files to their canonical GitHub URLs, while the workflow copies the
logo and presentation assets into the artifact. Generated HTML is not committed.

## Consequences

GitHub and Pages render the same source content, though their presentation and generated anchors
can differ. The site build must fail unless conversion succeeds, the expected landing-page
sections and logo are present, and no repository-relative link remains unresolved. Site builds
require Pandoc and the GitHub Pages deployment actions, but the application gains no runtime
dependency.

## Considered & rejected

- **Separate website content — judgment:** it gives the site more layout freedom, but duplicates
  the project's first-run instructions and creates an avoidable drift path.
- **mdBook — verified:** `rg -n 'mdbook' Cargo.toml justfile .github docs` found no existing mdBook
  setup. Adding a second documentation system is unnecessary for one README-derived page.
- **Commit generated HTML — judgment:** it makes every README edit carry generated churn and lets
  source and output disagree between regenerations.
