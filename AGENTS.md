# Repository Guidelines

## Project Structure & Module Organization
Core sources live in `src/`. The `app` module orchestrates global state and command dispatch, while `domain` defines device models, actions, and settings. Networking backends reside in `infrastructure` (scanners, fingerprinter, ARP spoofer). Terminal UI components live under `presentation/tui` with theming in `presentation/tui/theme`. Shared helpers are in `utils`, and `assets/` stores static bundles such as vendor databases or icons used during scans.

## Build, Test, and Development Commands
Use `cargo check` for a fast compile-time validation before submitting changes. Run `cargo fmt` to apply the enforced Rust style; the CI rejects unformatted code. Execute `cargo run --release` to exercise the interactive scanner with realistic performance; prefer a controlled lab network. When test suites are added, prefer `cargo test --all-features` to validate both unit and integration scenarios.

## Debugging Build & Command Issues
When a command fails, rerun it with verbose output: `cargo check -v` or `cargo test -v -- --nocapture` to surface compiler hints and runtime logs. Use `cargo clean` followed by the failing command if incremental artifacts look corrupt. For dependency resolution errors, run `cargo tree` to spot conflicting versions. Capture terminal transcripts (copy the full command and error) in your PR or ticket so other agents can reproduce quickly. If the failure stems from environment assumptions (e.g., missing `libpcap`), document the resolution steps inside the PR description and update onboarding docs when it affects everyone.

## Coding Style & Naming Conventions
Follow standard Rust formatting (4-space indentation, `snake_case` for functions/variables, `PascalCase` for types and enums). Keep modules small and cohesive; split new UI widgets into files inside `presentation/tui/components`. Logs should be short, action-oriented, and localized (Spanish strings are acceptable when consistent with current output). Document non-trivial async flows with brief inline comments describing intent rather than mechanics.

## Testing Guidelines
Add module tests adjacent to the code under `src/...` using `#[cfg(test)]` blocks, and place broader network or TUI flows inside `tests/` for integration coverage. Mock network dependencies by introducing trait abstractions around scanner/spoofer operations to avoid live traffic during automated runs. Name test functions with the pattern `feature_under_test_expected_result`. Before opening a PR, run `cargo test --all-features -- --nocapture` to surface logs helpful for debugging failures.

## Commit & Pull Request Guidelines
Keep commit subjects in the imperative mood (e.g., `feat: add spinner for concurrent scans`). Group related adjustments into a single commit; avoid mixing refactors with feature work. Pull requests should include: summary of changes, manual verification steps (commands run), screenshots or terminal captures for TUI updates, and any linked issue references. Flag networking changes that require elevated privileges or may disrupt live traffic so reviewers can plan validation safely.

## Security & Configuration Tips
Running network scans may need elevated privileges; prefer launching via `sudo cargo run --release` on isolated networks. Store experimental configuration files in `.gitignore`d paths (e.g., `tmp/`) to avoid leaking sensitive data. Never commit device inventories gathered from production environments; scrub logs before sharing.
