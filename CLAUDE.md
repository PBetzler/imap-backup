# CLAUDE.md

This file provides project-specific guidance for Claude Code. It supplements the global `~/.claude/CLAUDE.md` — do not duplicate instructions already defined there.

**You MUST also read and follow [`CONTRIBUTING.md`](CONTRIBUTING.md)** for project coding standards, architecture, build commands, and conventions.

## Modularity Check

During any refactoring task, verify:

1. **Module boundaries** — Confirm the affected code is in the right directory for its responsibility. If a file has grown to serve multiple concerns, consider splitting it.
2. **Unused modules** — Check whether changes have made any modules, files, or directories obsolete. Remove dead code and empty directories.
3. **README.md currency** — If you created, moved, or removed files in a directory, update that directory's `README.md` to reflect the current state.
4. **Documentation placement** — Agent workflow and directives belong in `CLAUDE.md`, project coding standards in `CONTRIBUTING.md`. If you find misplaced content during refactoring, move it to the correct file.

## Review Checklist (Rust-Specific Additions)

In addition to the review checklist in the global `~/.claude/CLAUDE.md`, verify these Rust-specific items:

1. **Rust Rules compliance** — No `unsafe`, no panics (`unwrap()`, `expect()`, `panic!()`, `unreachable!()`), lint rules followed, doc comments on all public items.
2. **SLAP** — Each function operates at a single, consistent level of abstraction.
3. **README.md updates** — If you created, modified, or removed files in any directory, verify that directory's `README.md` is up to date. Create one if it does not exist.

### Build Verification

Run the build verification commands listed in the "Before Submitting" section of [`CONTRIBUTING.md`](CONTRIBUTING.md) and confirm they all pass.

### Review Communication

Use this Rust-adapted format for the mandatory `## Review` section:

```
## Review
- Re-read all modified files — confirmed correct
- Rust Rules compliance verified (no `unsafe`, no panics, lint rules followed)
- Code Design Principles (SLAP, DRY, pure functions) respected
- Error handling verified (`Result`/`Option` propagation)
- README.md updates: verified (all modified directories have current READMEs)
- Scope: changes match the request, no unrelated modifications
- Completeness: all user requests fully addressed
- Improvement opportunities: [none identified / listed suggestions]
- Refactoring assessment: [no files need splitting / file X could benefit from splitting]
- Build verification: cargo build, test, fmt --check, clippy all pass
```
