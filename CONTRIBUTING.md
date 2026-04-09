# Contributing

## AI Agents

If you are an AI coding agent, you **MUST** also read and follow [`CLAUDE.md`](CLAUDE.md), which contains agent-specific behavioral directives and review procedures.

## Build Commands

```bash
# Build
cargo build

# Run tests
cargo test

# Format and lint
cargo fmt
cargo clippy
```

## Code Design Principles

### Single Level of Abstraction Principle (SLAP) — Mandatory

Each function must operate at a **single, consistent level of abstraction**. A function should either orchestrate high-level steps or perform low-level work — never both.

**Why:** Mixing abstraction levels makes functions harder to read, test, and maintain. When a function jumps between coordinating steps and implementing details, the reader must constantly shift mental context.

**Do:**

```rust
/// Process a batch of incoming records.
fn process_batch(records: &[Record]) -> Result<BatchReport, ProcessError> {
    let validated = validate_records(records)?;
    let transformed = transform_records(&validated)?;
    let report = generate_report(&transformed)?;
    Ok(report)
}
```

Each step delegates to a function at the next level down. The orchestrator reads like a summary.

**Don't:**

```rust
fn process_batch(records: &[Record]) -> Result<BatchReport, ProcessError> {
    // High-level step mixed with low-level details
    let mut validated = Vec::new();
    for record in records {
        if record.name.is_empty() || record.value < 0 {
            continue;
        }
        validated.push(record.clone());
    }

    let transformed = transform_records(&validated)?;

    // More low-level details at the same level as orchestration
    let mut total = 0;
    let mut errors = 0;
    for item in &transformed {
        if item.status == Status::Success {
            total += item.value;
        } else {
            errors += 1;
        }
    }

    Ok(BatchReport { total, errors, count: transformed.len() })
}
```

This mixes orchestration with inline implementation. Extract the low-level loops into their own functions.

### Prefer Pure Functions

Prefer pure functions (deterministic, no side effects) over functions that mutate state or perform I/O. Pure functions are easier to test, reason about, and compose. Isolate side effects (mutation, I/O, logging) into clearly identified functions and modules — keep the core logic pure.

### Don't Repeat Yourself (DRY)

Do not duplicate code. If the same logic appears in more than one place, extract it into a shared function, module, or constant. This applies equally to production code and test code — use shared helper functions and fixtures instead of copying setup or assertion logic between tests. Test independence is not a justification for duplication.

## Modularity

The project must be structured modularly. Related functionality belongs in focused directories with clear boundaries and purpose.

### README.md per Directory

Every directory containing source code must have a `README.md` that describes:

1. **What** the directory contains and its purpose
2. **When** its code should be modified (what kinds of changes would touch this directory)

These files are orientation guides — any contributor should be able to read a directory's `README.md` and quickly determine whether this is the right place to add or modify functionality. Keep them concise and proportional to the directory's complexity.

## Rust Rules

- **Never use `unsafe` code.** Any `unsafe` block must have a preceding `// SAFETY:` comment explaining why it is sound.
- **Never panic.** Use `Result`/`Option` for error handling. No `unwrap()`, `expect()`, `panic!()`, or `unreachable!()` in production code.
- **Lint enforcement** — The compiler denies `unwrap_used`, `expect_used`, `panic`, and `unsafe_code`. Use targeted `#[allow(...)]` or `#[expect(...)]` only where explicitly justified.
- **`#[expect]` over `#[allow]`** — When suppressing a lint, prefer `#[expect(lint)]` over `#[allow(lint)]` so stale suppressions are caught. Use `#[allow]` only when the suppression applies broadly to generated or external code where the lint may not always fire.
- **Doc comments** — All public items must have `///` doc comments. The first line should be a single sentence describing what the item does.
- **Testing** — Every function that can be tested must have tests. Pure functions (those with deterministic inputs/outputs and no side effects) must have unit tests in the same module. Integration tests belong in dedicated test files. Tests are allowed to use `unwrap()`, `expect()`, and `panic!()`.
- **Preserve error context** — Prefer `Result<T, E>` over `Option<T>` when the caller needs to know *why* an operation failed. Do not collapse multiple failure modes into a single `None`.
- **Named constants for domain values** — Use `const` declarations with descriptive names for domain-specific numbers (thresholds, limits, sizes). Do not inline magic numbers.

## Key Conventions

- Run `cargo fmt` and `cargo clippy` before committing.
- Validate inputs at system boundaries (CLI arguments, network responses, config files). Trust internal types within the crate — do not add redundant checks deep in the call stack.

## Before Submitting

Run all of the following and confirm they pass before committing:

```bash
cargo build
cargo test
cargo fmt --check
cargo clippy
```

If any command fails, fix the issues before submitting your changes.
