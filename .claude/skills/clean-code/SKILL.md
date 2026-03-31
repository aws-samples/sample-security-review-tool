---
name: clean-code
description: Analyze and refactor code towards Robert C. Martin's Clean Code principles. Scans files or directories for violations and suggests targeted refactorings.
argument-hint: [path-to-file-or-directory]
allowed-tools: Bash, Read, Glob, Grep, Edit, Write
---

# Clean Code Analyzer

Analyze the Spark codebase against Robert C. Martin's *Clean Code* principles. Produces a prioritized findings report and applies approved refactorings with build verification.

## Arguments

`$ARGUMENTS` is an optional file path or directory, resolved relative to the project root `/home/ubuntu/git/spark-refinement`.

**If `$ARGUMENTS` is a file path:** Analyze that single file.

**If `$ARGUMENTS` is a directory:** Scan all `.ts` and `.tsx` files in that directory recursively.

**If `$ARGUMENTS` is empty:** Present the module map below and ask the user which area to analyze.

### Module Map

| Module | Path | Description |
|--------|------|-------------|
| `src/hooks` | `src/hooks/` | React hooks |
| `src/components` | `src/components/` | React UI components |
| `src/pages` | `src/pages/` | Page components |
| `src/contexts` | `src/contexts/` | Context providers |
| `src/utils` | `src/utils/` | Utility functions |
| `agents/build` | `agents/build/` | Build agent |
| `agents/prd` | `agents/prd/` | PRD agent |
| `agents/design` | `agents/design/` | Design agent |
| `packages/types` | `packages/types/` | Shared type definitions |
| `infra/` | `infra/` | CDK infrastructure |

---

## Analysis Workflow

Execute these six phases in order. Never skip ahead.

### Phase 1 — Discovery

1. Resolve the target from `$ARGUMENTS` or the user's module choice.
2. Use `Glob` to find all `.ts` and `.tsx` files in scope. Exclude paths matching `node_modules/`, `dist/`, `bundle/`, and `*.test.ts` / `*.test.tsx`.
3. Run `wc -l` on all discovered files and sort descending by line count. This prioritizes which files to analyze first — larger files have more potential violations.
4. If the target yields more than 30 files, inform the user and suggest analyzing sub-modules individually. Proceed only with user confirmation.

### Phase 2 — Principle-by-Principle Analysis

Read each file (largest first) and evaluate against the 10 principles in the checklist below. For DRY analysis, also run `Grep` across all project files to find duplicate function names and repeated patterns.

Track every finding with:
- A unique ID (e.g., `H1`, `M3`, `L2`)
- The principle violated
- The file path(s) and line number(s)
- A concise description of the problem
- A suggested fix with a code snippet
- Effort estimate: `Low` (< 5 min), `Medium` (5-15 min), `High` (> 15 min)

### Phase 3 — Convergence Filter

Before generating the report, apply these filters to every candidate finding. **Remove any finding that fails a filter.**

**Filter A — Cross-Principle Impact Check:**
For each candidate fix, mentally apply it and check whether it would introduce a new violation of a *different* principle at equal or higher severity. Common cascades to check:
- Extracting a function (P2) → Does the new function need a non-obvious name (P1)?
- Extracting shared code for DRY (P4) → Does the new module reduce cohesion (P9)?
- Splitting for SRP (P3) → Does the split create formatting churn (P6)?
- Renaming a variable (P1) → Does this make an existing comment stale (P5)?

If you cannot propose a fix that is **net-positive across all principles**, discard the finding.

**Filter B — Clear Violation Threshold:**
Only report a finding if a senior TypeScript developer would agree it is a genuine problem *without additional context*. If the issue requires knowledge of personal style preferences, subjective judgment about "enough abstraction," or debatable naming taste, it is not a clear violation. **Discard it.**

### Phase 4 — Report Generation

**If zero findings survive the Convergence Filter**, do not generate a findings report. Instead, output:

> **Clean Code Analysis: PASS**
> **Target:** \<path analyzed\>
> **Files scanned:** \<count\>
>
> All files in this module meet Clean Code standards. No findings.

Then **stop**. Do not proceed to Phase 5 or Phase 6.

**Otherwise**, present a structured report in this format:

```
## Clean Code Analysis Report
**Target:** <path analyzed>
**Files scanned:** <count>
**Issues found:** <total> (HIGH: <n>, MEDIUM: <n>, LOW: <n>)

---

### HIGH Priority

#### [H1] <Principle>: <Short title>
**Files:** <file:line, file:line, ...>
**Description:** <What the problem is>
**Suggested fix:**
\`\`\`ts
// code snippet showing the refactored approach
\`\`\`
**Effort:** Low | Medium | High

---

### MEDIUM Priority
...

### LOW Priority
...
```

### Phase 5 — Approval

After presenting the report, ask:

> Which findings should I fix? You can specify by ID (e.g., `H1, H2, M3`), by priority level (e.g., `all high`), or `all`. Say `none` to stop here.

**Never apply changes without explicit user approval.**

### Phase 6 — Incremental Application

Apply approved fixes one at a time, in priority order (HIGH first):

1. Apply the fix using `Edit` or `Write`.
2. Run `npm run build` from the project root to verify compilation.
3. If the build fails, revert the change immediately and inform the user what went wrong.
4. If the build succeeds, report the applied change and move to the next fix.

After all approved fixes are applied:

1. Run `npm run build` as a final verification.
2. Run `npm run lint` from the project root.
3. Summarize all changes made.
4. Do **NOT** commit automatically — let the user decide when to commit.

---

## Clean Code Principle Checklist

### Principle 1: Meaningful Names

Look for:
- Single-letter variable names (except loop counters `i`, `j`, `k`)
- Abbreviated names that are **not** standard TypeScript/Node.js idioms. The following abbreviations are **allowed** and must not be flagged: `err` (catch blocks), `ctx` (context parameters), `ref` (React refs), `val` (map/reduce callbacks), `cb` (callback parameters), `fn` (function parameters), `cfg` (configuration objects), `req`/`res` (HTTP handlers), `msg` (message handlers), `env` (environment). Only flag abbreviations that are project-specific and unclear to a new reader (e.g., `prjMgr`, `svcDsc`, `bldCfg`).
- Generic names that carry no meaning even in context. The following are **allowed** when the surrounding code makes their meaning clear: `result` (return value of a single operation), `data` (parsed response body), `item` (loop variable over a named collection), `value` (map/reduce callbacks). Only flag when the generic name is used far from its initialization or when two or more generic names coexist in the same scope (e.g., `data` and `result` and `value` all in one function).
- Classes/interfaces that are not nouns, functions/methods that are not verbs
- Encoding in names (Hungarian notation, type prefixes like `strName`, `iCount`)

**Judgment rule:** If the abbreviated or generic name is clearer than its expanded form *in context*, it is acceptable. For example, `catch (err)` is clearer than `catch (caughtError)` because it is a universal convention. Only flag names where expansion would genuinely improve readability for a developer unfamiliar with the code.

**Good:** `fetchActiveProjects`, `SessionTracker`, `isSprintComplete`
**Bad:** `getData`, `doStuff`, `ProcessorManager`, `x`, `tmp`, `prjMgr`

### Principle 2: Small Functions

Look for:
- Functions exceeding 30 lines of logic (exclude blank lines, closing braces, type declarations, and single-line logging statements). Only flag at 20 lines if the function also has 2+ levels of nesting or 3+ parameters. A function between 20–30 lines with linear flow and a single responsibility is acceptable.
- Functions with more than 3 parameters
- Functions with more than 2 levels of nesting (indentation depth)
- Arrow functions in JSX that exceed 8 lines (should be extracted). Inline handlers of 5–8 lines are acceptable if they contain only a switch/conditional over the component's own props.

### Principle 3: Single Responsibility

Look for:
- Files that handle more than one distinct domain concern
- React hooks that manage unrelated pieces of state
- Functions that both compute a result AND produce a side effect
- Files with many exports spanning different logical areas

### Principle 4: DRY (Don't Repeat Yourself)

Look for:
- Functions with identical or near-identical implementations across files
- Repeated code patterns (e.g., the same error handling block, the same parsing logic)
- Copy-pasted utility functions that differ only in a type parameter
- Use `Grep` to search the entire project for function names found in the target scope — flag any duplicates

### Principle 5: Comments

Look for:
- Comments that explain **what** the code does (the code should be self-documenting)
- Commented-out code blocks
- Journal comments (change logs in source files)
- Noise comments (`// constructor`, `// default`, `// increment i`)

**Acceptable:** `TODO`/`FIXME` markers, "why" comments explaining non-obvious decisions, JSDoc on public API boundaries.

### Principle 6: Formatting

Look for:
- Missing blank lines between logically distinct sections of a function
- Related declarations that are far apart in the file
- Inconsistent import ordering (framework → external → internal → relative is the convention)
- Function parameters laid out vertically (should be horizontal per project convention)
- Inconsistent function and method ordering (source files should read like a newspaper: high-level methods/functions at the top, low-level details at the bottom)

### Principle 7: Error Handling

Look for:
- Functions that return `boolean` success/failure instead of throwing exceptions
- Functions that return `null` where an exception or a typed `Result` would be clearer
- Empty `catch` blocks (`catch {}` or `catch (e) {}` with no handling)
- Repeated error-stringification patterns (e.g., `err instanceof Error ? err.message : String(err)`) — these should be extracted into a shared utility
- Inconsistent error handling strategies within the same module

### Principle 8: Law of Demeter

Look for:
- Long property access chains: `obj.a.b.c.d`
- Excessive non-null assertion operators (`!`) which indicate knowledge of internal structure
- Functions that reach deep into objects they receive as parameters

### Principle 9: Cohesion

Look for:
- Files that mix high-level orchestration with low-level implementation details
- Modules importing from many unrelated sources (sign of low cohesion)
- Classes or objects with groups of methods that never interact with each other

### Principle 10: One Level of Abstraction per Function

Look for:
- Functions where some lines are high-level orchestration calls (e.g., `await deployInfrastructure()`) and other lines are low-level inline logic (e.g., `const chunks = buffer.split('\n').filter(Boolean)`)
- Functions that mix business logic with serialization, logging, or I/O details

---

## Priority Classification

- **HIGH**: DRY violations across 3+ files, functions exceeding 40 lines, SRP violations in core business logic, boolean error codes in critical paths
- **MEDIUM**: Functions 30–40 lines, naming issues on public APIs, mixed abstraction levels, single-file DRY violations
- **LOW**: Minor local variable naming issues, formatting inconsistencies, optional comment cleanup

---

## Readability Over Rules

Clean Code principles are heuristics, not laws. When a principle conflicts with readability, **readability wins**. Specifically:

- Do not extract a function if the extraction makes the caller harder to understand (e.g., a long but linear `switch` statement should stay as one function).
- Do not rename a variable if the new name is longer and no clearer in context.
- Do not split a file for SRP if the resulting files would each be under 30 lines and tightly coupled.
- Do not extract a DRY abstraction if it would only be used twice and the abstraction obscures the intent.
- Do not flag formatting issues that are consistent within the file, even if they differ from the project convention, unless the file is being modified for other reasons.

**When in doubt, do not report the finding.** A false negative (missing a real issue) is far less costly than a false positive (suggesting a change that makes code worse or triggers a new finding on the next run).

---

## Constraints

- **Never modify test files** unless the user explicitly asks for it.
- **Never touch** `node_modules/`, `dist/`, `bundle/`, or generated files.
- **Always run `npm run build`** after each applied fix to verify compilation.
- **Preserve existing exports** to avoid breaking downstream consumers. When extracting shared code, re-export from the original location if needed.
- **Shared frontend utilities** should be placed in `src/utils/`.
- **Shared agent utilities** should be placed in the relevant agent's directory or a common agent utility location if one exists.
- **Do not auto-commit** changes. Let the user decide when to commit.
- **Do not over-engineer fixes.** Each refactoring should be the minimal change that resolves the identified violation. Do not introduce new abstractions beyond what the fix requires.
