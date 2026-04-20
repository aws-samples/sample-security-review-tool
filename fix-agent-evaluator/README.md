# Fix Agent Evaluator

A test harness that evaluates the quality of fixes produced by the SRT
`FixAgent`. Intentionally **not** part of `src/` — this is a development-time
tool, not a shipped CLI feature.

## What it does

Given a target project folder, the evaluator:

1. Runs `srt` (programmatically, via `AssessCoordinator`) to scan the project
   for security issues.
2. Iterates every **high-priority, open** finding and invokes the `FixAgent`
   (programmatically, via `FixCoordinator.generateFix` / `applyFix`). It
   bookmarks the SRT log file around each run and captures the resulting git
   diff, giving a clean 1:1 mapping between finding and agent session.
3. For each finding, spins up a **reviewer agent** (its own Bedrock Converse
   loop, with read-only `list_files` / `grep` / `read_file` tools) that judges
   the fix on two axes:
     - **Effectiveness** (HIGH / MEDIUM / LOW) — does the change actually
       mitigate the risk, or is it a minimal-compliance workaround?
     - **Efficiency** (HIGH / MEDIUM / LOW) — number of **retries** derived
       from the agent log. A retry is any failed `validate_fix`, `edit_file`,
       or `apply_edits` invocation. HIGH = 0 retries, MEDIUM = 1 retry,
       LOW = 2+ retries. Turn count is reported as context only; different
       rules legitimately need different numbers of turns.
   When either rating is below HIGH, the reviewer returns a **drop-in
   replacement for the rule's `fix` text** so you can paste it straight back
   into the rule source.
4. Writes `reports/evaluation-<timestamp>.md` and `.json`, with problematic
   findings sorted first.

## Why library-mode instead of driving the CLI

`srt fix -e` is interactive (inquirer-based). Scripting it via PTY is fragile:
any change to a prompt breaks the harness, and mapping stdout back to findings
is guesswork. Calling `FixCoordinator.generateFix(issue)` directly gives us
the exact same `FixAgent` execution with none of the UI coupling.

## Usage

```bash
cd fix-agent-evaluator
bun src/index.ts /path/to/target/project
```

(`bun` is used rather than `tsx` because the SRT `src/` tree relies on TS
type-elision at compile time; bun matches the runtime the shipped CLI uses.)

Pre-requisites:

- AWS credentials for Bedrock. Provide them in one of these ways (checked in
  order):
    1. Environment variables: `AWS_REGION` (required), `AWS_PROFILE` (optional,
       defaults to `default`). This is the easiest option when running the
       evaluator under `bun` and avoids the quirk described below.
       ```bash
       export AWS_REGION=us-east-1
       export AWS_PROFILE=my-profile   # optional
       ```
    2. Point `SRT_CONFIG_PATH` at an existing `srtconfig.json` that `srt
       config` has already written next to your installed srt binary.
    3. Auto-discover `srtconfig.json` in common srt install locations
       (`~/.local/bin`, `~/bin`, `/usr/local/bin`).

  > Why this is needed: SRT's own `AppConfig` resolves `srtconfig.json` via
  > `dirname(process.execPath)`. When srt runs as a compiled binary that's
  > the srt install dir; when the evaluator runs under `bun`, `process.execPath`
  > points at the bun interpreter, so `AppConfig` can't find the config. The
  > evaluator initializes `BedrockConfig` directly to sidestep this.

- The target project must be a git repository (the evaluator uses git to
  capture per-finding diffs).
- Commit your working tree in the target project before running, since the
  evaluator will stage the applied fixes as it goes.
- If the target project is a CDK project, install the AWS CDK CLI yourself
  before running — SRT otherwise tries `npm install -g aws-cdk`, which fails
  with EACCES on most Linux/macOS installs. Install it one of these ways:
    - `npm install -g aws-cdk` run under `sudo`, OR
    - with a user-writable npm prefix (recommended):
      ```bash
      mkdir -p "$HOME/.npm-global"
      npm config set prefix "$HOME/.npm-global"
      export PATH="$HOME/.npm-global/bin:$PATH"   # add to ~/.bashrc / ~/.zshrc
      npm install -g aws-cdk
      ```
  Verify with `which cdk` — if that returns a path, SRT will skip the install
  step entirely.

Dev convenience:

```bash
npm run typecheck   # runs `tsc --noEmit`
```

## Output

`reports/evaluation-<timestamp>.md` contains one section per finding, for
example:

```
### ❌ S3-008 — infrastructure/shared-resources.ts (web-bucket)

- Effectiveness: LOW — the added rule only aborts incomplete multipart
  uploads; it does not manage the lifetime of stored objects.
- Efficiency: LOW — 3 retries (12 turns, 3 validate_fix failures).
- Root cause: vague-fix-guidance

**Current fix guidance:**
Configure a lifecycle policy to manage S3 objects during their lifetime.

**Recommended replacement (drop-in for the rule's `fix` string):**
Configure an S3 LifecycleConfiguration with at least one rule that actively
manages stored-object lifetime. ...
```

The corresponding `.json` file has the same content in structured form for
pipeline consumption.
