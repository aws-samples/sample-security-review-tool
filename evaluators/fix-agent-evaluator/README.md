# Fix Agent Evaluator

Validates the quality of fixes produced by the SRT fix agent
(`StrandsFixAgent`). Intentionally **not** part of `src/` — this is a
development-time tool, not a shipped CLI feature.

Two modes:

- **Fixture mode (default)** — iterate every fixable rule in the catalog,
  synthesize a minimal test project per rule, scan → fix → rescan → review,
  and produce a coverage report. Catches rules with deficient fix guidance
  without anyone having to hand-build test projects.
- **Project mode (legacy)** — point it at an existing git repository and
  evaluate whichever findings happen to fire there. Kept for cases where you
  want to evaluate real-world behavior on a specific project.

## What fixture mode does

For each `(rule, format)` combination the catalog produces:

1. **Generate a fixture.** A Bedrock agent synthesizes the smallest
   source code that triggers exactly one finding for the target rule and
   zero findings from other rules in the same scanner. Up to 3 validation
   retries; if still failing, the rule is marked `UNGENERATABLE`.
   Fixtures are cached at `fixtures/<scanner>/<format>/<CHECK-ID>/` and
   invalidated when the rule's source hash changes.
2. **Scan the fixture** via `AssessCoordinator` to seed `.srt/issues.json`
   and the pre-fix issue set.
3. **Fix the single target finding** by calling
   `FixCoordinator.generateFix` + `applyFix` directly. The log file is
   bookmarked so the per-finding agent session can be reconstructed.
4. **Rescan** the fixture. Returns three objective signals:
   - `targetRuleStillFires` — should be false
   - `newRulesTriggered` — should be empty
   - `validationPassed` — fixture still parses / synthesizes
5. **Review** the fix with a read-only Bedrock agent that rates:
   - **Effectiveness** (HIGH / MEDIUM / LOW) — does the change actually
     mitigate the risk, or is it a minimal-compliance workaround?
   - **Efficiency** (HIGH / MEDIUM / LOW) — number of failed `apply_fix`
     attempts. HIGH = 0 retries, MEDIUM = 1, LOW = 2+ or `give_up`.
   When effectiveness is below HIGH the reviewer returns a drop-in
   replacement for the rule's `fix` text.
6. **Reset** the fixture (`git reset --hard HEAD && git clean -fdx`) so the
   next run starts clean.

## Pass criteria

A rule passes for a given format only if all of:

- Effectiveness = HIGH
- Efficiency = HIGH
- Rescan: target rule no longer fires
- Rescan: no new rules triggered
- Rescan: fixture still validates

All five are surfaced in the coverage report's failure-reasons column so
you can see exactly which bar the rule fell below.

## Scanners covered

The catalog exposes every fixable rule across the four scanners whose
findings reach the fix agent:

| Scanner | Rules | Fixture formats |
| --- | ---: | --- |
| security-matrix | ~191 | `cfn`, `cdk` |
| checkov         | ~451 | `cfn`, `cdk` |
| bandit          | ~75  | `python` |
| semgrep         | ~200 | inferred from rule ID prefix (`python.*` → python, `yaml.github-actions.*` → yaml, etc.) |

Syft findings are excluded — they never reach the fix agent.

## Why library-mode instead of driving the CLI

`srt fix -e` is interactive (inquirer-based). Scripting it via PTY is
fragile: any change to a prompt breaks the harness, and mapping stdout back
to findings is guesswork. Calling `FixCoordinator.generateFix(issue)`
directly gives us the exact same fix-agent execution with none of the UI
coupling.

## Usage

```bash
cd evaluators/fix-agent-evaluator

# Fixture mode
bun src/index.ts                              # every rule, every applicable format
bun src/index.ts --rule S3-008                # single rule, all its formats
bun src/index.ts --rule S3-008 --format cfn   # single rule, single format
bun src/index.ts --source checkov             # one scanner
bun src/index.ts --service s3                 # one service
bun src/index.ts --format cfn,cdk             # limit to specific formats
bun src/index.ts --regenerate                 # force fixture regeneration

# Project mode (legacy)
bun src/index.ts /path/to/target/project
```

(`bun` is used rather than `tsx` because the SRT `src/` tree relies on TS
type-elision at compile time; bun matches the runtime the shipped CLI uses.)

### Filtering

- `--rule <checkId>` — one rule (e.g., `S3-008`, `CKV_AWS_3`, `B105`).
- `--source <scanner>` — `security-matrix` | `checkov` | `bandit` | `semgrep`.
- `--service <name>` — e.g., `s3`, `rds`, `lambda`. Classified from the rule's
  file path (security-matrix) or policy text (Checkov). Not every rule is
  classified; Bandit and Semgrep rules have no service.
- `--format <list>` — comma-separated subset of `cfn,cdk,python,yaml,...`.

### Pre-requisites

- **AWS credentials for Bedrock.** Provide them one of:
    1. Environment variables: `AWS_REGION` (required), `AWS_PROFILE`
       (optional, defaults to `default`).
       ```bash
       export AWS_REGION=us-east-1
       export AWS_PROFILE=my-profile   # optional
       ```
    2. Point `SRT_CONFIG_PATH` at an existing `srtconfig.json`.
    3. Auto-discovered `srtconfig.json` in `~/.local/bin`, `~/bin`, or
       `/usr/local/bin`.

  > Why: SRT's `AppConfig` resolves `srtconfig.json` via
  > `dirname(process.execPath)`, which points at the bun interpreter when
  > running under bun. The evaluator initializes `BedrockConfig` directly
  > to sidestep this.

- **Project mode only:** target must be a committed git repository. The
  evaluator stages fixes between findings.
- **CDK projects:** install the AWS CDK CLI yourself before running — SRT
  otherwise attempts `npm install -g aws-cdk`, which fails with EACCES on
  most Linux/macOS installs. Either run that command under `sudo`, or use a
  user-writable npm prefix:
  ```bash
  mkdir -p "$HOME/.npm-global"
  npm config set prefix "$HOME/.npm-global"
  export PATH="$HOME/.npm-global/bin:$PATH"
  npm install -g aws-cdk
  ```

Dev convenience:

```bash
npm run typecheck   # tsc --noEmit
```

## Output

Both modes write a per-finding drill-down:

- `reports/evaluation-<timestamp>.md` — one section per finding
- `reports/evaluation-<timestamp>.json` — structured form

Fixture mode additionally writes:

- `reports/coverage-<timestamp>.md` — pass-rate per scanner, failure table
  sorted by severity of failure, per-rule suggested fix-text replacements,
  ungeneratable list.

Example drill-down entry:

```
### ❌ S3-008 — infrastructure/shared-resources.ts (web-bucket)

- Effectiveness: LOW — the added rule only aborts incomplete multipart
  uploads; it does not manage the lifetime of stored objects.
- Efficiency: LOW — 3 retries (retries: 3, turns: 4, apply_fix failures: 3).
- Root cause: vague-fix-guidance

**Current fix guidance:**
Configure a lifecycle policy to manage S3 objects during their lifetime.

**Recommended replacement (drop-in for the rule's `fix` string):**
Configure an S3 LifecycleConfiguration with at least one rule that actively
manages stored-object lifetime. ...
```

## Layout

```
fix-agent-evaluator/
  fixtures/                              # git-ignored; generated on demand
    security-matrix/
      cfn/<CHECK-ID>/
      cdk/<CHECK-ID>/
    checkov/
      cfn/<CHECK-ID>/
      cdk/<CHECK-ID>/
    bandit/<CHECK-ID>/
    semgrep/<CHECK-ID>/
  reports/                               # git-ignored
    evaluation-<ts>.{md,json}
    coverage-<ts>.md                     # fixture mode only
  src/
    fixture-generator/                   # bedrock synth + validate + cache
    rescan-checker.ts
    reviewer/                            # effectiveness + efficiency reviewer
    report/
    srt-runner.ts
    evaluator.ts
    index.ts
# rule catalog imported from ../shared/rule-catalog/
```

## Related

Rule *implementation* correctness (does the rule's `evaluate()` method
actually detect the misconfiguration it claims to?) is evaluated by the
separate [`rule-impl-evaluator`](../rule-impl-evaluator/README.md).
