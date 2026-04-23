# Rule Implementation Evaluator

Validates that SRT's **security-matrix rules correctly detect** what they
claim to detect. For each rule, a Strands agent reads the rule source,
consults the official AWS documentation via the AWS Knowledge MCP Server,
and returns a structured verdict: CORRECT, PARTIAL, or INCORRECT.

This is a development-time tool, intentionally outside `src/`.

## Why it's separate from the fix-agent-evaluator

They answer different questions on different cadences:

- **fix-agent-evaluator**: do our fix-guidance strings produce good fixes?
  (Runs when fix text or the agent changes.)
- **rule-impl-evaluator**: do our rules detect the right things?
  (Runs when rule detection logic changes.)

Splitting them keeps the signal clean: if a rule's detection logic is wrong,
any fix-agent evaluation on that rule is already compromised, so you want to
run this one first.

## Scope

**Security-matrix rules only.** Checkov, Bandit, and Semgrep detection logic
is owned by those upstream projects and not meaningfully editable by us.

## How it works

For each rule:

1. Load the rule's full source from the shared rule catalog.
2. Hand the source + metadata to a Strands `Agent` wired with two tool
   providers:
   - `McpClient` pointed at the AWS Knowledge MCP Server
     (`https://knowledge-mcp.global.api.aws`) — exposes
     `search_documentation`, `read_documentation`, `recommend`, and
     `get_regional_availability`. Public, unauthenticated, maintained by AWS.
   - A local `submit_impl_verdict` tool for structured output.
3. The agent investigates via the MCP tools, then submits its verdict by
   calling `submit_impl_verdict` exactly once.
4. The evaluator collects verdicts and writes a report.

### Verdict schema

```ts
interface RuleImplVerdict {
  checkId: string;
  correctness: 'CORRECT' | 'PARTIAL' | 'INCORRECT';
  correctnessReasoning: string;
  awsDocCitations: string[];       // URLs the agent relied on
  missedCases: string[];           // configs that should fire but don't
  falsePositiveRisks: string[];    // configs that fire but are compliant
  suggestedLogicChanges: string;   // concrete code changes if not CORRECT
  ruleSourceHash: string;          // used by --changed on the next run
}
```

### Correctness ratings

- **CORRECT** — detection logic matches AWS best-practice; no important
  misses; no significant false-positive risks.
- **PARTIAL** — mainline case works but misses at least one valid mitigation
  path, or has a non-trivial false-positive risk.
- **INCORRECT** — wrong property, wrong reference values, or structural bug.

## Usage

```bash
cd evaluators/rule-impl-evaluator

bun src/index.ts                              # review every security-matrix rule
bun src/index.ts --rule S3-008                # single rule
bun src/index.ts --service s3                 # one service
bun src/index.ts --changed                    # only rules whose source hash changed since last report
bun src/index.ts --concurrency 4              # parallel reviews (default 4)
```

(`bun` is used rather than `tsx` because the SRT `src/` tree relies on TS
type-elision at compile time; bun matches the runtime the shipped CLI uses.)

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

- **Network access** to `https://knowledge-mcp.global.api.aws`. No API key
  or AWS credentials are required for the MCP endpoint itself; only Bedrock
  access needs AWS auth.

Dev convenience:

```bash
npm run typecheck   # tsc --noEmit
```

## Output

- `reports/impl-review-<timestamp>.md` — grouped by rating
  (INCORRECT → PARTIAL → CORRECT collapsed), one section per rule with
  reasoning, missed cases, false-positive risks, suggested logic changes,
  and AWS doc citations.
- `reports/impl-review-<timestamp>.json` — structured form; used by
  `--changed` on the next run to diff source hashes.

### `--changed` workflow

1. Run `bun src/index.ts` once to establish a baseline report.
2. Edit any rule source.
3. Re-run with `--changed`. Only rules whose source hash differs from the
   latest report are re-reviewed. Useful for quick feedback after a rule
   tweak without paying for a full 191-rule sweep.

## Example output

```
### S3-008

**Reasoning:** The rule targets the correct CloudFormation property
(`LifecycleConfiguration` on `AWS::S3::Bucket`), as confirmed in the AWS
docs. The mainline detection — missing `LifecycleConfiguration` on a bucket —
works. However, the rule only checks for the presence of a truthy value and
does not validate the contents, and it flags intrinsic functions outright.
This creates both missed cases and false positive risks. ...

**Missed cases:**
  - LifecycleConfiguration present but Rules is an empty array
  - LifecycleConfiguration with all rules set to `Status: Disabled`
  ...

**False-positive risks:**
  - Buckets whose LifecycleConfiguration is supplied via an intrinsic
    function are flagged even though the resolved value at deploy time may
    be a fully valid lifecycle configuration
  ...

**Suggested logic changes:**
1) When LifecycleConfiguration is resolved, drill into `Rules` and require
at least one rule with `Status === 'Enabled'` AND at least one of
{Transitions, ExpirationInDays, AbortIncompleteMultipartUpload, ...}.
2) For intrinsic functions, either skip with an informational note ...

**AWS doc citations:**
  - https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-lifecycleconfiguration.html
  - https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-rule.html
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html
```

## Layout

```
rule-impl-evaluator/
  reports/                               # git-ignored
    impl-review-<ts>.{md,json}
  src/
    aws-knowledge-mcp-client.ts          # Strands McpClient wrapper
    bedrock-bootstrap.ts
    reviewer-agent.ts                    # Strands Agent loop
    submit-verdict-tool.ts               # structured-output tool
    evaluator.ts                         # orchestrator, --changed, parallelism
    report-writer.ts
    prompts.ts
    types.ts
    index.ts
# rule catalog imported from ../shared/rule-catalog/
```

## Related

Fix-agent quality (does the fix-text produce a valid fix when handed to the
agent?) is evaluated by the separate
[`fix-agent-evaluator`](../fix-agent-evaluator/README.md).
