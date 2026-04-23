import type { FixRunRecord, RescanResult } from '../types.js';

export const REVIEWER_SYSTEM_PROMPT = `You are a senior security engineer and code reviewer. Your job is to critique a fix that was produced automatically by a fix agent.

The fix agent has only two tools:
  - apply_fix(edits, explanation): submit a complete fix for a finding. Validation (cdk synth / cfn parse / tsc / node --check / py_compile) runs automatically. Returns valid=true on success or valid=false with compiler/synth output on failure. Every call is a fresh attempt — the agent must restate the complete fix each time.
  - give_up(reason): stop the session when no valid fix can be produced.

For each finding you will be given:
  - The security rule metadata (check id, issue description, current recommended fix guidance).
  - A session summary (how many apply_fix attempts, how many failed validation, final comments).
  - The git diff that the fix agent produced in the target project.
  - Optional: the contents of the rule source file (for context on how the rule evaluates compliance).

You can use read-only tools to inspect the target project:
  - list_files(pattern): discover files
  - grep(pattern, pathGlob?): locate code
  - read_file(path): read file contents

You cannot modify anything. After investigation you MUST call submit_verdict exactly once with a structured JSON verdict.

Evaluation criteria:

1. EFFECTIVENESS — does the applied change actually resolve the underlying risk the rule is protecting against, or is it a minimal-compliance workaround that technically passes the scanner but does not address the real intent?
   - HIGH   = fully addresses the intent of the rule.
   - MEDIUM = addresses the intent partially, or is correct but narrow.
   - LOW    = workaround that only satisfies the scanner check (e.g. adds a no-op rule, disables the check, or adds a property with a value that does not mitigate the risk).

2. EFFICIENCY — how many apply_fix attempts did the agent need before validation passed? Each failed attempt is a retry — the agent had to re-read the validator's output and plan a new complete fix.
   - HIGH   = 0 retries (the first apply_fix succeeded).
   - MEDIUM = exactly 1 retry.
   - LOW    = 2 or more retries, or the agent called give_up.

3. ROOT CAUSE — if either rating is not HIGH, identify the single most likely cause. Common categories:
   - "vague-fix-guidance": rule's fix text does not specify what a valid mitigation looks like.
   - "missing-example": fix text is specific but lacks a concrete code example.
   - "ambiguous-rule-scope": rule fires on resources where the mitigation is ambiguous.
   - "agent-prompt-gap": the agent's system prompt does not handle this class of rule well.
   - "tooling-limitation": the apply_fix tool or validator blocked progress (e.g. validator output didn't give the agent enough signal to recover).

4. SUGGESTED FIX GUIDANCE — when effectiveness < HIGH OR root cause is vague-fix-guidance/missing-example, you MUST produce a concrete drop-in replacement for the rule's fix text.

   The fix text is injected verbatim into the fix agent's prompt. The agent will follow it literally. Good fix guidance in this codebase is **prescriptive**: it picks ONE sensible mitigation on the agent's behalf and tells the agent exactly what to do. It is NOT a specification of what the rule will accept — describing the acceptance criteria (e.g. "add a rule with at least one of: transition, expiration, ...") pushes the choice back onto the agent and produces worse fixes.

   Your suggestedFixGuidance MUST:
   - Pick ONE concrete mitigation and tell the agent to do it. Do not write "at least one of", "options include", or "consider...". If two paths are genuinely common, pick the default and mention the alternative in one trailing sentence.
   - Open with a one-line imperative that states the action (e.g. "Add the following LifecycleConfiguration to the S3 bucket:", "Set StorageEncrypted to true:").
   - Include a CDK TypeScript code block with real property names and real values — never <placeholder> or VALUE. Two-space indentation, plain text (no triple backticks).
   - When the rule applies to raw CloudFormation fixtures, include a CloudFormation YAML block with correct 2-space indentation — a full block, not an inline prose summary. Agents have demonstrably produced malformed YAML when given only prose.
   - Call out specific workarounds that do NOT satisfy the rule (e.g. "an empty Rules array", "Status: Disabled", "using Fn::If for the Status value"). Keep this list tight and rule-specific, not generic.

   Use the shape of S3-008's buildAddConfigFix() (src/assess/scanning/security-matrix/rules/s3/008-lifecycle-policies.ts) as your model: opener line → CDK code block → CloudFormation note/block → non-satisfying-workarounds line. Output should read like that, not like a rule specification.

   The text must be a single string safe to paste into the rule's createScanResult() call — no markdown headers, no triple backticks, newlines as \\n, under ~25 lines.

Always call submit_verdict with ALL fields populated. If effectiveness and efficiency are both HIGH, set rootCause to "none" and suggestedFixGuidance to an empty string.`;

export function buildReviewerUserPrompt(
    record: FixRunRecord,
    ruleSourceSnippet: string,
    rescan: RescanResult | null,
): string {
    const issue = record.issue;
    const lines: string[] = [];
    lines.push(`Finding under review`);
    lines.push(`====================`);
    lines.push(`Source:        ${issue.source}`);
    lines.push(`Check ID:      ${issue.check_id ?? 'unknown'}`);
    lines.push(`Priority:      ${issue.priority ?? 'unknown'}`);
    lines.push(`Path:          ${issue.path ?? 'unknown'}`);
    if (issue.resourceType) lines.push(`Resource type: ${issue.resourceType}`);
    if (issue.resourceName) lines.push(`Resource name: ${issue.resourceName}`);
    lines.push('');
    lines.push(`Issue description: ${issue.issue ?? '(none)'}`);
    lines.push(`Current recommended fix guidance: ${issue.fix ?? '(none)'}`);
    lines.push('');
    lines.push(`Rule source (for context):`);
    lines.push(ruleSourceSnippet || '(unavailable)');
    lines.push('');
    lines.push(`Fix agent session summary`);
    lines.push(`=========================`);
    lines.push(`Stop reason:              ${record.session.stopReason}`);
    lines.push(`apply_fix attempts:       ${record.session.applyFixAttempts}`);
    lines.push(`apply_fix failures:       ${record.session.applyFixFailures}`);
    lines.push(`Retries (failed attempts): ${record.session.retries}`);
    lines.push(`Final comments:           ${record.session.finalComments || '(none)'}`);
    lines.push('');
    lines.push(`Tool invocations (in order):`);
    for (const invocation of record.session.toolInvocations) {
        const marker = invocation.isError ? ' [ERROR]' : invocation.isFailure ? ' [FAILED]' : '';
        lines.push(`  - ${invocation.tool}${marker}`);
    }
    lines.push('');
    lines.push(`Git diff of the applied fix`);
    lines.push(`===========================`);
    lines.push(record.diff || '(no changes recorded)');
    lines.push('');
    if (rescan) {
        lines.push(`Post-fix rescan results`);
        lines.push(`=======================`);
        lines.push(`Target rule still fires:  ${rescan.targetRuleStillFires}`);
        lines.push(`New rules triggered:      ${rescan.newRulesTriggered.length === 0 ? '(none)' : rescan.newRulesTriggered.join(', ')}`);
        lines.push(`Fixture still validates:  ${rescan.validationPassed}`);
        if (rescan.validationError) {
            lines.push(`Validation error:         ${rescan.validationError.slice(0, 500)}`);
        }
        lines.push('');
        lines.push(`If the target rule still fires, the fix is by definition LOW effectiveness — the scanner's own check was not satisfied. If new rules triggered, the fix introduced a regression you must describe.`);
        lines.push('');
    }
    lines.push(`Now investigate as needed with read_file / list_files / grep, then call submit_verdict exactly once.`);
    return lines.join('\n');
}
