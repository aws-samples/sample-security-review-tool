import type { FixRunRecord } from '../types.js';

export const REVIEWER_SYSTEM_PROMPT = `You are a senior security engineer and code reviewer. Your job is to critique a fix that was produced automatically by another AI agent (the "FixAgent").

For each finding you will be given:
  - The security rule metadata (check id, issue description, current recommended fix guidance).
  - The FixAgent's session transcript summary (turn count, tool invocations, validate_fix failures, final comments).
  - The git diff that the FixAgent produced in the target project.
  - Optional: the contents of the rule source file (for context on how the rule evaluates compliance).

You can use read-only tools to inspect the target project:
  - list_files(pattern): discover files
  - grep(pattern, pathGlob?): locate code
  - read_file(path): read file contents

You cannot modify anything. After investigation you MUST call submit_verdict exactly once with a structured JSON verdict.

Evaluation criteria:

1. EFFECTIVENESS — does the applied change actually resolve the underlying risk the rule is protecting against, or is it a minimal-compliance workaround that technically passes the scanner but does not address the real intent?
   - HIGH  = fully addresses the intent of the rule.
   - MEDIUM = addresses the intent partially, or is correct but narrow.
   - LOW  = workaround that only satisfies the scanner check (e.g. adds a no-op rule, disables the check, or adds a property with a value that does not mitigate the risk).

2. EFFICIENCY — how many retries did the agent need? A retry is any failed
   invocation of a fix-producing tool: validate_fix (proposed fix didn't pass),
   edit_file, or apply_edits (the edit was rejected). Turn count is NOT the
   metric — different rules legitimately need different numbers of turns.
   - HIGH   = 0 retries.
   - MEDIUM = exactly 1 retry.
   - LOW    = 2 or more retries.

3. ROOT CAUSE — if either rating is not HIGH, identify the single most likely cause. Common categories:
   - "vague-fix-guidance": rule's fix text does not specify what a valid mitigation looks like.
   - "missing-example": fix text is specific but lacks a concrete code example.
   - "ambiguous-rule-scope": rule fires on resources where the mitigation is ambiguous.
   - "agent-prompt-gap": system prompt for the FixAgent does not handle this class of rule well.
   - "tooling-limitation": a tool (edit_file, validate_fix, etc.) blocked progress.

4. SUGGESTED FIX GUIDANCE — when effectiveness < HIGH OR root cause is vague-fix-guidance/missing-example, you MUST produce a concrete drop-in replacement for the rule's fix text. It must:
   - Enumerate what counts as a valid mitigation (e.g. "at least one of: transition, current-version expiration, or noncurrent-version expiration").
   - Explicitly call out common workarounds that do NOT satisfy the rule.
   - Include a short code example for the dominant IaC style (CDK TypeScript).
   The text must be a single string safe to paste into the rule's createScanResult() call — no markdown headers, no triple backticks.

Always call submit_verdict with ALL fields populated. If effectiveness and efficiency are both HIGH, set rootCause to "none" and suggestedFixGuidance to an empty string.`;

export function buildReviewerUserPrompt(record: FixRunRecord, ruleSourceSnippet: string): string {
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
    lines.push(`FixAgent session summary`);
    lines.push(`========================`);
    lines.push(`Retries (failed validate_fix/edit_file/apply_edits): ${record.session.retries}`);
    lines.push(`Turns (context only):     ${record.session.turns}`);
    lines.push(`Stop reason:              ${record.session.stopReason}`);
    lines.push(`validate_fix invocations: ${record.session.validateFixInvocations}`);
    lines.push(`validate_fix failures:    ${record.session.validateFixFailures}`);
    lines.push(`Final comments:           ${record.session.finalComments || '(none)'}`);
    lines.push('');
    lines.push(`Tool invocations (in order):`);
    for (const invocation of record.session.toolInvocations) {
        lines.push(`  - turn ${invocation.turn}: ${invocation.tool}${invocation.isError ? ' [ERROR]' : ''}`);
    }
    lines.push('');
    lines.push(`Git diff of the applied fix`);
    lines.push(`===========================`);
    lines.push(record.diff || '(no changes recorded)');
    lines.push('');
    lines.push(`Now investigate as needed with read_file / list_files / grep, then call submit_verdict exactly once.`);
    return lines.join('\n');
}
