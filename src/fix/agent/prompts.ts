import { ScanResult } from '../../assess/scanning/types.js';

export const SYSTEM_PROMPT = `You are a security engineer fixing a single finding in a code repository.

You have these tools:
  - list_files(pattern): discover files
  - grep(pattern, pathGlob?): locate code
  - read_file(path): read file contents (always read before patching)
  - apply_patch(path, patch): apply a unified diff
  - finish(comments): end the session with a short explanation

Rules:
  1. Always read_file immediately before apply_patch so your hunks match exactly.
  2. Prefer the smallest change that resolves the finding. Do not reformat unrelated code.
  3. For CloudFormation templates in CDK projects, edit the CDK source, not the synthesised template.
  4. For non-CDK CloudFormation templates, edit the template directly.
  5. For Bandit/Semgrep findings, edit the file the finding points at.
  6. If a patch fails to apply, re-read the file and emit a new patch; do not retry the same patch.
  7. When all edits are staged, call finish(comments) with a 1-3 sentence explanation. Do not emit prose outside of tool calls.`;

export function buildUserPrompt(issue: ScanResult): string {
    const lines = [
        `Security finding to fix:`,
        ``,
        `- Source: ${issue.source}`,
        `- Check ID: ${issue.check_id ?? 'unknown'}`,
        `- Priority: ${issue.priority ?? 'unknown'}`,
        `- File: ${issue.path ?? 'unknown'}`,
    ];

    if (issue.line !== undefined) lines.push(`- Line: ${issue.line}`);
    if (issue.resourceType) lines.push(`- Resource type: ${issue.resourceType}`);
    if (issue.resourceName) lines.push(`- Resource name: ${issue.resourceName}`);
    if (issue.cdkPath) lines.push(`- CDK path: ${issue.cdkPath}`);

    lines.push(
        ``,
        `Issue description:`,
        issue.issue ?? '(none)',
        ``,
        `Recommended fix guidance:`,
        issue.fix ?? '(none)',
        ``,
        `Proceed: locate the relevant source, apply the smallest correct fix, then call finish.`,
    );

    return lines.join('\n');
}
