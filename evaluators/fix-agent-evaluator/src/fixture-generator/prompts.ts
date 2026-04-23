import type { FixtureFormat, RuleEntry } from '../../../shared/rule-catalog/src/index.js';
import type { ValidationFailure } from './types.js';

export const SYNTH_SYSTEM_PROMPT = `You generate minimal test fixtures for a security scanner. Your fixture must:
  1. Trigger the target rule exactly once — no more, no less.
  2. Trigger no other rule from the same scanner. (Findings from other scanners are acceptable and should be ignored.)
  3. Be the smallest plausible project that will cause the scanner to inspect the relevant resource. Do not add unrelated resources, comments, or explanatory prose.
  4. Parse cleanly (CFN: valid CloudFormation; CDK: compiles and synthesizes; Python: parses; other languages: parse in their native tool).
  5. Use realistic identifiers but mark the triggering resource with a marker in metadata, a top comment, or a filename containing the check ID so a human skimming the fixture knows what it's for.

You will be given:
  - The check ID and scanner.
  - The rule's description, priority, and fix guidance (use these to understand what the scanner looks for).
  - For security-matrix rules: the rule's source code (read it carefully — the detection logic is authoritative).
  - A target fixture format (CFN YAML, CDK TypeScript, Python, etc).

When the previous attempt failed validation, you will also be given the failure details. Adjust accordingly — do not repeat the same mistake.

You emit the fixture by calling the submit_fixture tool exactly once with a list of files. Do not narrate your reasoning in prose. Do not output the fixture as text in the response body.`;

export function buildSynthUserPrompt(
    rule: RuleEntry,
    format: FixtureFormat,
    previousFailure: ValidationFailure | null,
): string {
    const lines: string[] = [];
    lines.push(`Target rule: ${rule.checkId} (${rule.scanner})`);
    lines.push(`Priority: ${rule.priority}`);
    lines.push(`Description: ${rule.description}`);
    if (rule.applicableResourceTypes && rule.applicableResourceTypes.length > 0) {
        lines.push(`Applicable resource types: ${rule.applicableResourceTypes.join(', ')}`);
    }
    lines.push('');
    lines.push(`Current fix guidance (for context on what the rule wants):`);
    lines.push(rule.fixGuidance);
    lines.push('');
    if (rule.ruleBody) {
        lines.push(`Rule source code (the authoritative detection logic):`);
        lines.push('```');
        lines.push(rule.ruleBody);
        lines.push('```');
        lines.push('');
    }
    lines.push(`Target fixture format: ${format}`);
    lines.push(formatInstructions(format, rule.scanner));
    if (previousFailure) {
        lines.push('');
        lines.push(`Previous attempt failed validation:`);
        lines.push(`  kind:    ${previousFailure.kind}`);
        lines.push(`  message: ${previousFailure.message}`);
        if (previousFailure.details) {
            lines.push(`  details: ${previousFailure.details.slice(0, 2000)}`);
        }
        lines.push(`Adjust the fixture to address this and avoid introducing new violations.`);
    }
    lines.push('');
    lines.push(`Call submit_fixture exactly once with the complete set of files.`);
    return lines.join('\n');
}

function formatInstructions(format: FixtureFormat, scanner: string): string {
    const checkId = '<CHECK-ID>';
    switch (format) {
        case 'cfn':
            return [
                '',
                `Emit a single file named "template.yaml" containing a valid CloudFormation template.`,
                `Include a top-level comment referencing the check ID: "# SRT fixture: ${checkId}".`,
                `Keep the template minimal — one triggering resource plus any required dependencies.`,
            ].join('\n');
        case 'cdk':
            return [
                '',
                `Emit a minimal CDK TypeScript project with these files:`,
                `  - cdk.json (app command: "npx ts-node bin/app.ts")`,
                `  - package.json (with aws-cdk-lib, constructs, typescript, ts-node, @types/node dependencies)`,
                `  - tsconfig.json (strict: true, target: ES2020, module: commonjs, lib: [ES2020])`,
                `  - bin/app.ts (new cdk.App + one stack)`,
                `  - lib/stack.ts (a Stack subclass defining the triggering construct)`,
                `Add a block comment atop lib/stack.ts: "// SRT fixture: <CHECK-ID>".`,
                `Use aws-cdk-lib v2 APIs. Keep the stack minimal — one triggering construct plus required dependencies.`,
            ].join('\n');
        case 'python':
            return [
                '',
                `Emit a single file named "fixture_${checkId.toLowerCase()}.py" containing the minimum Python code that triggers the rule.`,
                `Begin the file with a comment: "# SRT fixture: ${checkId}".`,
                scanner === 'bandit'
                    ? `Bandit triggers on specific Python constructs (e.g., hardcoded passwords, exec, assert). Ensure the construct is present and avoid neighbouring issues that would trigger other Bandit checks.`
                    : `Include only the construct needed for the target rule.`,
            ].join('\n');
        case 'javascript':
            return [
                '',
                `Emit a single file named "fixture.js" containing the minimum JavaScript that triggers the rule.`,
                `Begin with a comment: "// SRT fixture: ${checkId}".`,
            ].join('\n');
        case 'go':
            return [
                '',
                `Emit a minimal Go project: go.mod declaring module "fixture" with go 1.21, and a single main.go.`,
                `Begin main.go with: "// SRT fixture: ${checkId}".`,
            ].join('\n');
        case 'java':
            return [
                '',
                `Emit a single Java file named Fixture.java. Begin with "// SRT fixture: ${checkId}".`,
            ].join('\n');
        case 'yaml':
            return [
                '',
                `Emit a single YAML file named ".github/workflows/fixture.yml" containing a minimal GitHub Actions workflow that triggers the rule.`,
                `Begin with: "# SRT fixture: ${checkId}".`,
            ].join('\n');
    }
}
