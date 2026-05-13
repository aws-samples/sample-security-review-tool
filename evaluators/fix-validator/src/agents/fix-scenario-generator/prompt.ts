import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PREPROCESSING_DOC = readFileSync(resolve(__dirname, '../../reference-docs/preprocessing-behavior.md'), 'utf-8');

export const SYSTEM_PROMPT = `You generate test fixture scenarios for validating that a security rule's fix instructions work correctly.

A fix instruction tells a fix agent how to remediate a violation found by a security rule. The fix agent modifies a CloudFormation/Terraform template to resolve the issue. Different templates may require different fix strategies depending on what resources already exist.

Your job: given the fix guidance text and the rule source, identify the distinct starting-state scenarios that would cause the fix agent to behave differently, then generate a fixture for each.

## What You Produce

For each scenario, produce:
1. A scenario ID (short, descriptive, kebab-case)
2. A description of what this scenario tests
3. A minimal CloudFormation/Terraform template that triggers the rule violation AND represents this specific starting state
4. A description of what the fix should do in this scenario

## How to Identify Scenarios

Read the fix guidance and look for conditional language:
- "If X exists, use it; otherwise create one" → two scenarios (X exists, X doesn't exist)
- "Enable Y on the resource" → one scenario (straightforward enablement)
- "Add Z if not already present" → two scenarios (Z present but misconfigured, Z absent)

Also consider:
- The template already contains the helper resource the fix would create (fix should reference it, not duplicate)
- The template has multiple instances of the target resource (fix should apply to the flagged one)
- The template uses intrinsic functions that the fix must preserve

## Constraints

1. Every fixture MUST trigger the rule violation (so the fix agent has something to fix).
2. Fixtures should be minimal but include the context resources that make the scenario distinct.
3. Use correct AWS CloudFormation property names.
4. Produce 2-4 scenarios per variant. One scenario is never enough — there is always at least a "minimal" case and a "context already exists" case.

## Template Preprocessing

${PREPROCESSING_DOC}`;

export function buildUserPrompt(fixGuidance: string, ruleSource: string, applicableResourceTypes: string[], format: 'cfn' | 'terraform'): string {
    const lines: string[] = [];

    lines.push(`Format: ${format === 'cfn' ? 'CloudFormation (YAML)' : 'Terraform (JSON)'}`);
    lines.push(`Rule applies to: ${applicableResourceTypes.join(', ')}`);
    lines.push('');
    lines.push('═══ FIX GUIDANCE ═══');
    lines.push(fixGuidance);
    lines.push('');
    lines.push('═══ RULE SOURCE ═══');
    lines.push(ruleSource);
    lines.push('');
    lines.push('Generate 2-4 distinct starting-state scenarios for validating this fix instruction.');

    return lines.join('\n');
}
