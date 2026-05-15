import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { RuleRequirement } from '../../shared/types/requirements.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
//const CANONICAL_TEST = readFileSync(resolve(srtRepoRoot(), 'tests', 'core', 'scanners', 'srt', 'rules', 's3', '001-access-logging.test.ts'), 'utf-8');

export const SYSTEM_PROMPT = `You write a single Vitest test file for one security-rule requirement. Use the fileEditor tool with command 'create' to write the file at the path I give you. Follow the canonical pattern shown below. Do not add commentary — output only the tool call to create the file.`;

export function buildUserPrompt(testPath: string, controlPath: string, factoryPath: string, ruleId: string, service: string, format: 'cfn' | 'tf', requirement: RuleRequirement): string {
    const lines: string[] = [];

    lines.push(`Target test file path: ${testPath}`);
    lines.push(`Format: ${format === 'cfn' ? 'CloudFormation' : 'Terraform'}`);
    lines.push(`Rule ID: ${ruleId} — Service: ${service}`);
    lines.push('');
    lines.push('═══ IMPORT SOURCES ═══');
    lines.push(`Control: ${controlPath}`);
    lines.push(`Adapter factory: ${factoryPath}`);
    lines.push('');
    lines.push('═══ REQUIREMENT ═══');
    lines.push(`ID: ${requirement.id}`);
    lines.push(`Description: ${requirement.description}`);
    lines.push(`Category: ${requirement.category}`);
    lines.push(`Expected behavior: ${requirement.expectedBehavior}`);
    lines.push(`Rationale: ${requirement.rationale}`);
    lines.push('');
    lines.push('═══ CANONICAL REFERENCE ═══');
    lines.push('Follow this pattern for imports, describe structure, helper functions, and assertions:');
    lines.push('```typescript');
    //lines.push(CANONICAL_TEST);
    lines.push('```');
    lines.push('');
    lines.push('═══ CONSTRAINTS ═══');
    lines.push('- One top-level describe block named after the control class (e.g. Ddb002Control).');
    lines.push('- Build Template (for CFN) or TerraformResource[] (for TF) inline within the test.');
    lines.push('- For CFN tests: call parseCfnTemplate(template) before creating the context. The scanner engine preprocesses templates to resolve intrinsics (Ref, Fn::GetAtt, Fn::Sub, etc.) before adapters see them. Import parseCfnTemplate from the cfn-utils module.');
    lines.push('- Bind context via the adapter factory; call control.run(adapter, context).');
    lines.push(`- expectedBehavior === 'flag' → expect(result).not.toBeNull() plus expect(result!.check_id).toBe('${ruleId}').`);
    lines.push(`- expectedBehavior === 'pass' → expect(result).toBeNull().`);
    lines.push('- Use only relative imports computed from the test file path to the source paths above.');

    return lines.join('\n');
}

export function buildRetryPrompt(originalPrompt: string, errors: string[]): string {
    const lines: string[] = [];
    lines.push(originalPrompt);
    lines.push('');
    lines.push('═══ TYPECHECK FAILED ═══');
    lines.push('The file you wrote has TypeScript errors:');
    lines.push('');
    lines.push(errors.join('\n'));
    lines.push('');
    lines.push('View the file you wrote with fileEditor view, then fix with str_replace. Only fix the errors above.');
    return lines.join('\n');
}
