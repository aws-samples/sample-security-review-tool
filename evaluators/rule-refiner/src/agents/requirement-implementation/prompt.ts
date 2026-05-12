import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { RuleRequirement } from '../../types/requirements.js';
import type { GeneratedFixture } from '../fixture-generator/types.js';
import type { ValidationDiagnostics, ValidationResult } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PREPROCESSING_DOC = readFileSync(resolve(__dirname, '../../reference-docs/preprocessing-behavior.md'), 'utf-8');
const BASE_RULE_DOC = readFileSync(resolve(__dirname, '../../reference-docs/base-rule-api.md'), 'utf-8');
const SCANNER_DOC = readFileSync(resolve(__dirname, '../../reference-docs/scanner-engine.md'), 'utf-8');

export const SYSTEM_PROMPT = `You implement security scanning rules. You receive requirements (with test fixtures) and must write rule logic that satisfies all of them.

## Guidelines

- Make minimal changes — add or modify only the logic needed for the requirements.
- Preserve all imports, class structure, exports, and unrelated logic.
- Do not refactor, rename, or restructure the file.
- Always read the current file before writing.
- Verify property names against AWS documentation if uncertain.

If the expected behavior is 'flag', ensure the rule DOES produce a finding for the described case.
If the expected behavior is 'pass', ensure the rule does NOT produce a finding for the described case.

## How Rules Are Invoked

${SCANNER_DOC}

## BaseRule API

${BASE_RULE_DOC}

## Template Preprocessing

${PREPROCESSING_DOC}

## Regression Handling

If regression feedback is provided, it means a previously-passing requirement now fails after your last edit. You must fix the regression while still satisfying the current requirement. Study both the failing test case and the current requirement to find an implementation that satisfies both.`;

export function buildUserPrompt(ruleBody: string, sourceLocation: string, requirement: RuleRequirement, fixture: GeneratedFixture, regressions: ValidationResult[], allRequirementsSoFar: RuleRequirement[], fixturesForRegressions: Map<string, GeneratedFixture>, resolvedTemplate?: string): string {
    const lines: string[] = [];

    lines.push(`Rule source file: ${sourceLocation}`);
    lines.push('');
    lines.push('<current-rule-source>');
    lines.push(ruleBody);
    lines.push('</current-rule-source>');
    lines.push('');
    lines.push('═══ REQUIREMENT TO IMPLEMENT ═══');
    lines.push('');
    lines.push(`ID: ${requirement.id}`);
    lines.push(`Description: ${requirement.description}`);
    lines.push(`Category: ${requirement.category}`);
    lines.push(`Expected behavior: ${requirement.expectedBehavior}`);
    lines.push(`Rationale: ${requirement.rationale}`);
    lines.push('');
    lines.push('Raw fixture (the template before preprocessing):');
    lines.push('```yaml');
    lines.push(fixture.templateSnippet);
    lines.push('```');

    if (resolvedTemplate) {
        lines.push('');
        lines.push('Resolved fixture (what the rule will actually see after parseCfnTemplate runs):');
        lines.push('```json');
        lines.push(resolvedTemplate);
        lines.push('```');
    }

    if (regressions.length > 0) {
        lines.push('');
        lines.push('═══ REGRESSIONS TO FIX ═══');
        lines.push('');
        lines.push('The following previously-passing requirements now FAIL. You must fix these while also satisfying the above requirement:');
        lines.push('');
        for (const regression of regressions) {
            const req = allRequirementsSoFar.find(r => r.id === regression.requirementId);
            if (!req) continue;

            lines.push(`- ${req.id}: ${req.description}`);
            lines.push(`  Expected: ${regression.expected}, Got: ${regression.actual}`);

            const regFixture = fixturesForRegressions.get(req.id);
            if (regFixture) {
                lines.push(`  Fixture:`);
                lines.push('  ```');
                lines.push(regFixture.templateSnippet.split('\n').map(l => '  ' + l).join('\n'));
                lines.push('  ```');
            }

            if (regression.diagnostics.resolvedTemplate) {
                lines.push(`  Resolved fixture:`);
                lines.push('  ```json');
                lines.push(regression.diagnostics.resolvedTemplate.split('\n').map(l => '  ' + l).join('\n'));
                lines.push('  ```');
            }
        }
    }

    lines.push('');
    lines.push('Modify the rule source to satisfy the requirement (and fix any regressions). Write the complete updated file using write_file.');

    return lines.join('\n');
}

export function formatDiagnostics(diagnostics: ValidationDiagnostics): string {
    const lines: string[] = [];

    lines.push('═══ FAILURE DIAGNOSTICS ═══');
    lines.push(`Rule invoked: ${diagnostics.ruleWasInvoked ? 'YES' : 'NO'}`);
    lines.push(`Matched resource types: [${diagnostics.matchedResourceTypes.join(', ')}]`);
    lines.push(`Template resource types: [${diagnostics.templateResourceTypes.join(', ')}]`);
    lines.push(`Suggested cause: ${diagnostics.suggestedCause.toUpperCase()}`);

    if (diagnostics.parseError) {
        lines.push(`Parse error: ${diagnostics.parseError}`);
    }
    if (diagnostics.evaluationError) {
        lines.push(`Evaluation error: ${diagnostics.evaluationError}`);
    }

    switch (diagnostics.suggestedCause) {
        case 'rule_logic':
            lines.push('→ The rule was invoked on the correct resource type but did not produce the expected result. Review the detection logic for this scenario.');
            break;
        case 'value_mismatch':
            lines.push('→ The rule tried to access a property that does not exist or has an unexpected type. Check the resolved template below to see what values are actually present.');
            break;
        case 'cross_resource_not_found':
            lines.push('→ The rule tried to look up a related resource that is not in the template. Check your cross-resource lookup logic against the resolved template.');
            break;
        case 'intrinsic_not_handled':
            lines.push('→ The rule encountered an unresolved intrinsic (Fn::If or Fn::ImportValue) but did not handle it. These remain as objects after preprocessing.');
            break;
        case 'fixture_missing_resource':
            lines.push('→ The fixture does not contain a resource type the rule evaluates. This is a FIXTURE problem — escalation will regenerate the fixture.');
            break;
        case 'fixture_parse_error':
            lines.push('→ The fixture template could not be parsed. This is a FIXTURE problem — escalation will regenerate the fixture.');
            break;
        case 'fixture_wrong_structure':
            lines.push('→ The fixture structure is invalid. This is a FIXTURE problem — escalation will regenerate the fixture.');
            break;
    }

    if (diagnostics.resolvedTemplate) {
        lines.push('');
        lines.push('Resolved template (what the rule actually received):');
        lines.push('```json');
        lines.push(diagnostics.resolvedTemplate);
        lines.push('```');
    }

    return lines.join('\n');
}
