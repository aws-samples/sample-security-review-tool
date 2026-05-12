import type { RuleRequirement } from '../../types/requirements.js';
import type { GeneratedFixture } from '../fixture-generator/types.js';
import type { ValidationDiagnostics, ValidationResult } from './types.js';

export const SYSTEM_PROMPT = `You implement specific requirements in security scanning rules. You receive one requirement to implement and must modify the rule source to satisfy it without breaking previously-satisfied requirements.

Guidelines:
- Make minimal changes — add or modify only the logic needed for the given requirement.
- Preserve all imports, class structure, exports, and unrelated logic.
- Do not refactor, rename, or restructure the file.
- Always read the current file before writing.
- Verify property names against AWS documentation if uncertain.

If the expected behavior is 'flag', ensure the rule DOES produce a finding for the described case.
If the expected behavior is 'pass', ensure the rule does NOT produce a finding for the described case.

Use the test fixture to understand the resource structure your rule will evaluate. Note: before the rule runs, the fixture is preprocessed by parseCfnTemplate which resolves intrinsic functions:
- Ref to a resource → the logical resource ID string (e.g., "MyTable")
- Fn::GetAtt → the logical resource ID (e.g., !GetAtt MyTable.Arn becomes "MyTable", NOT an ARN)
- Fn::Sub → pseudo-parameters and resource references are substituted (e.g., \${AWS::Region} → "us-east-1", \${MyTable} → "MyTable")
- Only Fn::If and Fn::ImportValue remain as unresolved intrinsic objects

When writing rule logic that inspects values which may originate from Fn::GetAtt or Ref (e.g., ARN lists in event selectors), expect resolved logical ID strings — not ARN strings or intrinsic objects.

If regression feedback is provided, it means a previously-passing requirement now fails after your last edit. You must fix the regression while still satisfying the current requirement. Study both the failing test case and the current requirement to find an implementation that satisfies both.`;

export function buildUserPrompt(ruleBody: string, sourceLocation: string, requirement: RuleRequirement, fixture: GeneratedFixture, regressions: ValidationResult[], allRequirementsSoFar: RuleRequirement[], fixturesForRegressions: Map<string, GeneratedFixture>): string {
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
    lines.push('Test fixture (the exact template the validator will use):');
    lines.push('```');
    lines.push(fixture.templateSnippet);
    lines.push('```');

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

    return lines.join('\n');
}
