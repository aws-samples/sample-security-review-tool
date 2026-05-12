import type { RuleRequirement } from '../../types/requirements.js';
import type { GeneratedFixture } from '../fixture-generator/types.js';

export const SYSTEM_PROMPT = `You generate Vitest test files for security scanning rules.

You receive a list of requirements with their validated fixtures (templates that have been confirmed to produce the expected rule behavior). Your job is to produce a complete, runnable test file.

## Test File Pattern

Follow this exact pattern:

\`\`\`typescript
import { describe, it, expect } from 'vitest';
import RuleClass from '../../relative/path/to/rule.js';
import type { Template } from 'cloudform-types';

describe('RuleClass', () => {
  const rule = new RuleClass();
  const stackName = 'test-stack';

  describe('appliesTo', () => {
    it('should apply to AWS::Service::Resource', () => {
      expect(rule.appliesTo('AWS::Service::Resource')).toBe(true);
    });

    it('should not apply to unrelated types', () => {
      expect(rule.appliesTo('AWS::Other::Resource')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    // Group by category: flag cases first, then pass cases

    describe('should flag', () => {
      it('description from requirement', () => {
        const template: Template = { Resources: { /* fixture resources */ } };
        const resource = template.Resources!['LogicalId'];
        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
        expect(result!.check_id).toBe('RULE-ID');
      });
    });

    describe('should pass', () => {
      it('description from requirement', () => {
        const template: Template = { Resources: { /* fixture resources */ } };
        const resource = template.Resources!['LogicalId'];
        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });
    });
  });
});
\`\`\`

## Rules

1. Use the exact fixture template YAML from each requirement, converted to a TypeScript object.
2. The fixture YAML has already been validated — the test is guaranteed to pass if you transcribe it correctly.
3. Import the rule using its default export path.
4. Group tests by expected behavior: "should flag" and "should pass".
5. Each test's description should come from the requirement description.
6. The template must be preprocessed (use parseCfnTemplate) — import and call it in the test.
7. Find the target resource by looking for the first resource whose Type matches the rule's applicableResourceTypes.`;

export function buildUserPrompt(ruleId: string, ruleClassName: string, ruleImportPath: string, applicableResourceTypes: string[], requirements: RuleRequirement[], fixtures: Map<string, GeneratedFixture>): string {
    const lines: string[] = [];

    lines.push(`Rule ID: ${ruleId}`);
    lines.push(`Rule class name: ${ruleClassName}`);
    lines.push(`Import path: ${ruleImportPath}`);
    lines.push(`Applicable resource types: ${applicableResourceTypes.join(', ')}`);
    lines.push('');
    lines.push('═══ REQUIREMENTS AND FIXTURES ═══');

    for (const req of requirements) {
        const fixture = fixtures.get(req.id);
        if (!fixture) continue;

        lines.push('');
        lines.push(`--- ${req.id} (${req.expectedBehavior}) ---`);
        lines.push(`Description: ${req.description}`);
        lines.push(`Category: ${req.category}`);
        lines.push('Fixture:');
        lines.push('```yaml');
        lines.push(fixture.templateSnippet);
        lines.push('```');
    }

    lines.push('');
    lines.push('Generate the complete Vitest test file.');

    return lines.join('\n');
}
