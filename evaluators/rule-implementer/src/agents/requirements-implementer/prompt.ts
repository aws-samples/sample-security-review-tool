import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { RuleRequirement } from '../../shared/types/requirements.js';
import type { RegressionInfo } from '../../shared/types/implementation.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PREPROCESSING_DOC = readFileSync(resolve(__dirname, '../preprocessing-behavior.md'), 'utf-8');
const BASE_RULE_DOC = readFileSync(resolve(__dirname, 'base-rule-api.md'), 'utf-8');
const SCANNER_DOC = readFileSync(resolve(__dirname, 'scanner-engine.md'), 'utf-8');

export const SYSTEM_PROMPT = `You implement security scanning rules. You receive a failing test and must write rule logic that makes it pass.

## Guidelines

- Make minimal changes — add or modify only the logic needed for the requirement.
- Preserve all imports, class structure, exports, and unrelated logic.
- Do not refactor, rename, or restructure the file.
- Verify property names against AWS documentation if uncertain.

If the expected behavior is 'flag', ensure the rule DOES produce a finding for the described case.
If the expected behavior is 'pass', ensure the rule does NOT produce a finding for the described case.

## Code Structure (MANDATORY)

Follow Robert C. Martin's Clean Code principles. Your rule implementation MUST be structured as small, named private methods:

- \`evaluateResource\` must read like a high-level summary. It should delegate to well-named helper methods.
- Each private method does ONE thing at ONE level of abstraction.
- No deeply nested loops or conditions. If you find yourself nesting more than 2 levels deep, extract a named method.
- Method names must reveal intent (e.g., \`isTrailCoveringTable\`, \`hasValidEventSelector\`, \`isExplicitlyExcluded\`).

Example of CORRECT structure (from S3-001):

\`\`\`typescript
public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
  if (this.isLogDestinationBucket(template, resource)) return null;
  if (!this.hasLoggingConfiguration(resource)) return this.createResult(...);
  if (this.isSelfLogging(template, resource)) return this.createResult(...);
  return null;
}

private isLogDestinationBucket(template: Template, resource: Resource): boolean { ... }
private hasLoggingConfiguration(resource: Resource): boolean { ... }
private isSelfLogging(template: Template, resource: Resource): boolean { ... }
\`\`\`

Example of WRONG structure (do NOT do this):

\`\`\`typescript
public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
  const resources = template.Resources || {};
  const trails = Object.entries(resources).filter(...);
  if (trails.length === 0) return this.createResult(...);
  const covered = trails.some(([_, trailRaw]) => {
    const props = trail.Properties || {};
    const eventSelectors = Array.isArray(props.EventSelectors) ? props.EventSelectors : [];
    for (const selector of eventSelectors) {
      // 150 more lines of nested loops...
    }
  });
  // Everything in one giant function
}
\`\`\`

## Fix Guidance Style (MANDATORY)

The \`fix\` string in \`createResult\` must describe REQUIRED OUTCOMES, not specific implementation details. Fix guidance becomes stale when IaC APIs change, so never embed exact property paths or values.

CORRECT fix guidance style:
- Describe what security outcome must be achieved
- State constraints (what must NOT be done)
- Mention which resources need to exist and what they must satisfy
- Let the fix agent figure out the specific property names

Example of CORRECT fix guidance (from S3-001):
"Enable S3 access logging by configuring the source bucket to send access logs to a separate, dedicated logging bucket. First, check whether the template already contains a dedicated logging bucket. If one exists, reuse it. If not, create a new S3 bucket to serve as the log destination. Do NOT log to the same bucket (self-logging)."

Example of WRONG fix guidance (too implementation-specific):
"Set BucketEncryption.ServerSideEncryptionConfiguration[0].ServerSideEncryptionByDefault.SSEAlgorithm to 'aws:kms' and KMSMasterKeyID to !GetAtt MyKey.Arn"

## How Rules Are Invoked

${SCANNER_DOC}

## BaseRule API

${BASE_RULE_DOC}

## Template Preprocessing

${PREPROCESSING_DOC}

## Regression Handling

If regression feedback is provided, it means a previously-passing requirement now fails after your last edit. You must fix the regression while still satisfying the current requirement. Study both the failing test case and the current requirement to find an implementation that satisfies both.`;

export function buildUserPrompt(ruleBody: string, sourceLocation: string, requirement: RuleRequirement, testFile: { path: string; content: string }, failureOutput: string, regressions: RegressionInfo[]): string {
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
    lines.push('═══ TEST FILE (the oracle — make this pass) ═══');
    lines.push(`Path: ${testFile.path}`);
    lines.push('```typescript');
    lines.push(testFile.content);
    lines.push('```');
    lines.push('');
    lines.push('═══ TEST FAILURE OUTPUT ═══');
    lines.push('```');
    lines.push(failureOutput);
    lines.push('```');

    if (regressions.length > 0) {
        lines.push('');
        lines.push('═══ REGRESSIONS TO FIX ═══');
        lines.push('');
        lines.push('The following previously-passing tests now FAIL. You must fix these while also satisfying the above requirement:');
        lines.push('');
        for (const regression of regressions) {
            lines.push(`--- ${regression.requirementId} (${regression.testPath}) ---`);
            lines.push('Test content:');
            lines.push('```typescript');
            lines.push(regression.testContent);
            lines.push('```');
            lines.push('Failure output:');
            lines.push('```');
            lines.push(regression.failureOutput);
            lines.push('```');
            lines.push('');
        }
    }

    lines.push('');
    lines.push('Modify the rule source to satisfy the requirement (and fix any regressions).');

    return lines.join('\n');
}
