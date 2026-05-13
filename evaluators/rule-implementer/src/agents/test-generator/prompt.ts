import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { RuleRequirement } from '../../shared/types/requirements.js';
import type { FixtureRegenerationContext } from '../../shared/types/fixtures.js';
import { FixtureFormat } from '../../shared/types/rule-catalog.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PREPROCESSING_DOC = readFileSync(resolve(__dirname, '../preprocessing-behavior.md'), 'utf-8');

export const SYSTEM_PROMPT = `You generate minimal CloudFormation or Terraform test fixtures for individual security rule requirements.

Your job: given a requirement description, produce the smallest valid template snippet that exercises the described scenario.

## Critical Constraints

1. The fixture MUST include at least one resource whose Type matches the rule's appliesTo list. Without this, the rule will never be invoked and validation always returns 'pass' regardless of the rule logic.
2. Include only the resources needed to exercise the requirement — the target resource plus any context resources the rule inspects (e.g., a CloudTrail Trail for a DynamoDB rule that checks trail coverage).
3. Use correct AWS CloudFormation property names. Verify against AWS documentation if uncertain.
4. Keep property values realistic but minimal.

## CloudFormation Format

Output YAML representing the Resources section of a CloudFormation template. Example:

MyTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: my-table
    BillingMode: PAY_PER_REQUEST
MyTrail:
  Type: AWS::CloudTrail::Trail
  Properties:
    IsLogging: true
    S3BucketName: my-bucket

## Terraform Format

Output a JSON array of TerraformResource objects:
[{"type": "aws_dynamodb_table", "name": "my_table", "address": "aws_dynamodb_table.my_table", "values": {...}}]

## Expected Behavior

- If expectedBehavior is 'flag': the fixture must represent a NON-COMPLIANT state — the rule should produce a finding.
- If expectedBehavior is 'pass': the fixture must represent a COMPLIANT state — the rule should return null.

## Fixture Realism

When referencing a resource's ARN, use !GetAtt Resource.Arn (the standard CloudFormation idiom) rather than constructing the ARN manually with Fn::Sub. When referencing a resource itself, use !Ref. Use the most natural and idiomatic CloudFormation patterns for each scenario.

## Template Preprocessing

${PREPROCESSING_DOC}`;

export function buildUserPrompt(requirement: RuleRequirement, applicableResourceTypes: string[], fixtureFormat: FixtureFormat, regenerationContext?: FixtureRegenerationContext): string {
    const lines: string[] = [];

    lines.push(`Format: ${fixtureFormat === 'cfn' ? 'CloudFormation (YAML)' : 'Terraform (JSON)'}`);
    lines.push(`Rule applies to resource types: ${applicableResourceTypes.join(', ')}`);
    lines.push('');
    lines.push('═══ REQUIREMENT ═══');
    lines.push(`ID: ${requirement.id}`);
    lines.push(`Description: ${requirement.description}`);
    lines.push(`Category: ${requirement.category}`);
    lines.push(`Expected behavior: ${requirement.expectedBehavior}`);
    lines.push(`Rationale: ${requirement.rationale}`);

    if (regenerationContext) {
        lines.push('');
        lines.push('═══ PREVIOUS ATTEMPT FAILED ═══');
        lines.push('');
        lines.push('The previous fixture did not work. Here is what went wrong:');
        lines.push('');
        lines.push(`Previous fixture:`);
        lines.push('```');
        lines.push(regenerationContext.previousFixture);
        lines.push('```');
        lines.push('');
        lines.push(`Rule was invoked: ${regenerationContext.failureDiagnostics.ruleWasInvoked}`);
        lines.push(`Resource types in fixture: ${regenerationContext.failureDiagnostics.templateResourceTypes.join(', ')}`);
        lines.push(`Matched resource types: ${regenerationContext.failureDiagnostics.matchedResourceTypes.join(', ')}`);
        lines.push(`Suggested cause: ${regenerationContext.failureDiagnostics.suggestedCause}`);

        if (regenerationContext.failureDiagnostics.parseError) {
            lines.push(`Parse error: ${regenerationContext.failureDiagnostics.parseError}`);
        }
        if (regenerationContext.failureDiagnostics.evaluationError) {
            lines.push(`Evaluation error: ${regenerationContext.failureDiagnostics.evaluationError}`);
        }

        lines.push('');
        lines.push('Generate a corrected fixture that addresses the issue above.');
    }

    lines.push('');
    lines.push('Generate the minimal fixture snippet for this requirement.');

    return lines.join('\n');
}
