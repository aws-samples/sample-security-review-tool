import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import { PREPROCESSING_BEHAVIOR } from './preprocessing-behavior.js';
import { TERRAFORM_SOURCE_BEHAVIOR } from './terraform-source-behavior.js';

export class RuleImplementationPromptBuilder {
    constructor(private readonly context: RuleContext) { }

    public buildSystemPrompt(): string {
        return `You are responsible for implementing the Green Phase (writing minimum passing implementation) of a Test-Driven Development workflow for a SecurityControl class.
You must follow the principles in Robert C. Martin's 'Clean Code'. Once you have implemented the code, run the tests and confirm they pass.

## ControlFinding.issue field rules

- \`issue\` is an optional override of the control's \`description\`. Only set it when additional context makes the finding clearer for the specific scenario.
- It MUST be a problem statement (what is wrong), NEVER remediation guidance (how to fix it).
- It MUST be IaC-format-agnostic: no CloudFormation property names, Terraform argument names, resource type ARNs, or format-specific terminology.
- Remediation belongs exclusively in \`remediationScenarios[].intent\` (format-agnostic intent). Never put fix instructions in \`issue\`.
- A corresponding \`remediationScenario\` with a clear, format-agnostic \`intent\` MUST be provided for every unique \`issue\` value to guide users towards resolution.

Good: 'DynamoDB table data plane events are not captured by any CloudTrail trail in the template'
Bad: 'Configure a CloudTrail trail with a data event selector for AWS::DynamoDB::Table'

## CloudFormation Template Preprocessing

${PREPROCESSING_BEHAVIOR}

## Terraform Source Behavior

${TERRAFORM_SOURCE_BEHAVIOR}

## Conflict Detection & Structured Output

After implementing the requirement, run all tests. Your final structured output must be one of:

- **Success**: All tests pass → return \`{ "status": "success" }\`
- **Conflict**: The current requirement's tests cannot pass without breaking a previously-passing requirement's tests → return a conflict report

A conflict report:
\`\`\`json
{
  "status": "conflict",
  "currentRequirementId": "REQ-05",
  "conflictingRequirementId": "REQ-03",
  "explanation": "Both requirements target the same field but demand opposite outcomes for indistinguishable inputs in Terraform's data model"
}
\`\`\`

Rules:
- Make at least 3 genuine attempts to satisfy both requirements before reporting a conflict.
- The conflicting requirement ID is in the failing test filename (e.g., "REQ-03.cfn.test.ts" → "REQ-03").
- Only report a conflict when you are confident the requirements are fundamentally irreconcilable in the current data model.`;
    }

    public buildUserPrompt(spec: RequirementsSpec, requirement: RuleRequirement): string {
        const cfnTestFilePath = path.join(this.context.testsFolderPath, `${requirement.id}.cfn.test.ts`);
        const tfTestFilePath = path.join(this.context.testsFolderPath, `${requirement.id}.tf.test.ts`);

        return `Create a minimum implementation for the following rule requirement, ensuring that the unit tests pass:
            Rule ID: ${spec.ruleId}
            Rule Description: ${spec.description}
            Rule's CloudFormation Resources: ${spec.cfnResources.join(', ')}
            Rule's Terraform Resources: ${spec.tfResources.join(', ')}
            Requirement Description: ${requirement.description}
            Expected Behavior: ${requirement.expectedBehavior}
            Rationale: ${requirement.rationale}

            <source-files>
                <source-file path="${this.context.ruleControlFilePath}">
                ${fs.readFileSync(this.context.ruleControlFilePath, 'utf8')}
                </source-file>
                <source-file path="${this.context.ruleAdapterBaseFilePath}">
                ${fs.readFileSync(this.context.ruleAdapterBaseFilePath, 'utf8')}
                </source-file>
                <source-file path="${this.context.ruleAdapterCfnFilePath}">
                ${fs.readFileSync(this.context.ruleAdapterCfnFilePath, 'utf8')}
                </source-file>
                <source-file path="${this.context.ruleAdapterTfFilePath}">
                ${fs.readFileSync(this.context.ruleAdapterTfFilePath, 'utf8')}
                </source-file>
                <source-file path="${this.context.securityControlBaseFilePath}">
                ${fs.readFileSync(this.context.securityControlBaseFilePath, 'utf8')}
                </source-file>
                <source-file path="${this.context.securityControlTypesFilePath}">
                ${fs.readFileSync(this.context.securityControlTypesFilePath, 'utf8')}
                </source-file>
            </source-files>

            <unit-tests>
                <cfn-unit-tests path="${cfnTestFilePath}">
                ${fs.readFileSync(cfnTestFilePath, 'utf8')}
                </unit-tests>
                <tf-unit-tests path="${tfTestFilePath}">
                ${fs.readFileSync(tfTestFilePath, 'utf8')}
                </unit-tests>
            </unit-tests>`;
    }
}
