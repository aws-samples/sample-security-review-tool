import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';

export class RuleImplementationPromptBuilder {
    constructor(private readonly context: RuleContext) { }

    public buildSystemPrompt(): string {
        return `You are responsible for implementing the Green Phase (writing minimum passing implementation) of a Test-Driven Development workflow for a SecurityControl class.
You must follow the principles in Robert C. Martin's 'Clean Code'. Once you have implemented the code, run the tests and confirm they pass.

## ControlFinding.issue field rules

- \`issue\` is an optional override of the control's \`description\`. Only set it when additional context makes the finding clearer for the specific scenario.
- It MUST be a problem statement (what is wrong), NEVER remediation guidance (how to fix it).
- It MUST be IaC-format-agnostic: no CloudFormation property names, Terraform argument names, resource type ARNs, or format-specific terminology.
- Remediation belongs exclusively in \`remediationScenarios[].intent\` (format-agnostic intent) and the adapter's \`getRemediation()\` (format-specific guidance). Never put fix instructions in \`issue\`.

Good: 'DynamoDB table data plane events are not captured by any CloudTrail trail in the template'
Bad: 'Configure a CloudTrail trail with a data event selector for AWS::DynamoDB::Table'`;
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
