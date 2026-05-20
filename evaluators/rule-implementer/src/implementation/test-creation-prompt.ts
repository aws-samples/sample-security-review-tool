import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';

export class TestCreationPromptBuilder {
    constructor(private readonly context: RuleContext) { }

    public buildSystemPrompt(): string {
        return `You are responsible for implementing the Red Phase (writing failing tests) of a Test-Driven Development workflow for a SecurityControl class. Your responsibilities include:
         - Creating unit tests in Vitest.
         - Ensuring unit tests are only written for the specific requirement.
         - Ensuring unit tests are created for both CloudFormation and Terraform.
         - Ensuring the unit test file is self-contained and executable with Vitest.
         - If the scenario has no meaningful representation in a given format (e.g., a condition that only one format's data model can express), write a single skipped test with a comment explaining why, rather than inventing a fixture that doesn't represent the scenario.`;
    }

    public buildUserPrompt(spec: RequirementsSpec, requirement: RuleRequirement): string {
        const cfnTestFilePath = path.join(this.context.testsFolderPath, `${requirement.id}.cfn.test.ts`);
        const tfTestFilePath = path.join(this.context.testsFolderPath, `${requirement.id}.tf.test.ts`);

        const relativeToControl = path.relative(path.dirname(cfnTestFilePath), this.context.ruleControlFilePath).replace(/\.ts$/, '.js');
        const relativeToAdapter = path.relative(path.dirname(cfnTestFilePath), this.context.ruleAdapterBaseFilePath).replace(/\.ts$/, '.js');
        const typesFilePath = path.join(this.context.srtRootFolderPath, 'src/assess/scanning/security-matrix/controls/types.ts');
        const relativeToTypes = path.relative(path.dirname(cfnTestFilePath), typesFilePath).replace(/\.ts$/, '.js');

        return `Create unit tests for the following rule requirement:
            Rule ID: ${spec.ruleId}
            Rule Description: ${spec.description}
            Rule's CloudFormation Resources: ${spec.cfnResources.join(', ')}
            Rule's Terraform Resources: ${spec.tfResources.join(', ')}
            Scenario: ${requirement.description}
            Expected Behavior: ${requirement.expectedBehavior}
            Rationale: ${requirement.rationale}

            Import the control from: ${relativeToControl}
            Import the adapter from: ${relativeToAdapter}
            Import types from: ${relativeToTypes}

            Save the CloudFormation unit test file to: ${cfnTestFilePath}
            Save the Terraform unit test file to: ${tfTestFilePath}

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
        `;
    }
}
