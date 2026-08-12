import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import { PREPROCESSING_BEHAVIOR } from './preprocessing-behavior.js';
import { TERRAFORM_PLAN_BEHAVIOR } from './terraform-plan-behavior.js';

export class TestCreationPromptBuilder {
    constructor(private readonly context: RuleContext) { }

    public buildSystemPrompt(): string {
        return `You are responsible for implementing the Red Phase (writing failing tests) of a Test-Driven Development workflow for a SecurityControl class. Your responsibilities include:
         - Creating unit tests in Vitest.
         - Ensuring unit tests cover the specific requirement, and nothing beyond what is needed to prove it holds.
         - Ensuring unit tests are created for both CloudFormation and Terraform.
         - Ensuring the unit test file is self-contained and executable with Vitest.
         - If the scenario has no meaningful representation in a given format (e.g., a condition that only one format's data model can express), write a single skipped test with a comment explaining why, rather than inventing a fixture that doesn't represent the scenario.

## Every Test File Must Discriminate

A test file whose assertions all expect the same outcome cannot fail for the right reason. If every test expects the control to return null, a control that never returns a finding passes them all; if every test expects a finding, a control that flags everything passes them all. Such a file proves nothing about the requirement.

Each file must therefore contain at least one test that asserts the OPPOSITE outcome, chosen as the nearest input that flips the verdict — change only what the requirement turns on, and keep everything else identical.

For a requirement that passes because a value meets some standard, the opposite case is a value that fails to meet it while remaining present. Not an absent value: absence is usually a different requirement, and a test that removes the value entirely does not prove the standard is enforced.

Name the opposite test so its purpose is clear, and comment which requirement owns the primary behavior.

Write the tests from the requirement, not from the implementation. The source files below are provided so your fixtures use real property names and your imports resolve — not as a description of correct behavior. Where the current implementation appears to contradict the requirement, write the test the requirement demands and let it fail: the implementation phase that follows will make it pass. A test written to agree with existing code cannot detect that the code is wrong.

## CloudFormation Template Preprocessing

${PREPROCESSING_BEHAVIOR}

## Terraform Plan Behavior

${TERRAFORM_PLAN_BEHAVIOR}`;
    }

    public buildUserPrompt(spec: RequirementsSpec, requirement: RuleRequirement, problems: string[] = []): string {
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
        ${this.rejectionNotice(problems)}`;
    }

    private rejectionNotice(problems: string[]): string {
        if (problems.length === 0) return '';

        return `
## Your Previous Attempt Was Rejected

${problems.map(problem => `- ${problem}`).join('\n')}

Rewrite both files. Every input a test asserts on has to be one the requirement actually decides, and each file needs at least one test asserting the opposite outcome, using the nearest input that flips it. A file asserting only one outcome is satisfied by a control that hardcodes that outcome, which is why it was rejected.

If you believe the scenario genuinely cannot be represented in one of the two formats, skip every test in that file and say why in a comment. Do not leave a live test alongside a skipped one to get past this.
`;
    }
}
