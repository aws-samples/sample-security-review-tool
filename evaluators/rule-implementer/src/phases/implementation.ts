import * as fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { RequirementImplementationAgent } from '../agents/requirements-implementer/agent.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import type { RegressionInfo } from '../shared/types/implementation.js';
import { RuleContext } from '../shared/rule-context.js';
import { Agent, BedrockModel, tool } from '@strands-agents/sdk';
import z from 'zod';
import path from 'node:path';

const MAX_RETRIES = 3;

export interface ImplementationResult {
    totalRequirements: number;
    passed: number;
    failed: string[];
}

interface VitestResult {
    allPassed: boolean;
    output: string;
}

export class ImplementationWorkflow {
    constructor(private readonly context: RuleContext) { }

    public async implement(spec: RequirementsSpec): Promise<void> {
        for (const requirement of spec.requirements.filter(r => !r.implemented || !r.tested)) {
            if (requirement.implemented && requirement.tested) continue;

            await this.createUnitTests(spec, requirement, 'cfn');
            //await this.createUnitTests(spec, requirement, 'tf');

            await this.implementRequirement(spec, requirement);

            // Update the requirement status in the spec file after implementation attempt
            // const requirementsFile = this.context.requirementsFilePath;
            // if (fs.existsSync(requirementsFile)) {
            //     const fileContent = fs.readFileSync(requirementsFile, 'utf8');
            //     const specData = JSON.parse(fileContent) as RequirementsSpec;
            //     const reqToUpdate = specData.requirements.find(r => r.id === requirement.id);
            //     if (reqToUpdate) {
            //         reqToUpdate.implemented = true;
            //         reqToUpdate.tested = true;
            //         fs.writeFileSync(requirementsFile, JSON.stringify(specData, null, 2));
            //     }
            // }
        }
    }

    private async createUnitTests(spec: RequirementsSpec, requirement: RuleRequirement, format: 'cfn' | 'tf'): Promise<void> {
        const cfnTestFilePath = path.join(this.context.testsFolderPath, `${requirement.id}.cfn.test.ts`);
        const tfTestFilePath = path.join(this.context.testsFolderPath, `${requirement.id}.tf.test.ts`);

        if (fs.existsSync(cfnTestFilePath)) return;

        console.log(`\n==== Creating unit tests for ${spec.ruleId} ${requirement.id} ====\n`);

        const relativeToControl = path.relative(path.dirname(cfnTestFilePath), this.context.ruleControlFilePath).replace(/\.ts$/, '.js');
        const relativeToAdapter = path.relative(path.dirname(cfnTestFilePath), this.context.ruleAdapterBaseFilePath).replace(/\.ts$/, '.js');
        const typesFilePath = path.join(this.context.srtRootFolderPath, 'src/assess/scanning/security-matrix/controls/types.ts');
        const relativeToTypes = path.relative(path.dirname(cfnTestFilePath), typesFilePath).replace(/\.ts$/, '.js');

        const writeFileTool = tool({
            name: 'write_file',
            description: 'Write the complete file content.',
            inputSchema: z.object({
                filePath: z.string().describe('The absolute path of the file to write'),
                content: z.string().describe('The complete file content'),
            }),
            callback: async ({ filePath, content }) => {                
                fs.mkdirSync(path.dirname(filePath), { recursive: true });
                fs.writeFileSync(filePath, content);
                return 'Written successfully.';
            },
        });

        const vitestTool = tool({
            name: 'run_vitest',
            description: 'Run Vitest against the test file to check if tests pass or fail. Returns the test output including pass/fail status and error messages.',
            inputSchema: z.object({
                filePath: z.string().describe('The absolute path of the test file to run with Vitest'),
            }),
            callback: async ({ filePath }) => {
                const result = spawnSync('npx', ['vitest', 'run', '--reporter=verbose', filePath], { cwd: this.context.srtRootFolderPath, encoding: 'utf8', timeout: 60_000 });
                const output = ((result.stdout ?? '') + (result.stderr ?? ''));
                return { passed: result.status === 0, output };
            },
        });

        const systemPrompt = `You are responsible for implementing the Red Phase (writing failing tests) of a Test-Driven Development workflow for a SecurityControl class. Your responsibilities include:
         - Creating unit tests in Vitest.
         - Ensuring unit tests are only written for the specific requirement.
         - Ensuring unit tests are created for both CloudFormation and Terraform.
         - Ensuring the unit test file is self-contained and executable with Vitest.
         - If the scenario has no meaningful representation in a given format (e.g., a condition that only one format's data model can express), write a single skipped test with a comment explaining why, rather than inventing a fixture that doesn't represent the scenario.`;

        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
            systemPrompt: systemPrompt,
            tools: [writeFileTool, vitestTool]
        });

        const userPrompt = `Create unit tests for the following rule requirement:
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

        await agent.invoke(userPrompt);

        //fs.writeFileSync(`messages-${Date.now()}.json`, JSON.stringify(agent.messages, null, 2));
    }

    private async implementRequirement(spec: RequirementsSpec, requirement: RuleRequirement): Promise<void> {
        console.log(`\n==== Implementing ${spec.ruleId} ${requirement.id} ====\n`);

        const cfnTestFilePath = path.join(this.context.testsFolderPath, `${requirement.id}.cfn.test.ts`);
        const tfTestFilePath = path.join(this.context.testsFolderPath, `${requirement.id}.tf.test.ts`);

        const writeFileTool = tool({
            name: 'write_file',
            description: 'Write the complete file content.',
            inputSchema: z.object({
                filePath: z.string().describe('The absolute path of the file to write'),
                content: z.string().describe('The complete file content'),
            }),
            callback: async ({ filePath, content }) => {
                fs.writeFileSync(filePath, content);
                return 'Written successfully.';
            },
        });

        const vitestTool = tool({
            name: 'run_vitest',
            description: 'Run unit tests. Returns the test output including pass/fail status and error messages.',
            callback: async () => {
                const result = spawnSync('npx', ['vitest', 'run', '--reporter=verbose', this.context.testsFolderPath], { cwd: this.context.srtRootFolderPath, encoding: 'utf8', timeout: 60_000 });
                const output = ((result.stdout ?? '') + (result.stderr ?? ''));
                return { passed: result.status === 0, output };
            }
        });

        const systemPrompt = `You are responsible for implementing the Green Phase (writing minimum passing implementation) of a Test-Driven Development workflow for a SecurityControl class. 
        You must follow the principles in Robert C. Martin's 'Clean Code'. Once you have implemented the code, run the tests and confirm they pass.`;

        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
            systemPrompt: systemPrompt,
            tools: [writeFileTool, vitestTool]
        });

        const userPrompt = `Create a minimum implementation for the following rule requirement, ensuring that the unit tests pass:
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

        await agent.invoke(userPrompt);
    }
}