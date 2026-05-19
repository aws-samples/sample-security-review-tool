import * as fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { RequirementImplementationAgent } from '../agents/requirements-implementer/agent.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import type { RegressionInfo } from '../shared/types/implementation.js';
import { RuleContext } from '../shared/fixture-paths.js';
import { Agent, BedrockModel, tool } from '@strands-agents/sdk';
import { fileEditor } from '@strands-agents/sdk/vended-tools/file-editor';
import z, { file } from 'zod';
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

            await this.implementRequirement(spec, requirement, 'cfn');
            //await this.implementRequirement(spec, requirement, 'tf');

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
        const testFilePath = path.join(this.context.testsFolderPath, `${this.context.safeRuleId}.${format}.test.ts`);

        if (fs.existsSync(testFilePath)) return;

        console.log(`Creating unit tests for ${spec.ruleId} ${requirement.id} (${format})...`);

        const relativeToControl = path.relative(path.dirname(testFilePath), this.context.ruleControlFilePath).replace(/\.ts$/, '.js');
        const adapterFileName = `${format}-${this.context.service}-adapter.ts`;
        const adapterFilePath = path.join(this.context.ruleAdaptersFolderPath, adapterFileName);
        const relativeToAdapter = path.relative(path.dirname(testFilePath), adapterFilePath).replace(/\.ts$/, '.js');
        const typesFilePath = path.join(this.context.srtRootFolderPath, 'src/assess/scanning/security-matrix/controls/types.ts');
        const relativeToTypes = path.relative(path.dirname(testFilePath), typesFilePath).replace(/\.ts$/, '.js');


        const writeFileTool = tool({
            name: 'write_file',
            description: 'Write the complete file content.',
            inputSchema: z.object({
                content: z.string().describe('The complete file content'),
            }),
            callback: async ({ content }) => {
                fs.mkdirSync(this.context.testsFolderPath, { recursive: true });
                fs.writeFileSync(testFilePath, content);
                return 'Written successfully.';
            },
        });

        const vitestTool = tool({
            name: 'run_vitest',
            description: 'Run Vitest against the test file to check if tests pass or fail. Returns the test output including pass/fail status and error messages.',
            inputSchema: z.object({}),
            callback: async () => {
                const result = spawnSync('npx', ['vitest', 'run', '--reporter=verbose', testFilePath], { cwd: this.context.srtRootFolderPath, encoding: 'utf8', timeout: 60_000 });
                const output = ((result.stdout ?? '') + (result.stderr ?? '')).slice(0, 4000);
                return { passed: result.status === 0, output };
            },
        });

        const systemPrompt = `You are responsible for implementing the Red Phase (writing failing tests) of a Test-Driven Development workflow for a SecurityControl class. Your responsibilities include:
         - Creating unit tests in Vitest. 
         - Ensuring unit tests are only written for the specific requirement.
         - Ensuring the unit test file is self-contained and executable with Vitest.`;

        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
            systemPrompt: systemPrompt,
            tools: [writeFileTool, vitestTool]
        });

        const userPrompt = `Create unit tests for the following rule requirement:
            Rule ID: ${spec.ruleId}
            Rule Description: ${spec.description}
            Rule Resource Type: ${format === 'cfn' ? 'CloudFormation' : 'Terraform'}
            Rule Resources: ${format === 'cfn' ? spec.cfnResources.join(', ') : spec.tfResources.join(', ')}
            Scenario: ${requirement.description}
            Expected Behavior: ${requirement.expectedBehavior}
            Rationale: ${requirement.rationale}

            Import the control from: ${relativeToControl}
            Import the adapter from: ${relativeToAdapter}
            Import types from: ${relativeToTypes}

            <source-files>
                <source-file path="${this.context.ruleControlFilePath}">
                ${fs.readFileSync(this.context.ruleControlFilePath, 'utf8')}
                </source-file>
                ${fs.existsSync(this.context.ruleAdaptersFolderPath) ? fs.readdirSync(this.context.ruleAdaptersFolderPath).map(f => {
            const p = path.join(this.context.ruleAdaptersFolderPath, f);
            return `<source-file path="${p}">\n${fs.readFileSync(p, 'utf8')}\n</source-file>`;
        }).join('\n') : ''}
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

    private async implementRequirement(spec: RequirementsSpec, requirement: RuleRequirement, format: 'cfn' | 'tf'): Promise<void> {
        console.log(`Implementing ${spec.ruleId} ${requirement.id} (${format})...`);

        const testFilePath = path.join(this.context.testsFolderPath, `${requirement.id}.${format}.test.ts`);

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
            description: 'Run Vitest against the test file to check if tests pass or fail. Returns the test output including pass/fail status and error messages.',
            callback: async () => {
                const result = spawnSync('npx', ['vitest', 'run', '--reporter=verbose', testFilePath], { cwd: this.context.srtRootFolderPath, encoding: 'utf8', timeout: 60_000 });
                const output = ((result.stdout ?? '') + (result.stderr ?? '')).slice(0, 4000);
                return { passed: result.status === 0, output };
            }
        });

        const systemPrompt = `You are responsible for implementing the Green Phase (writing minimum passing implementation) of a Test-Driven Development workflow for a SecurityControl class. 
        You must follow Robert C. Martin's principle of Clean Code. Once you have implemented the code, run the tests and confirm they pass.`;

        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
            systemPrompt: systemPrompt,
            tools: [writeFileTool, vitestTool]
        });

        const userPrompt = `Create a minimum implementation for the following rule requirement, ensuring that the unit tests pass:
            Rule ID: ${spec.ruleId}
            Rule Description: ${spec.description}
            Rule Resource Type: ${format === 'cfn' ? 'CloudFormation' : 'Terraform'}
            Rule Resources: ${format === 'cfn' ? spec.cfnResources.join(', ') : spec.tfResources.join(', ')}
            Requirement Description: ${requirement.description}
            Expected Behavior: ${requirement.expectedBehavior}
            Rationale: ${requirement.rationale}
            
            <source-files>
                <source-file path="${this.context.ruleControlFilePath}">
                ${fs.readFileSync(this.context.ruleControlFilePath, 'utf8')}
                </source-file>
                ${fs.existsSync(this.context.ruleAdaptersFolderPath) ? fs.readdirSync(this.context.ruleAdaptersFolderPath).map(f => {
            const p = path.join(this.context.ruleAdaptersFolderPath, f);
            return `<source-file path="${p}">\n${fs.readFileSync(p, 'utf8')}\n</source-file>`;
        }).join('\n') : ''}
                <source-file path="${this.context.securityControlBaseFilePath}">
                ${fs.readFileSync(this.context.securityControlBaseFilePath, 'utf8')}
                </source-file>
                <source-file path="${this.context.securityControlTypesFilePath}">
                ${fs.readFileSync(this.context.securityControlTypesFilePath, 'utf8')}
                </source-file>
                <source-file path="${testFilePath}">
                ${fs.readFileSync(testFilePath, 'utf8')}
                </source-file>
            </source-files>
            `;

        await agent.invoke(userPrompt);
    }
}

///////////////////////

export async function implementRule(spec: RequirementsSpec, service: string): Promise<ImplementationResult> {
    const { ruleId, requirements } = spec;

    console.log(`  Implementing ${requirements.length} requirements for ${ruleId}...`);

    const cfnResult = await implementRequirements(ruleId, service, requirements, 'cfn');
    const tfResult = await implementRequirements(ruleId, service, requirements, 'tf');

    const totalPassed = cfnResult.passed + tfResult.passed;
    const totalReqs = cfnResult.totalRequirements + tfResult.totalRequirements;
    const allFailed = [...cfnResult.failed, ...tfResult.failed];

    console.log(`  Final: ${totalPassed}/${totalReqs} passing`);
    return { totalRequirements: totalReqs, passed: totalPassed, failed: allFailed };
}

async function implementRequirements(ruleId: string, service: string, requirements: RuleRequirement[], format: 'cfn' | 'tf'): Promise<ImplementationResult> {
    const sorted = [...requirements].sort((a, b) => {
        if (a.expectedBehavior === 'flag' && b.expectedBehavior === 'pass') return -1;
        if (a.expectedBehavior === 'pass' && b.expectedBehavior === 'flag') return 1;
        return 0;
    });

    const regressionPaths: string[] = [];
    const passed: string[] = [];
    const failed: string[] = [];

    console.log(`\n    [${format.toUpperCase()}] ${sorted.length} requirements`);

    for (const requirement of sorted) {
        const outcome = await implementRequirement(ruleId, service, requirement, format, regressionPaths);

        if (outcome === 'passed') {
            passed.push(requirement.id);
            const testPath = getTestPath(ruleId, service, requirement.id, format);
            if (testPath) regressionPaths.push(testPath);
            console.log(`      ✓ ${requirement.id}`);
        } else {
            failed.push(`${requirement.id}-${format}`);
            console.log(`      ✗ ${requirement.id}`);
        }
    }

    return { totalRequirements: sorted.length, passed: passed.length, failed };
}

async function implementRequirement(ruleId: string, service: string, requirement: RuleRequirement, format: 'cfn' | 'tf', regressionPaths: string[]): Promise<'passed' | 'failed'> {
    const testPath = getTestPath(ruleId, service, requirement.id, format);
    if (!testPath) return 'failed';

    const initial = runVitest([testPath]);
    if (initial.allPassed) return 'passed';

    let latestFailure = initial.output;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        const regressions = checkRegressions(regressionPaths);
        const testFile = { path: testPath, content: fs.readFileSync(testPath, 'utf8') };
        const agent = new RequirementImplementationAgent();

        await agent.invoke(ruleId, service, requirement, testFile, latestFailure, regressions);

        const result = runVitest([testPath]);
        if (!result.allPassed) {
            latestFailure = result.output;
            console.log(`        attempt ${attempt}: still failing`);
            continue;
        }

        const postRegressions = checkRegressions(regressionPaths);
        if (postRegressions.length === 0) return 'passed';

        console.log(`        attempt ${attempt}: passed but caused ${postRegressions.length} regression(s)`);
    }

    return 'failed';
}

function getTestPath(ruleId: string, service: string, requirementId: string, format: 'cfn' | 'tf'): string | null {
    // const p = computeTestPath(ruleId, service, requirementId, format);
    // return fs.existsSync(p) ? p : null;
    return null;
}

function checkRegressions(regressionPaths: string[]): RegressionInfo[] {
    if (regressionPaths.length === 0) return [];

    const batchResult = runVitest(regressionPaths);
    if (batchResult.allPassed) return [];

    const regressions: RegressionInfo[] = [];
    for (const p of regressionPaths) {
        const individual = runVitest([p]);
        if (individual.allPassed) continue;
        regressions.push({ requirementId: extractRequirementId(p), testPath: p, testContent: fs.readFileSync(p, 'utf8'), failureOutput: individual.output });
    }
    return regressions;
}

function runVitest(testPaths: string[]): VitestResult {
    if (testPaths.length === 0) return { allPassed: true, output: '' };

    // const result = spawnSync('npx', ['vitest', 'run', '--reporter=verbose', ...testPaths], { cwd: srtRepoRoot(), encoding: 'utf8', timeout: 60_000 });
    // const output = (result.stdout ?? '') + (result.stderr ?? '');

    // return { allPassed: result.status === 0, output: truncate(output, 4000) };

    return { allPassed: true, output: "" };

}

function extractRequirementId(testPath: string): string {
    const match = testPath.match(/req-(\d+)/);
    return match ? `REQ-${match[1]}` : 'unknown';
}

function truncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.slice(0, maxLength) + '\n... (truncated)';
}
