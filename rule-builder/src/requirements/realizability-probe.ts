import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { tool } from '@strands-agents/sdk';
import z from 'zod';
import { OpusAgent } from '../shared/agents/opus-agent.js';
import { AgentToolFactory } from '../implementation/agent-tools.js';
import { firstLine } from '../implementation/test-discrimination.js';
import { createAwsKnowledgeMcpClient } from '../shared/aws-knowledge-mcp-client.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';
import { RuleContext } from '../shared/rule-context.js';
import type { RuleRequirement } from '../shared/types/requirements.js';

const MAX_SNIPPET_ATTEMPTS = 3;
const LINT_TIMEOUT_MS = 60_000;
const TERRAFORM_TIMEOUT_MS = 120_000;

const UNBUILDABLE_CFN_RULES = ['E3002', 'E3012'];
const UNBUILDABLE_TF_MESSAGES = [/is not expected here/i, /Unsupported argument/i, /Unsupported block type/i];

export interface RealizabilityVerdict {
    requirementId: string;
    realizable: boolean;
    reason: string;
}

interface Evidence {
    unbuildable: boolean;
    detail: string;
}

export class RealizabilityProbe {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext, private readonly cfnResources: string[], private readonly tfResources: string[]) { }

    public async probe(requirements: RuleRequirement[]): Promise<RealizabilityVerdict[]> {
        const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'srt-realizability-'));

        try {
            return await this.probeInWorkspace(requirements, workspace);
        } finally {
            fs.rmSync(workspace, { recursive: true, force: true });
        }
    }

    private async probeInWorkspace(requirements: RuleRequirement[], workspace: string): Promise<RealizabilityVerdict[]> {
        const snippetsFolder = path.join(workspace, 'snippets');
        fs.mkdirSync(snippetsFolder, { recursive: true });
        const terraformProject = this.prepareTerraformProject(workspace);

        let outstanding = requirements;
        let failures = new Map<string, string>();

        for (let attempt = 1; attempt <= MAX_SNIPPET_ATTEMPTS && outstanding.length > 0; attempt++) {
            await this.writeSnippets(outstanding, snippetsFolder, terraformProject, failures);
            failures = await this.unbuildable(outstanding, snippetsFolder, terraformProject);

            outstanding = outstanding.filter(requirement => failures.has(requirement.id));
            if (outstanding.length > 0) {
                this.logger.warning(`${outstanding.length} scenario(s) do not build (attempt ${attempt} of ${MAX_SNIPPET_ATTEMPTS})`);
            }
        }

        return requirements.map(requirement => ({
            requirementId: requirement.id,
            realizable: !failures.has(requirement.id),
            reason: failures.get(requirement.id) ?? 'a template expressing the scenario validates',
        }));
    }

    private async writeSnippets(requirements: RuleRequirement[], snippetsFolder: string, terraformProject: string | null, failures: Map<string, string>): Promise<void> {
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new OpusAgent({
                systemPrompt: SYSTEM_PROMPT,
                tools: [
                    mcpClient,
                    AgentToolFactory.createWriteFileTool({ ensureDir: true }),
                    this.createCfnLintTool(),
                    ...(terraformProject ? [this.createTerraformValidateTool(terraformProject)] : []),
                ],
            });

            await this.logger.task(`realizing ${requirements.length} scenario(s)`, () => agent.invoke(this.buildUserPrompt(requirements, snippetsFolder, failures)));
        } finally {
            await mcpClient.disconnect().catch(() => { });
        }
    }

    private buildUserPrompt(requirements: RuleRequirement[], snippetsFolder: string, failures: Map<string, string>): string {
        const scenarios = requirements
            .map(requirement => `### ${requirement.id}\n${requirement.description}${this.previousFailure(requirement, failures)}`)
            .join('\n\n');

        return `## Rule\n\n${this.context.description}

## Resource Types

CloudFormation: ${this.cfnResources.join(', ') || 'none recorded'}
Terraform: ${this.tfResources.join(', ') || 'none recorded'}

## Scenarios

${scenarios}

Write, for each scenario, ${path.join(snippetsFolder, '<REQ-ID>.yaml')} and ${path.join(snippetsFolder, '<REQ-ID>.tf')}.`;
    }

    private previousFailure(requirement: RuleRequirement, failures: Map<string, string>): string {
        const failure = failures.get(requirement.id);
        if (!failure) return '';

        return `\n\nYour previous attempt did not validate: ${failure}\nIf the scenario genuinely cannot be written in a format, leave that attempt as the closest thing to it you can write and do not disguise the error by expressing something else.`;
    }

    private async unbuildable(requirements: RuleRequirement[], snippetsFolder: string, terraformProject: string | null): Promise<Map<string, string>> {
        const cfn = await Promise.all(requirements.map(requirement => this.lintCloudFormation(path.join(snippetsFolder, `${requirement.id}.yaml`))));

        const failures = new Map<string, string>();
        for (const [index, requirement] of requirements.entries()) {
            const cfnEvidence = cfn[index];
            if (!cfnEvidence.unbuildable) continue;

            const terraformEvidence = await this.validateTerraform(path.join(snippetsFolder, `${requirement.id}.tf`), terraformProject);
            if (!terraformEvidence.unbuildable) continue;

            failures.set(requirement.id, `no format can express it — CloudFormation: ${cfnEvidence.detail}; Terraform: ${terraformEvidence.detail}`);
        }

        return failures;
    }

    private async lintCloudFormation(templatePath: string): Promise<Evidence> {
        if (!fs.existsSync(templatePath)) return { unbuildable: true, detail: 'no template was written' };

        const result = await AgentToolFactory.runCfnLint(templatePath, ['--format', 'json'], LINT_TIMEOUT_MS);

        return this.interpretCfnLint(result.stdout ?? '', result.stderr ?? '');
    }

    private interpretCfnLint(stdout: string, stderr: string): Evidence {
        let matches: Array<{ Rule?: { Id?: string }; Message?: string }>;
        try {
            matches = JSON.parse(stdout);
        } catch {
            return { unbuildable: false, detail: `cfn-lint produced no readable report (${firstLine(stderr) || 'no output'})` };
        }

        const shapeErrors = matches.filter(match => UNBUILDABLE_CFN_RULES.includes(match.Rule?.Id ?? ''));
        if (shapeErrors.length === 0) return { unbuildable: false, detail: 'validates' };

        return { unbuildable: true, detail: shapeErrors.map(error => `${error.Rule?.Id} ${error.Message}`).join('; ') };
    }

    private async validateTerraform(snippetPath: string, terraformProject: string | null): Promise<Evidence> {
        if (!terraformProject) return { unbuildable: false, detail: 'terraform is unavailable, so nothing was checked' };
        if (!fs.existsSync(snippetPath)) return { unbuildable: true, detail: 'no configuration was written' };

        const stagedPath = path.join(terraformProject, 'snippet.tf');
        fs.cpSync(snippetPath, stagedPath);

        try {
            const result = spawnSync('terraform', ['validate', '-json'], { cwd: terraformProject, encoding: 'utf8', timeout: TERRAFORM_TIMEOUT_MS });
            return this.interpretTerraformValidate(result.stdout ?? '', result.stderr ?? '');
        } finally {
            fs.rmSync(stagedPath, { force: true });
        }
    }

    private interpretTerraformValidate(stdout: string, stderr: string): Evidence {
        let report: { diagnostics?: Array<{ severity?: string; summary?: string; detail?: string }> };
        try {
            report = JSON.parse(stdout);
        } catch {
            return { unbuildable: false, detail: `terraform produced no readable report (${firstLine(stderr) || 'no output'})` };
        }

        const shapeErrors = (report.diagnostics ?? [])
            .filter(diagnostic => diagnostic.severity === 'error')
            .filter(diagnostic => UNBUILDABLE_TF_MESSAGES.some(pattern => pattern.test(`${diagnostic.summary} ${diagnostic.detail}`)));

        if (shapeErrors.length === 0) return { unbuildable: false, detail: 'validates' };

        return { unbuildable: true, detail: shapeErrors.map(error => error.summary).join('; ') };
    }

    private prepareTerraformProject(workspace: string): string | null {
        const projectFolder = path.join(workspace, 'terraform');
        fs.cpSync(this.context.terraformFixtureTemplateFolderPath, projectFolder, { recursive: true });

        const result = spawnSync('terraform', ['init', '-backend=false', '-input=false'], { cwd: projectFolder, encoding: 'utf8', timeout: TERRAFORM_TIMEOUT_MS });
        if (result.status === 0) return projectFolder;

        this.logger.warning(`Terraform is unavailable for realizability checks: ${firstLine(result.stderr ?? '') || firstLine(result.stdout ?? '') || 'terraform init failed'}`);
        return null;
    }

    private createCfnLintTool() {
        return tool({
            name: 'run_cfn_lint',
            description: 'Run cfn-lint against one CloudFormation template you have written. Returns the findings. Call it for every template before you finish.',
            inputSchema: z.object({ filePath: z.string().describe('The absolute path of the template to lint') }),
            callback: async ({ filePath }) => this.lintCloudFormation(filePath),
        });
    }

    private createTerraformValidateTool(terraformProject: string) {
        return tool({
            name: 'run_terraform_validate',
            description: 'Run terraform validate against one Terraform configuration you have written. Returns the diagnostics. Call it for every configuration before you finish.',
            inputSchema: z.object({ filePath: z.string().describe('The absolute path of the configuration to validate') }),
            callback: async ({ filePath }) => this.validateTerraform(filePath, terraformProject),
        });
    }
}


const SYSTEM_PROMPT = `You establish whether the scenarios in a security rule's requirements specification describe configurations that can actually be written. For each one you write the smallest CloudFormation template and the smallest Terraform configuration that expresses it, and validate them.

The specification is format-agnostic on purpose, so a scenario that cannot be written in either format is one the rule will never encounter. Those are removed from the specification. Your templates are the evidence for that decision and are then thrown away — they are not fixtures, and nothing is deployed.

## What Each File Must Contain

CloudFormation (<REQ-ID>.yaml): a complete template — 'AWSTemplateFormatVersion: '2010-09-09'' and a Resources block containing only the resources the scenario needs.

Terraform (<REQ-ID>.tf): resource blocks only. Do NOT write terraform {} or provider {} blocks; the surrounding project supplies them.

Use the resource types listed for the rule. Keep both files minimal: the resources the scenario names and nothing else.

## Express The Scenario, Not Something Near It

The template has to put the configuration where the scenario says it is. A scenario about a setting on a related resource means the property goes on that related resource. A scenario about a value appearing twice means it appears twice. A scenario about an absent configuration means the property is left out — not set to a placeholder.

If validation rejects what the scenario describes, that is the finding. Do not move the property somewhere legal, substitute a different property, or drop the resource to make the error go away: a template that validates by expressing something else tells the specification a false thing, and the scenario stays in with no coverage behind it.

Where the scenario cannot be written in a format, leave the closest attempt you can and let the validator report it. A scenario is only removed when NEITHER format can express it, so an honest failure in one format costs nothing.

## Before You Finish

Look up the resource in the AWS documentation when you are unsure a property exists or what shape it takes. Then lint every template and validate every configuration you wrote, and fix the errors that are yours — a typo, a missing required property, a malformed value. Leave only the errors that are the scenario's.
`;
