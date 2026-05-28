import * as fs from 'node:fs';
import { RuleContext } from '../shared/rule-context.js';

export class FixtureGenerationPromptBuilder {
    constructor(private readonly context: RuleContext) { }

    public buildSystemPrompt(): string {
        return `You write CDK fixture stacks that trigger security rule scenarios for remediation testing.

Your output is a single TypeScript file defining a CDK stack class called FixtureStack. The stack must:
- Trigger EVERY remediation scenario defined in the control's remediationScenarios array.
- Use as many resources as needed per scenario (supporting resources like WebACLs or VPCs are fine).
- Only include resources relevant to this rule.
- Each scannable resource must be intentionally non-compliant in the specific way its target scenario detects.
- Compile without TypeScript errors and synthesize without runtime errors.

Important constraints:
- The control's evaluate() method returns on the FIRST matching finding per resource. To trigger multiple scenarios you typically need separate resources, each configured to match a different scenario's condition while NOT matching earlier conditions in the evaluate chain.
- Study the evaluate() method carefully to understand the order of checks and what conditions trigger each scenario.
- Use the AWS documentation tools to look up the correct CDK constructs before writing the fixture. Use L2 (high-level) constructs where they exist.
- Never omit required properties or use type casts to bypass the TypeScript compiler.
- If a scenario cannot be expressed in CDK (e.g., because CDK's type system enforces a property that the scenario requires to be absent), do NOT attempt workarounds. Instead, include a comment in the fixture explaining which scenario is skipped and why it cannot be triggered in CDK.
- After writing the fixture, run the TypeScript compiler to verify it compiles. If it fails, fix the errors.`;
    }

    public buildUserPrompt(): string {
        const controlSource = fs.readFileSync(this.context.ruleControlFilePath, 'utf8');
        const adapterSource = fs.readFileSync(this.context.ruleAdapterBaseFilePath, 'utf8');
        const adapterCfnSource = fs.readFileSync(this.context.ruleAdapterCfnFilePath, 'utf8');
        const fixtureOutputPath = `${this.context.cdkFixtureOutputFolderPath}/fixture-stack.ts`;

        return `Write a CDK fixture stack that triggers all remediation scenarios for rule ${this.context.ruleId}.

Save the file to: ${fixtureOutputPath}

<source-files>
    <source-file path="${this.context.ruleControlFilePath}">
    ${controlSource}
    </source-file>
    <source-file path="${this.context.ruleAdapterBaseFilePath}">
    ${adapterSource}
    </source-file>
    <source-file path="${this.context.ruleAdapterCfnFilePath}">
    ${adapterCfnSource}
    </source-file>
</source-files>`;
    }
}
