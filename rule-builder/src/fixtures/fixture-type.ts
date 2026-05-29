import { InvokableTool } from '@strands-agents/sdk';
import { RuleContext } from '../shared/rule-context.js';
import { AgentToolFactory } from '../implementation/agent-tools.js';

const CDK_SYSTEM_PROMPT = `You write CDK fixture stacks that trigger security rule scenarios for remediation testing.

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

const TERRAFORM_SYSTEM_PROMPT = `You write Terraform fixtures that trigger security rule scenarios for remediation testing.

Your output is a single HCL file (main.tf) defining the resource blocks needed to trigger the rule. The file must:
- Trigger EVERY remediation scenario defined in the control's remediationScenarios array.
- Use as many resources as needed per scenario (supporting resources are fine).
- Only include resources relevant to this rule.
- Declare exactly the aws_* resource types listed in the Terraform adapter's applicableResourceTypes array.
- Each scannable resource must be intentionally non-compliant in the specific way its target scenario detects.
- Initialize, validate, and plan cleanly (the plan runs with dummy credentials and no AWS access).

Important constraints:
- The control's evaluate() method returns on the FIRST matching finding per resource. To trigger multiple scenarios you typically need separate resources, each configured to match a different scenario's condition while NOT matching earlier conditions in the evaluate chain.
- Study the evaluate() method and the Terraform adapter carefully to understand the order of checks, which aws_* resource types apply, and which resource argument each scenario reads.
- Do NOT emit terraform {} or provider {} blocks — provider and version configuration is supplied by the surrounding template (versions.tf and providers.tf).
- The fixture is exercised with 'terraform plan' using dummy credentials and no network access to AWS. Never use data sources that query live AWS APIs (e.g. data "aws_caller_identity", data "aws_region", data "aws_availability_zones"). Hardcode any value such resources would supply (account id, region, ARNs) as a literal instead.
- Keep the fixture minimal: include ONLY the resources needed to trigger the scenario. Do NOT add supporting resources that would satisfy the rule and prevent the finding from firing.
- Use the AWS documentation tools to look up the correct Terraform resource arguments before writing the fixture.
- If a scenario cannot be expressed in Terraform, do NOT attempt workarounds. Instead, include an HCL comment explaining which scenario is skipped and why it cannot be triggered.`;

export class FixtureType {
    constructor(public readonly label: string, public readonly outputFolderPath: string, public readonly templateFolderPath: string, public readonly resourceFilePath: string, public readonly resourceFileName: string, public readonly adapterFilePath: string, public readonly systemPrompt: string, public readonly createValidationTool: () => InvokableTool<unknown, any>) { }

    static cdk(context: RuleContext): FixtureType {
        return new FixtureType('CDK', context.cdkFixtureOutputFolderPath, context.cdkFixtureTemplateFolderPath, context.cdkFixtureResourceFilePath, 'fixture-stack.ts', context.ruleAdapterCfnFilePath, CDK_SYSTEM_PROMPT, () => AgentToolFactory.createTscTool(context.cdkFixtureOutputFolderPath));
    }

    static terraform(context: RuleContext): FixtureType {
        return new FixtureType('Terraform', context.terraformFixtureOutputFolderPath, context.terraformFixtureTemplateFolderPath, context.terraformFixtureResourceFilePath, 'main.tf', context.ruleAdapterTfFilePath, TERRAFORM_SYSTEM_PROMPT, () => AgentToolFactory.createTerraformValidateTool(context.terraformFixtureOutputFolderPath));
    }
}
