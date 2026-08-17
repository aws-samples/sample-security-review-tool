import { InvokableTool } from '@strands-agents/sdk';
import { RuleContext } from '../shared/rule-context.js';
import { AgentToolFactory } from '../implementation/agent-tools.js';
import { PREPROCESSING_BEHAVIOR } from '../implementation/preprocessing-behavior.js';
import { TERRAFORM_SOURCE_BEHAVIOR } from '../implementation/terraform-source-behavior.js';

const RESOLVABILITY_STEER = `## A triggering value must be statically resolvable

The scanner evaluates the rule against the value left AFTER preprocessing — it never deploys the stack. A resource can only trigger the rule on a property whose value preprocessing reduces to a scalar. If the value reduces to an opaque object (an unresolved intrinsic), the rule sees "unknown" and does NOT fire, so the fixture fails to trigger.

When you need a property to TRIGGER the rule, give it a statically resolvable value:
- a literal string (always safe, and the simplest correct choice), or
- an Fn::Sub/Fn::Join built only from literals, pseudo-parameters, and template parameters.

Do NOT derive a triggering value from a CREATED resource's runtime attribute. In CDK, tokens like \`repository.repositoryUri\`, \`bucket.bucketArn\`, or any \`resource.someAttr\` synthesize to Fn::GetAtt/Fn::Select/Fn::Split, which preprocessing cannot resolve — the rule will never see the string and the fixture will silently fail to trigger. Hardcode the equivalent literal instead.

If a rule genuinely cannot be triggered by any statically resolvable value, do not fabricate one — add a comment naming the scenario and explaining why it cannot be triggered.`;

const CFN_PREPROCESSING_SECTION = `\n\n${RESOLVABILITY_STEER}\n\n## CloudFormation Template Preprocessing\n\n${PREPROCESSING_BEHAVIOR}`;
const TERRAFORM_SOURCE_SECTION = `\n\n## Terraform Source Behavior\n\n${TERRAFORM_SOURCE_BEHAVIOR}`;

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

const CFN_SYSTEM_PROMPT = `You write CloudFormation fixture templates that trigger security rule scenarios for remediation testing.

Your output is a single YAML file (template.yaml) defining the Resources needed to trigger the rule. The file must:
- Begin with AWSTemplateFormatVersion: '2010-09-09'.
- Trigger EVERY remediation scenario defined in the control's remediationScenarios array.
- Use as many resources as needed per scenario (supporting resources are fine).
- Only include resources relevant to this rule.
- Declare exactly the AWS::* resource Types listed in the CloudFormation adapter's applicableResourceTypes array.
- Each scannable resource must be intentionally non-compliant in the specific way its target scenario detects.
- Pass cfn-lint cleanly.

Important constraints:
- The control's evaluate() method returns on the FIRST matching finding per resource. To trigger multiple scenarios you typically need separate resources, each configured to match a different scenario's condition while NOT matching earlier conditions in the evaluate chain.
- Study the evaluate() method and the CloudFormation adapter carefully to understand the order of checks, which AWS::* resource types apply, and which resource property each scenario reads.
- Use static, hardcoded values for all properties. Do NOT use Parameters, Mappings, or Conditions to indirect the values the rule reads — the property must be visible directly on the resource so the scanner can evaluate it.
- Do NOT use intrinsic functions (!Ref, !GetAtt, !Sub, !Join, !ImportValue, pseudo-parameters like AWS::Region or AWS::AccountId) for values the rule inspects. If you reference another fixture resource, !Ref is acceptable for resource wiring (e.g. a SecurityGroup id), but the property the rule checks must be a literal.
- Keep the fixture minimal: include ONLY the resources needed to trigger the scenario. Do NOT add supporting resources that would satisfy the rule and prevent the finding from firing.
- Use the AWS documentation tools to look up the correct CloudFormation resource type and property names before writing the fixture.
- If a scenario cannot be expressed in CloudFormation, do NOT attempt workarounds. Instead, include a YAML comment explaining which scenario is skipped and why it cannot be triggered.`;

export class FixtureType {
    constructor(public readonly label: string, public readonly outputFolderPath: string, public readonly templateFolderPath: string, public readonly resourceFilePath: string, public readonly resourceFileName: string, public readonly adapterFilePath: string, public readonly systemPrompt: string, public readonly createValidationTool: () => InvokableTool<unknown, any>) { }

    static cdk(context: RuleContext): FixtureType {
        return new FixtureType('CDK', context.cdkFixtureOutputFolderPath, context.cdkFixtureTemplateFolderPath, context.cdkFixtureResourceFilePath, 'fixture-stack.ts', context.ruleAdapterCfnFilePath, CDK_SYSTEM_PROMPT + CFN_PREPROCESSING_SECTION, () => AgentToolFactory.createTscTool(context.cdkFixtureOutputFolderPath));
    }

    static terraform(context: RuleContext): FixtureType {
        return new FixtureType('Terraform', context.terraformFixtureOutputFolderPath, context.terraformFixtureTemplateFolderPath, context.terraformFixtureResourceFilePath, 'main.tf', context.ruleAdapterTfFilePath, TERRAFORM_SYSTEM_PROMPT + TERRAFORM_SOURCE_SECTION, () => AgentToolFactory.createTerraformValidateTool(context.terraformFixtureOutputFolderPath));
    }

    static cloudFormation(context: RuleContext): FixtureType {
        return new FixtureType('CloudFormation', context.cloudFormationFixtureOutputFolderPath, context.cloudFormationFixtureTemplateFolderPath, context.cloudFormationFixtureResourceFilePath, 'template.yaml', context.ruleAdapterCfnFilePath, CFN_SYSTEM_PROMPT + CFN_PREPROCESSING_SECTION, () => AgentToolFactory.createCfnLintTool(context.cloudFormationFixtureOutputFolderPath));
    }
}
