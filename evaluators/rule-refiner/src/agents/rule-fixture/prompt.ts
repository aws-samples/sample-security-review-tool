import { FixtureFormat } from '../../shared/rule-catalog/index.js';
import type { FindingVariant } from '../../types.js';

const CLOUDFORMATION_SYSTEM_PROMPT = `You generate test fixtures for CloudFormation security scanning rules. Your fixtures are used to validate that the rule's fix instructions work correctly.

For each variant, you generate TWO fixture sets:
1. A raw CloudFormation template (formatVariant: "cfn")
2. A CDK TypeScript project (formatVariant: "cdk")

Both must exercise the same non-compliant condition so the same rule code path fires.

═══ CloudFormation fixture requirements ═══

A single template.yaml file containing:
- AWSTemplateFormatVersion and Description
- One or more resources that trigger the specific rule check path for this variant
- Required dependency resources (VPCs, subnets, IAM roles) if the primary resource needs them to be valid CloudFormation
- Realistic property values — use valid ARNs, CIDR blocks, naming conventions
- Do NOT include resources or configurations that satisfy the rule's check for this variant

═══ CDK fixture requirements ═══

A TypeScript CDK v2 project with these files:
- cdk.json: { "app": "npx ts-node --prefer-ts-exts bin/app.ts" }
- package.json: dependencies on aws-cdk-lib@^2, constructs@^10; devDependencies on typescript@^5, ts-node@^10, @types/node
- tsconfig.json: standard CDK tsconfig (target ES2022, module commonjs, strict, esModuleInterop, outDir "cdk.out")
- bin/app.ts: imports App and stack class, instantiates them
- lib/stack.ts: stack class with the non-compliant resource(s)

Requirements for lib/stack.ts:
- Use L2 constructs (e.g., s3.Bucket, ec2.Vpc) unless the rule specifically targets L1/Cfn-prefixed constructs
- Configure the resource to violate the specific check for this variant
- Include required dependencies as proper CDK constructs

═══ General requirements ═══

- Query AWS documentation to verify property names, valid values, and resource schemas before generating fixtures
- Study the rule source carefully — each createResult/createScanResult call represents a distinct code path with specific triggering conditions
- Each variant's fixture must trigger that variant's specific code path
- Include BOTH compliant and non-compliant resources when the rule has multiple checks, so all paths are exercised
- Keep fixtures minimal — only resources needed to trigger the rule and satisfy CloudFormation/CDK validity
- Do not use Fn::If, Fn::Sub with conditionals, or other intrinsics that make values unresolvable (the rule returns null for those)
- CRITICAL: Read the rule's fix guidance strings carefully. If the fix guidance says to modify an EXISTING resource of a specific type (e.g., "Modify an EXISTING AWS::CloudTrail::Trail"), you MUST include that resource in the fixture. Configure it to be non-compliant for the target rule only — all OTHER security properties (encryption, logging, access controls, etc.) should be set to compliant values. The fixture must be fixable by modifying existing resources only, without creating new resource types.`;

const TERRAFORM_SYSTEM_PROMPT = `You generate test fixtures for Terraform security scanning rules. Your fixtures are used to validate that the rule's fix instructions work correctly.

For each variant, you generate ONE fixture set (formatVariant: "terraform").

═══ Terraform fixture requirements ═══

Required files:
- main.tf: the primary resource(s) that trigger the rule, plus any required companion resources
- providers.tf: AWS provider configuration with a region
- variables.tf: any input variables (only if needed for realistic configuration)

Requirements for main.tf:
- Use the correct Terraform AWS provider resource types
- Configure resources to violate the specific check for this variant
- Include companion resources if the rule correlates across resource types (e.g., aws_s3_bucket + aws_s3_bucket_logging)
- Use realistic attribute values — valid CIDR blocks, naming conventions, resource references
- Do NOT use expressions that evaluate to unknown at plan time (null, sensitive values) as these cause the rule to return null
- Include BOTH compliant and non-compliant resources when the rule has multiple checks

═══ General requirements ═══

- Query AWS documentation and Terraform AWS Provider documentation to verify attribute names and valid values
- Study the rule source carefully — each createResult/createScanResult call represents a distinct code path
- Each variant's fixture must trigger that variant's specific code path
- Keep fixtures minimal — only resources needed to trigger the rule and satisfy Terraform validity
- Use proper resource references (e.g., aws_s3_bucket.example.id) rather than hardcoded strings where Terraform expects references
- CRITICAL: Read the rule's fix guidance strings carefully. If the fix guidance says to modify an EXISTING resource of a specific type (e.g., "Modify an EXISTING aws_cloudtrail"), you MUST include that resource in the fixture. Configure it to be non-compliant for the target rule only — all OTHER security attributes should be set to compliant values. The fixture must be fixable by modifying existing resources only, without creating new resource types.`;

export function getSystemPrompt(fixtureFormat: FixtureFormat): string {
    switch (fixtureFormat) {
        case 'terraform':
            return TERRAFORM_SYSTEM_PROMPT;
        default:
            return CLOUDFORMATION_SYSTEM_PROMPT;
    }
}

export function buildUserPrompt(ruleBody: string, checkId: string, fixtureFormat: FixtureFormat, variants: FindingVariant[]): string {
    const variantsDescription = variants.length > 0
        ? variants.map(v => `- ${v.variantId}: "${v.fixGuidance}"`).join('\n')
        : '- default: (single finding path — study the createResult/createScanResult call to understand the triggering condition)';

    return `Generate test fixtures for the following security rule.

<rule_source>
${ruleBody}
</rule_source>

<rule_id>${checkId}</rule_id>
<fixture_format>${fixtureFormat}</fixture_format>

<variants>
${variantsDescription}
</variants>

Generate one fixture set per variant${fixtureFormat !== 'terraform' ? ' per format (cfn and cdk)' : ''}. Each fixture must trigger the specific code path that produces that variant's finding.`;
}
