import { srtRepoRoot } from '../../shared/fixture-paths.js';
import type { RequirementsSpec } from '../../shared/types/requirements.js';

export const SYSTEM_PROMPT = `You scaffold empty-but-typeable security rule files for a TDD workflow. You will be given a rule's metadata and the target file paths to create. Use the fileEditor tool to:
1. View the canonical reference files I point you to (read them first to understand the pattern).
2. Create the scaffold files following the same patterns.

Key constraints:
- The control's evaluate() method must return null unconditionally (stub — implementation comes later).
- Adapter interfaces should extend BoundAdapter with NO additional methods.
- Bound adapter classes implement only resourceId, resourceType, and getRemediation() returning null.
- Factories must have applicableResourceTypes populated and working appliesTo() + bind().
- remediationScenarios on the control should be an empty array.
- Export a singleton instance of the control (e.g. export const ddb002Control = new Ddb002Control()).
- All files must compile with strict TypeScript.`;

export function buildScaffolderPrompt(ruleId: string, service: string, description: string, spec: RequirementsSpec, controlPath: string, adaptersDir: string, adaptersExist: boolean): string {
    const root = srtRepoRoot();
    const lines: string[] = [];

    lines.push('═══ RULE METADATA ═══');
    lines.push(`Rule ID: ${ruleId}`);
    lines.push(`Service: ${service}`);
    lines.push(`Description: ${description}`);
    lines.push('');
    lines.push('═══ REQUIREMENTS SUMMARY ═══');
    for (const req of spec.requirements) {
        lines.push(`- ${req.id}: ${req.description}`);
    }
    lines.push('');
    lines.push('═══ CANONICAL REFERENCE FILES (view these first) ═══');
    lines.push(`Control: ${root}/src/assess/scanning/security-matrix/rules/s3/controls/s3-001.control.ts`);
    lines.push(`Adapter interface: ${root}/src/assess/scanning/security-matrix/rules/s3/adapters/s3-bucket-adapter.ts`);
    lines.push(`CFN adapter factory: ${root}/src/assess/scanning/security-matrix/rules/s3/adapters/cfn-s3-bucket-adapter.ts`);
    lines.push(`TF adapter factory: ${root}/src/assess/scanning/security-matrix/rules/s3/adapters/tf-s3-bucket-adapter.ts`);
    lines.push(`Controls types: ${root}/src/assess/scanning/security-matrix/controls/types.ts`);
    lines.push(`SecurityControl base: ${root}/src/assess/scanning/security-matrix/controls/security-control.ts`);
    lines.push('');
    lines.push('═══ TARGET FILES TO CREATE ═══');
    lines.push(`Control: ${controlPath}`);

    if (!adaptersExist) {
        lines.push(`Adapter interface: ${adaptersDir}/${service}-adapter.ts`);
        lines.push(`CFN adapter factory: ${adaptersDir}/cfn-${service}-adapter.ts`);
        lines.push(`TF adapter factory: ${adaptersDir}/tf-${service}-adapter.ts`);
        lines.push('');
        lines.push('The adapters directory does not exist yet — create all adapter files plus the control.');
        lines.push('Infer applicableResourceTypes from the requirements above (look for resource type names like AWS::DynamoDB::Table or aws_dynamodb_table).');
    } else {
        lines.push('');
        lines.push('Adapters already exist for this service — only create the control file.');
        lines.push(`View the adapters directory to see what exists: ${adaptersDir}`);
        lines.push('The control should use BoundAdapter as its adapter type (from controls/types.ts) since the existing adapters serve a different rule.');
    }

    lines.push('');
    lines.push('═══ INSTRUCTIONS ═══');
    lines.push('1. View all canonical reference files first.');
    lines.push('2. Create the target files following the same code style and import patterns.');
    lines.push('3. evaluate() returns null unconditionally.');
    lines.push('4. remediationScenarios = [].');
    lines.push('5. Adapter interface extends BoundAdapter with no added methods.');
    lines.push('6. Use fileEditor create for each file. Ensure parent directories exist (view them first).');

    return lines.join('\n');
}
