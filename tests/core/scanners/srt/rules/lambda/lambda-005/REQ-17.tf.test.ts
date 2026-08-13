import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-17 (LAMBDA-005): when the presence or content of an administrator-level grant on a
 * Lambda execution role is unknown at plan time (field recorded as null), the rule must not
 * report a finding. Detection of resolvable broad grants belongs to the primary LAMBDA-005
 * requirements and appears here only as the opposite case.
 */

const factory = new Lambda005TfAdapterFactory();

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'exec',
  address: 'aws_iam_role.exec',
  values: { name: 'lambda-exec-role' },
} as unknown as TerraformResource;

const lambdaFunction: TerraformResource = {
  type: 'aws_lambda_function',
  name: 'fn',
  address: 'aws_lambda_function.fn',
  values: { function_name: 'my-fn', role: 'aws_iam_role.exec' },
} as unknown as TerraformResource;

function run(extra: TerraformResource[]): ScanResult | null {
  const allResources = [role, lambdaFunction, ...extra];
  const context: TfContext = { projectName: 'test-project', resource: role, allResources };
  const adapter = factory.bind(context);
  return lambda005Control.run(adapter as never, context);
}

describe('LAMBDA-005 REQ-17 (Terraform): undecidable admin-level grants are not flagged', () => {
  it('returns no finding when the attachment policy_arn is unknown at plan time', () => {
    const attachment: TerraformResource = {
      type: 'aws_iam_role_policy_attachment',
      name: 'admin',
      address: 'aws_iam_role_policy_attachment.admin',
      values: { role: 'aws_iam_role.exec', policy_arn: null },
    } as unknown as TerraformResource;

    expect(run([attachment])).toBeNull();
  });

  it('returns no finding when the inline role policy document is unknown at plan time', () => {
    const inline: TerraformResource = {
      type: 'aws_iam_role_policy',
      name: 'inline',
      address: 'aws_iam_role_policy.inline',
      values: { role: 'aws_iam_role.exec', name: 'inline', policy: null },
    } as unknown as TerraformResource;

    expect(run([inline])).toBeNull();
  });

  // Opposite outcome: reference-form attachment to a declared administrator-level policy is resolvable and must be flagged.
  it('reports a finding when the attachment references a declared AdministratorAccess policy', () => {
    const policy: TerraformResource = {
      type: 'aws_iam_policy',
      name: 'admin',
      address: 'aws_iam_policy.admin',
      values: { name: 'AdministratorAccess' },
    } as unknown as TerraformResource;

    const attachment: TerraformResource = {
      type: 'aws_iam_role_policy_attachment',
      name: 'admin',
      address: 'aws_iam_role_policy_attachment.admin',
      values: { role: 'aws_iam_role.exec', policy_arn: 'aws_iam_policy.admin' },
    } as unknown as TerraformResource;

    const result = run([policy, attachment]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.exec');
  });
});
