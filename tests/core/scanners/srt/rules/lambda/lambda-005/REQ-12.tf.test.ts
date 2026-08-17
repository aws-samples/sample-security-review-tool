import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (LAMBDA-005): A Lambda execution role attached to a mix of permission sets —
 * several narrowly scoped ones plus one administrator- or power-user-level one — must
 * still be flagged, because effective privilege is the union of all attachments.
 */

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'exec',
  address: 'aws_iam_role.exec',
  values: {
    name: 'order-processor-exec',
    assume_role_policy: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        { Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' },
      ],
    }),
  },
} as unknown as TerraformResource;

const lambdaFunction: TerraformResource = {
  type: 'aws_lambda_function',
  name: 'order_processor',
  address: 'aws_lambda_function.order_processor',
  // reference form: role = aws_iam_role.exec.arn collapses to the address
  values: { function_name: 'order-processor', role: 'aws_iam_role.exec', runtime: 'nodejs20.x' },
} as unknown as TerraformResource;

function attachment(name: string, policyArn: string, roleRef: string): TerraformResource {
  return {
    type: 'aws_iam_role_policy_attachment',
    name,
    address: `aws_iam_role_policy_attachment.${name}`,
    values: { role: roleRef, policy_arn: policyArn },
  } as unknown as TerraformResource;
}

const narrowAttachments = (roleRef: string): TerraformResource[] => [
  attachment('basic', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole', roleRef),
  attachment('s3_read', 'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess', roleRef),
];

function runOnRole(extraAttachment: TerraformResource, roleRef = 'aws_iam_role.exec'): ScanResult | null {
  const allResources = [role, lambdaFunction, ...narrowAttachments(roleRef), extraAttachment];
  const context: TfContext = {
    projectName: 'lambda-project',
    resource: role,
    allResources,
  };
  const adapter = new Lambda005TfAdapterFactory().bind(context);
  return lambda005Control.run(adapter, context);
}

const broadManagedPolicyRemediation = lambda005Control.findings['overly-broad-managed-policy'].remediation;

describe('LAMBDA-005 REQ-12 (Terraform): mixed narrow + admin-level attachments', () => {
  it('flags an execution role whose narrow attachments are accompanied by AdministratorAccess (reference form)', () => {
    const result = runOnRole(attachment('admin', 'arn:aws:iam::aws:policy/AdministratorAccess', 'aws_iam_role.exec'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.exec');
    expect(result?.fix).toBe(broadManagedPolicyRemediation);
  });

  it('flags an execution role whose narrow attachments are accompanied by PowerUserAccess (literal role name form)', () => {
    const result = runOnRole(
      attachment('power', 'arn:aws:iam::aws:policy/PowerUserAccess', 'order-processor-exec'),
      'order-processor-exec',
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.fix).toBe(broadManagedPolicyRemediation);
  });

  // Opposite outcome: identical fixture except the broad attachment is replaced by another
  // narrowly scoped policy, so the union of attachments stays least-privilege.
  it('does not flag when every attached permission set is narrowly scoped', () => {
    const result = runOnRole(attachment('xray', 'arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess', 'aws_iam_role.exec'));

    expect(result).toBeNull();
  });
});
