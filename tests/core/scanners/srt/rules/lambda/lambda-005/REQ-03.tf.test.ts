import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda005TfAdapterFactory();

function policyDocument(resourceScope: unknown): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: '*',
        Resource: resourceScope,
      },
    ],
  });
}

function buildResources(resourceScope: unknown): TerraformResource[] {
  const role: TerraformResource = {
    type: 'aws_iam_role',
    name: 'exec',
    address: 'aws_iam_role.exec',
    values: {
      name: 'handler-exec-role',
      assume_role_policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: { Service: 'lambda.amazonaws.com' },
            Action: 'sts:AssumeRole',
          },
        ],
      }),
    },
  } as unknown as TerraformResource;

  const inlinePolicy: TerraformResource = {
    type: 'aws_iam_role_policy',
    name: 'grant',
    address: 'aws_iam_role_policy.grant',
    values: {
      name: 'inline-grant',
      // Reference form — HCL wrote aws_iam_role.exec.id
      role: 'aws_iam_role.exec',
      policy: policyDocument(resourceScope),
    },
  } as unknown as TerraformResource;

  const fn: TerraformResource = {
    type: 'aws_lambda_function',
    name: 'handler',
    address: 'aws_lambda_function.handler',
    values: {
      function_name: 'handler',
      runtime: 'nodejs20.x',
      handler: 'index.handler',
      // Reference form — HCL wrote aws_iam_role.exec.arn
      role: 'aws_iam_role.exec',
    },
  } as unknown as TerraformResource;

  return [role, inlinePolicy, fn];
}

function run(allResources: TerraformResource[], address: string): ScanResult | null {
  const resource = allResources.find(r => r.address === address)!;
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 (Terraform) — wildcard action scoped to a named resource', () => {
  // Primary behaviour owned by this requirement: a wildcard action alone is not a violation.
  it('does not flag a Lambda execution role whose all-actions grant targets a specific named resource ARN', () => {
    const resources = buildResources('arn:aws:s3:::specific-app-bucket/*');

    expect(run(resources, 'aws_iam_role.exec')).toBeNull();
  });

  it('does not flag when the all-actions grant lists only specific named resource ARNs', () => {
    const resources = buildResources([
      'arn:aws:dynamodb:us-east-1:123456789012:table/orders',
      'arn:aws:sqs:us-east-1:123456789012:order-queue',
    ]);

    expect(run(resources, 'aws_iam_role.exec')).toBeNull();
  });

  // Opposite case: the nearest input that flips the verdict — resource scope widened to '*'.
  it('flags the same role when the all-actions grant is widened to all resources', () => {
    const resources = buildResources('*');

    const result = run(resources, 'aws_iam_role.exec');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.exec');
  });
});
