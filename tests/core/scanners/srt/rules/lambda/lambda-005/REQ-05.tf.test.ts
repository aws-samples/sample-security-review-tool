import { describe, it, expect } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { TfContext, TerraformResource, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (LAMBDA-005): A Lambda execution role permission grant that covers every
 * resource (`Resource: "*"`) must be flagged even when the action list is a small set
 * of explicitly named actions — resource scoping is an independent requirement.
 */

const factory = new Lambda005TfAdapterFactory();

function runControl(allResources: TerraformResource[], address: string): ScanResult | null {
  const resource = allResources.find(r => r.address === address)!;
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  return lambda005Control.run(factory.bind(context), context);
}

function policyJson(resource: string): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:PutObject'],
        Resource: resource,
      },
    ],
  });
}

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'fn_role',
  address: 'aws_iam_role.fn_role',
  values: { name: 'fn-exec-role' },
} as unknown as TerraformResource;

function lambdaFunction(roleRef: string): TerraformResource {
  return {
    type: 'aws_lambda_function',
    name: 'fn',
    address: 'aws_lambda_function.fn',
    values: { function_name: 'my-fn', role: roleRef, runtime: 'nodejs20.x' },
  } as unknown as TerraformResource;
}

function rolePolicy(roleRef: string, resource: string): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'fn_policy',
    address: 'aws_iam_role_policy.fn_policy',
    values: { name: 'fn-policy', role: roleRef, policy: policyJson(resource) },
  } as unknown as TerraformResource;
}

describe('LAMBDA-005 REQ-05 (Terraform): named actions on all resources', () => {
  it('flags an execution role whose policy grants named actions on Resource "*" (reference form)', () => {
    const result = runControl(
      [
        role,
        lambdaFunction('aws_iam_role.fn_role'),
        rolePolicy('aws_iam_role.fn_role', '*'),
      ],
      'aws_iam_role.fn_role',
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.fn_role');
  });

  it('flags the same grant when the role is wired by literal name', () => {
    const result = runControl(
      [role, lambdaFunction('fn-exec-role'), rolePolicy('fn-exec-role', '*')],
      'aws_iam_role.fn_role',
    );

    expect(result).not.toBeNull();
  });

  // Opposite outcome: same named actions, but the resource scope is a specific ARN.
  it('does not flag the same named actions when scoped to a specific resource ARN', () => {
    const result = runControl(
      [
        role,
        lambdaFunction('aws_iam_role.fn_role'),
        rolePolicy('aws_iam_role.fn_role', 'arn:aws:s3:::my-app-bucket/*'),
      ],
      'aws_iam_role.fn_role',
    );

    expect(result).toBeNull();
  });
});
