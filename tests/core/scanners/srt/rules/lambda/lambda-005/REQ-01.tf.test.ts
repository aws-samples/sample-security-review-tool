import { describe, it, expect } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * LAMBDA-005 / REQ-01
 *
 * Requirement owning the primary behavior asserted here:
 *   A Lambda execution role with no permission grants of any kind — no
 *   aws_iam_role_policy inline documents, no inline_policy blocks, no
 *   aws_iam_role_policy_attachment / aws_iam_policy_attachment — confers no
 *   privileges, so the control must PASS (return null).
 *
 * The discriminating (opposite) test keeps the same role/function wiring and only
 * adds the thing the requirement turns on: an over-broad permission grant.
 */

const ASSUME_ROLE_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Principal: { Service: 'lambda.amazonaws.com' },
      Action: 'sts:AssumeRole',
    },
  ],
});

const execRole = {
  type: 'aws_iam_role',
  name: 'exec',
  address: 'aws_iam_role.exec',
  values: {
    name: 'my-function-exec-role',
    assume_role_policy: ASSUME_ROLE_POLICY,
  },
} as unknown as TerraformResource;

// Reference form: role = aws_iam_role.exec.arn in HCL collapses to the address.
const lambdaFunction = {
  type: 'aws_lambda_function',
  name: 'fn',
  address: 'aws_lambda_function.fn',
  values: {
    function_name: 'my-function',
    handler: 'index.handler',
    runtime: 'nodejs20.x',
    role: 'aws_iam_role.exec',
  },
} as unknown as TerraformResource;

function run(allResources: TerraformResource[], target: TerraformResource): ScanResult | null {
  const factory = new Lambda005TfAdapterFactory();
  expect(factory.appliesTo(target.type)).toBe(true);
  const context: TfContext = {
    projectName: 'test-project',
    resource: target,
    allResources,
  };
  const adapter = factory.bind(context);
  return lambda005Control.run(adapter as never, context);
}

describe('LAMBDA-005 REQ-01 (Terraform): execution role with no permission grants', () => {
  it('passes when no inline role policy and no policy attachment reference the execution role', () => {
    const resources = [execRole, lambdaFunction];

    expect(run(resources, execRole)).toBeNull();
  });

  it('passes when grants exist in the plan but none of them reference this execution role', () => {
    const otherRole = {
      type: 'aws_iam_role',
      name: 'other',
      address: 'aws_iam_role.other',
      values: { name: 'other-role', assume_role_policy: ASSUME_ROLE_POLICY },
    } as unknown as TerraformResource;

    const otherRolePolicy = {
      type: 'aws_iam_role_policy',
      name: 'other_inline',
      address: 'aws_iam_role_policy.other_inline',
      values: {
        role: 'aws_iam_role.other',
        policy: JSON.stringify({
          Version: '2012-10-17',
          Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
        }),
      },
    } as unknown as TerraformResource;

    const resources = [execRole, lambdaFunction, otherRole, otherRolePolicy];

    expect(run(resources, execRole)).toBeNull();
  });

  // OPPOSITE CASE — owned by the wildcard-inline-policy requirement.
  // Same role and function; the only change is that a grant now exists on this role
  // (reference form: role = aws_iam_role.exec.name) and it is over-broad.
  it('flags the same role when an inline role policy grants wildcard action on wildcard resource', () => {
    const wildcardInline = {
      type: 'aws_iam_role_policy',
      name: 'inline',
      address: 'aws_iam_role_policy.inline',
      values: {
        role: 'aws_iam_role.exec',
        policy: JSON.stringify({
          Version: '2012-10-17',
          Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
        }),
      },
    } as unknown as TerraformResource;

    const resources = [execRole, lambdaFunction, wildcardInline];

    const result = run(resources, execRole);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
  });
});
