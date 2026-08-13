import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (LAMBDA-005): a wildcard-action/wildcard-resource statement whose Effect is
 * Deny grants no privilege and must NOT be flagged. The Allow variant of the same
 * statement is owned by the primary wildcard-grant requirement and is included here
 * only as the opposite-outcome case.
 */

const factory = new Lambda005TfAdapterFactory();

function policyDocument(wildcardEffect: 'Deny' | 'Allow'): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        // The statement under test: every action on every resource.
        Effect: wildcardEffect,
        Action: '*',
        Resource: '*',
      },
      {
        // A narrowly scoped permitting statement.
        Effect: 'Allow',
        Action: ['logs:PutLogEvents'],
        Resource: ['arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/fn:*'],
      },
    ],
  });
}

function buildResources(wildcardEffect: 'Deny' | 'Allow'): TerraformResource[] {
  const role: TerraformResource = {
    type: 'aws_iam_role',
    name: 'exec',
    address: 'aws_iam_role.exec',
    values: {
      name: 'fn-exec-role',
      inline_policy: [{ name: 'inline', policy: policyDocument(wildcardEffect) }],
    },
  } as unknown as TerraformResource;

  const fn: TerraformResource = {
    type: 'aws_lambda_function',
    name: 'fn',
    address: 'aws_lambda_function.fn',
    values: {
      function_name: 'fn',
      // Reference form: role = aws_iam_role.exec.arn collapses to the address.
      role: 'aws_iam_role.exec',
    },
  } as unknown as TerraformResource;

  return [role, fn];
}

function runRole(resources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: resources[0]!,
    allResources: resources,
  };
  return lambda005Control.run(factory.bind(context), context);
}

describe('LAMBDA-005 REQ-06 (Terraform)', () => {
  it('passes when the Lambda execution role denies all actions on all resources', () => {
    expect(runRole(buildResources('Deny'))).toBeNull();
  });

  // Opposite outcome: the same statement as a grant is over-permissive.
  it('flags the same statement when its effect permits all actions on all resources', () => {
    const result = runRole(buildResources('Allow'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.exec');
  });
});
