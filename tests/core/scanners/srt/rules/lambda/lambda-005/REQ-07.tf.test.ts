import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (LAMBDA-005): a Lambda execution role that grants "everything except a
 * short list of excluded actions" (NotAction) on every resource ("*") is an
 * over-broad grant and must be flagged.
 */

const factory = new Lambda005TfAdapterFactory();

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'fn_role',
  address: 'aws_iam_role.fn_role',
  values: {
    name: 'processor-execution-role',
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

const lambdaFunction: TerraformResource = {
  type: 'aws_lambda_function',
  name: 'processor',
  address: 'aws_lambda_function.processor',
  values: {
    function_name: 'processor',
    handler: 'index.handler',
    runtime: 'nodejs20.x',
    // role = aws_iam_role.fn_role.arn collapses to the resource address.
    role: 'aws_iam_role.fn_role',
  },
} as unknown as TerraformResource;

function rolePolicy(statement: unknown, roleReference: string): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'fn_permissions',
    address: 'aws_iam_role_policy.fn_permissions',
    values: {
      name: 'function-permissions',
      role: roleReference,
      policy: JSON.stringify({ Version: '2012-10-17', Statement: [statement] }),
    },
  } as unknown as TerraformResource;
}

function runControl(resources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: role,
    allResources: resources,
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

const NOT_ACTION_ALL_RESOURCES = {
  Effect: 'Allow',
  NotAction: ['iam:*', 'organizations:*', 'account:*'],
  Resource: '*',
};

describe('LAMBDA-005 REQ-07 (Terraform): NotAction grant on all resources', () => {
  it('flags an execution role whose policy allows all actions except a few, on all resources (reference form)', () => {
    const policy = rolePolicy(NOT_ACTION_ALL_RESOURCES, 'aws_iam_role.fn_role');

    const result = runControl([role, lambdaFunction, policy]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.fn_role');
  });

  it('flags the same NotAction grant when the policy wires the role by literal name', () => {
    const policy = rolePolicy(NOT_ACTION_ALL_RESOURCES, 'processor-execution-role');

    const result = runControl([role, lambdaFunction, policy]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
  });

  // Opposite outcome: the same "all actions except a few" grant, but scoped to
  // specific resource ARNs instead of every resource. The wildcard-resource
  // pairing this requirement turns on is absent, so no finding is expected.
  it('does not flag a NotAction grant that is limited to specific resource ARNs', () => {
    const policy = rolePolicy(
      {
        Effect: 'Allow',
        NotAction: ['iam:*', 'organizations:*', 'account:*'],
        Resource: [
          'arn:aws:s3:::app-data-bucket',
          'arn:aws:s3:::app-data-bucket/*',
        ],
      },
      'aws_iam_role.fn_role',
    );

    const result = runControl([role, lambdaFunction, policy]);

    expect(result).toBeNull();
  });
});
