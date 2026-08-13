import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-04 (LAMBDA-005): A Lambda execution role whose policy allows a service-prefixed
 * wildcard action (e.g. "s3:*") on "Resource": "*" must be flagged as the
 * wildcard-action / wildcard-resource anti-pattern.
 */

const factory = new Lambda005TfAdapterFactory();

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'exec',
  address: 'aws_iam_role.exec',
  values: {
    name: 'processor-exec-role',
    assume_role_policy: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        { Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' },
      ],
    }),
  },
} as unknown as TerraformResource;

// Reference form: HCL had `role = aws_iam_role.exec.arn`, collapsed to the role address.
const lambdaFunction: TerraformResource = {
  type: 'aws_lambda_function',
  name: 'processor',
  address: 'aws_lambda_function.processor',
  values: {
    function_name: 'processor',
    runtime: 'nodejs20.x',
    handler: 'index.handler',
    role: 'aws_iam_role.exec',
  },
} as unknown as TerraformResource;

/** Reference form: HCL had `role = aws_iam_role.exec.id`. */
function rolePolicy(statement: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'function_permissions',
    address: 'aws_iam_role_policy.function_permissions',
    values: {
      name: 'function-permissions',
      role: 'aws_iam_role.exec',
      policy: JSON.stringify({ Version: '2012-10-17', Statement: [statement] }),
    },
  } as unknown as TerraformResource;
}

function runOnRole(policy: TerraformResource) {
  const allResources = [role, lambdaFunction, policy];
  const context: TfContext = {
    projectName: 'lambda-005-req-04',
    resource: role,
    allResources,
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 REQ-04 (Terraform): service-prefixed wildcard action on all resources', () => {
  it('flags an execution role granting "s3:*" on "Resource": "*"', () => {
    const result = runOnRole(
      rolePolicy({ Effect: 'Allow', Action: 's3:*', Resource: '*' }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.exec');
    expect(result?.resourceType).toBe('aws_iam_role');
  });

  it('flags the same grant when "s3:*" appears inside an Action array on "Resource": "*"', () => {
    const result = runOnRole(
      rolePolicy({ Effect: 'Allow', Action: ['logs:CreateLogStream', 's3:*'], Resource: ['*'] }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
  });

  // Opposite outcome: the service-prefixed wildcard action remains, but it is no longer
  // paired with a wildcard resource, so this requirement's violation does not hold.
  it('does not flag "s3:*" scoped to a specific resource ARN', () => {
    const result = runOnRole(
      rolePolicy({ Effect: 'Allow', Action: 's3:*', Resource: 'arn:aws:s3:::my-app-bucket/*' }),
    );

    expect(result).toBeNull();
  });
});
