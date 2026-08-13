import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (LAMBDA-005): A Lambda execution role attached to a service-wide
 * full-access predefined managed policy (e.g. AmazonDynamoDBFullAccess) must be
 * flagged, because such a policy grants every action of that service over all of
 * its resources — more than the specific actions/resources the function requires.
 */

const factory = new Lambda005TfAdapterFactory();

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'fn',
  address: 'aws_iam_role.fn',
  values: {
    name: 'fn-exec-role',
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

const lambdaFn: TerraformResource = {
  type: 'aws_lambda_function',
  name: 'fn',
  address: 'aws_lambda_function.fn',
  values: {
    function_name: 'fn',
    // reference form: role = aws_iam_role.fn.arn
    role: 'aws_iam_role.fn',
    handler: 'index.handler',
    runtime: 'nodejs20.x',
  },
} as unknown as TerraformResource;

function attachment(roleRef: string, policyArn: string): TerraformResource {
  return {
    type: 'aws_iam_role_policy_attachment',
    name: 'attach',
    address: 'aws_iam_role_policy_attachment.attach',
    values: { role: roleRef, policy_arn: policyArn },
  } as unknown as TerraformResource;
}

function runOnRole(extra: TerraformResource[]) {
  const allResources = [role, lambdaFn, ...extra];
  const context: TfContext = {
    projectName: 'test-project',
    resource: role,
    allResources,
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 REQ-10 (Terraform)', () => {
  it('flags a Lambda execution role attached (reference form) to a service-wide full-access policy', () => {
    const result = runOnRole([
      attachment('aws_iam_role.fn', 'arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess'),
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.fn');
    expect(result?.resourceType).toBe('aws_iam_role');
  });

  it('flags a Lambda execution role attached (literal role name) to a service-wide full-access policy', () => {
    const result = runOnRole([
      attachment('fn-exec-role', 'arn:aws:iam::aws:policy/AmazonS3FullAccess'),
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
  });

  // Opposite outcome: identical wiring, but the attached predefined policy is
  // narrowly scoped rather than a service-wide full-access set.
  it('does not flag a Lambda execution role attached to a narrowly scoped managed policy', () => {
    const result = runOnRole([
      attachment(
        'aws_iam_role.fn',
        'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
      ),
    ]);

    expect(result).toBeNull();
  });
});
