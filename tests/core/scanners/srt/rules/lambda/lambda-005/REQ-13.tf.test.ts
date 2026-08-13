import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (LAMBDA-005): a separately declared aws_iam_role_policy bound to the assessed
 * Lambda execution role must be resolved and evaluated as if the grant were embedded
 * in the role itself.
 *
 * Cross-resource references have already been collapsed by the plan reader to the
 * target resource address (e.g. "aws_iam_role.exec").
 */

const factory = new Lambda005TfAdapterFactory();

const WILDCARD_POLICY_JSON = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
});

const SCOPED_POLICY_JSON = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: ['s3:GetObject'], Resource: ['arn:aws:s3:::app-bucket/*'] },
  ],
});

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'exec',
  address: 'aws_iam_role.exec',
  values: {
    name: 'processor-exec-role',
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
    role: 'aws_iam_role.exec',
  },
} as unknown as TerraformResource;

function standalonePolicy(policyJson: string, roleReference: string): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'exec_permissions',
    address: 'aws_iam_role_policy.exec_permissions',
    values: {
      name: 'exec-permissions',
      role: roleReference,
      policy: policyJson,
    },
  } as unknown as TerraformResource;
}

function run(allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: role,
    allResources,
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 REQ-13 (Terraform): standalone role policy bound to the Lambda execution role', () => {
  it('flags the execution role when a separately declared aws_iam_role_policy referencing it allows all actions on all resources', () => {
    const result = run([role, lambdaFunction, standalonePolicy(WILDCARD_POLICY_JSON, 'aws_iam_role.exec')]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.exec');
    expect(result?.resourceType).toBe('aws_iam_role');
  });

  it('flags the execution role when the standalone policy is bound by literal role name instead of a reference', () => {
    const result = run([role, lambdaFunction, standalonePolicy(WILDCARD_POLICY_JSON, 'processor-exec-role')]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
  });

  // Opposite outcome: the binding is identical, only the grant is narrowed.
  it('does not flag the execution role when the separately declared policy grants only specific actions and resource ARNs', () => {
    const result = run([role, lambdaFunction, standalonePolicy(SCOPED_POLICY_JSON, 'aws_iam_role.exec')]);

    expect(result).toBeNull();
  });
});
