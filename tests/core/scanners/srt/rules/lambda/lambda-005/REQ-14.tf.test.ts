import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const NARROW_DOCUMENT = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: ['logs:CreateLogStream', 'logs:PutLogEvents'],
      Resource: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/worker:*',
    },
  ],
});

const WILDCARD_DOCUMENT = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
});

const lambdaRole: TerraformResource = {
  type: 'aws_iam_role',
  name: 'lambda_exec',
  address: 'aws_iam_role.lambda_exec',
  values: { name: 'worker-exec-role' },
} as unknown as TerraformResource;

const pipelineRole: TerraformResource = {
  type: 'aws_iam_role',
  name: 'pipeline',
  address: 'aws_iam_role.pipeline',
  values: { name: 'pipeline-automation-role' },
} as unknown as TerraformResource;

const lambdaFunction: TerraformResource = {
  type: 'aws_lambda_function',
  name: 'worker',
  address: 'aws_lambda_function.worker',
  // Reference form: role = aws_iam_role.lambda_exec.arn collapses to the address.
  values: { function_name: 'worker', role: 'aws_iam_role.lambda_exec' },
} as unknown as TerraformResource;

const narrowRolePolicy: TerraformResource = {
  type: 'aws_iam_role_policy',
  name: 'lambda_logging',
  address: 'aws_iam_role_policy.lambda_logging',
  values: { name: 'narrow-logging', role: 'aws_iam_role.lambda_exec', policy: NARROW_DOCUMENT },
} as unknown as TerraformResource;

function broadRolePolicy(roleReference: string): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'broad_automation',
    address: 'aws_iam_role_policy.broad_automation',
    values: { name: 'broad-automation', role: roleReference, policy: WILDCARD_DOCUMENT },
  } as unknown as TerraformResource;
}

function evaluate(allResources: TerraformResource[], resource: TerraformResource) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = new Lambda005TfAdapterFactory().bind(context);
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 REQ-14 (Terraform): wildcard policy bound to a different identity', () => {
  // Primary behavior owned by REQ-14: a wildcard document bound to another role
  // confers no privilege on the assessed Lambda execution role.
  it('passes the Lambda execution role when the wildcard policy is bound to a different role', () => {
    const resources = [
      lambdaRole,
      pipelineRole,
      lambdaFunction,
      narrowRolePolicy,
      broadRolePolicy('aws_iam_role.pipeline'),
    ];

    expect(evaluate(resources, lambdaRole)).toBeNull();
  });

  // Opposite outcome: only the binding of the wildcard document changes.
  it('flags the Lambda execution role when the same wildcard policy is bound to it', () => {
    const resources = [
      lambdaRole,
      pipelineRole,
      lambdaFunction,
      narrowRolePolicy,
      broadRolePolicy('aws_iam_role.lambda_exec'),
    ];

    const result = evaluate(resources, lambdaRole);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.lambda_exec');
  });
});
