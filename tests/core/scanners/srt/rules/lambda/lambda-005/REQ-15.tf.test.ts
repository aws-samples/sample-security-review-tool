import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda005TfAdapterFactory();

const WILDCARD_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
});

const EC2_TRUST_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Principal: { Service: 'ec2.amazonaws.com' },
      Action: 'sts:AssumeRole',
    },
  ],
});

/** Role granting all actions on all resources, trusted only by EC2 (a non-serverless-compute principal). */
function ec2TrustedWildcardRole(): TerraformResource {
  return {
    type: 'aws_iam_role',
    name: 'wildcard',
    address: 'aws_iam_role.wildcard',
    values: {
      name: 'wildcard-role',
      assume_role_policy: EC2_TRUST_POLICY,
      inline_policy: [{ name: 'everything', policy: WILDCARD_POLICY }],
    },
  } as unknown as TerraformResource;
}

function runControl(allResources: TerraformResource[], target: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: target,
    allResources,
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 (Terraform) — REQ-15: wildcard role outside serverless-function scope', () => {
  it('passes a wildcard-granting role that is trusted by EC2 and not used as any function execution role', () => {
    const role = ec2TrustedWildcardRole();
    const instanceProfile = {
      type: 'aws_iam_instance_profile',
      name: 'app',
      address: 'aws_iam_instance_profile.app',
      values: { name: 'app-profile', role: 'aws_iam_role.wildcard' },
    } as unknown as TerraformResource;

    expect(runControl([role, instanceProfile], role)).toBeNull();
  });

  // Opposite outcome: the primary wildcard-grant behavior of LAMBDA-005 owns this case.
  it('flags the identical wildcard-granting role once a serverless function references it as its execution role', () => {
    const role = ec2TrustedWildcardRole();
    // Reference form — HCL wrote `role = aws_iam_role.wildcard.arn`.
    const fn = {
      type: 'aws_lambda_function',
      name: 'app',
      address: 'aws_lambda_function.app',
      values: {
        function_name: 'app-fn',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'aws_iam_role.wildcard',
      },
    } as unknown as TerraformResource;

    const result = runControl([role, fn], role);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.wildcard');
  });

  // Lambda cannot assume a role unless its trust policy names lambda.amazonaws.com, so the trust
  // policy puts a role in scope on its own — no function need appear in the plan.
  it('flags a wildcard-granting role trusted by Lambda even when no function references it', () => {
    const role = ec2TrustedWildcardRole();
    (role as any).values.assume_role_policy = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'lambda.amazonaws.com' },
          Action: 'sts:AssumeRole',
        },
      ],
    });

    const result = runControl([role], role);
    expect(result).not.toBeNull();
    expect(result?.resourceName).toBe('aws_iam_role.wildcard');
  });
});
