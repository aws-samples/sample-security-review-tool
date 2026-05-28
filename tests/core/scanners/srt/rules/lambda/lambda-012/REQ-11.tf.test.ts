import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-11 (TF): orphan/unused execution role', () => {
  it('passes when an IAM role resource exists but is not referenced by any aws_lambda_function', () => {
    // Plan defines:
    //  - One Lambda function referencing an externally-managed role ARN
    //    (no resource in this plan owns that ARN, so the role isn't "shared" with any sibling)
    //  - One unused/orphan aws_iam_role with a different ARN that no Lambda references
    // The orphan role has no Lambda consumers, so there is no sharing violation to flag.
    const lambdaResource: TerraformResource = {
      address: 'aws_lambda_function.my_function',
      type: 'aws_lambda_function',
      name: 'my_function',
      values: {
        function_name: 'my-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/external-lambda-role',
      },
    } as unknown as TerraformResource;

    const orphanRoleResource: TerraformResource = {
      address: 'aws_iam_role.unused_role',
      type: 'aws_iam_role',
      name: 'unused_role',
      values: {
        name: 'unused-role',
        arn: 'arn:aws:iam::123456789012:role/unused-role',
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

    const allResources: TerraformResource[] = [lambdaResource, orphanRoleResource];

    const factory = new Lambda012TfAdapterFactory();
    expect(factory.appliesTo(lambdaResource.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(adapter.sharesExecutionRole).toBe(false);
    expect(result).toBeNull();
  });
});
