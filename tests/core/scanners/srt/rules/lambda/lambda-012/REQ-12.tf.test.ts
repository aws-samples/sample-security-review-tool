import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 [TF] - Lambda functions must have unique IAM execution roles', () => {
  describe('Scenario: A single Lambda function references an execution role, and no other resource references that role', () => {
    it('should PASS for aws_lambda_function whose role is not referenced by any other resource', () => {
      const roleArn = 'arn:aws:iam::123456789012:role/my-lambda-role';

      const lambda = {
        address: 'aws_lambda_function.my_lambda',
        type: 'aws_lambda_function',
        name: 'my_lambda',
        values: {
          function_name: 'my-function',
          runtime: 'nodejs20.x',
          handler: 'index.handler',
          role: roleArn,
        },
      } as unknown as TerraformResource;

      const role = {
        address: 'aws_iam_role.my_lambda_role',
        type: 'aws_iam_role',
        name: 'my_lambda_role',
        values: {
          name: 'my-lambda-role',
          arn: roleArn,
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

      // An unrelated resource that does NOT reference the role ARN anywhere
      const unrelatedBucket = {
        address: 'aws_s3_bucket.unrelated',
        type: 'aws_s3_bucket',
        name: 'unrelated',
        values: {
          bucket: 'unrelated-bucket',
        },
      } as unknown as TerraformResource;

      const allResources = [lambda, role, unrelatedBucket];

      const factory = new Lambda012TfAdapterFactory();
      const context: TfContext = {
        projectName: 'test-project',
        resource: lambda,
        allResources,
      };

      const adapter = factory.bind(context);
      const result = lambda012Control.run(adapter, context);

      expect(result).toBeNull();
    });
  });
});
