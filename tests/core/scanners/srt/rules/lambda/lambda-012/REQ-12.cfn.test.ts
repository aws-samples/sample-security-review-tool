import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 [CFN] - Lambda functions must have unique IAM execution roles', () => {
  describe('Scenario: A single Lambda function references an execution role, and no other resource references that role', () => {
    it('should PASS for AWS::Lambda::Function whose role is not referenced by any other resource', () => {
      // After CFN preprocessing, !GetAtt MyLambdaRole.Arn resolves to the string "MyLambdaRole"
      const template = {
        Resources: {
          MyLambdaRole: {
            Type: 'AWS::IAM::Role',
            Properties: {
              AssumeRolePolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Principal: { Service: 'lambda.amazonaws.com' },
                    Action: 'sts:AssumeRole',
                  },
                ],
              },
            },
          },
          MyLambda: {
            Type: 'AWS::Lambda::Function',
            Properties: {
              FunctionName: 'my-function',
              Runtime: 'nodejs20.x',
              Handler: 'index.handler',
              Role: 'MyLambdaRole',
              Code: { ZipFile: 'exports.handler = async () => {};' },
            },
          },
          // An unrelated resource that does NOT reference MyLambdaRole
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              BucketName: 'unrelated-bucket',
            },
          },
        },
      } as unknown as Template;

      const factory = new Lambda012CfnAdapterFactory();
      const context: CfnContext = {
        stackName: 'test-stack',
        template,
        resource: template.Resources!.MyLambda,
        logicalId: 'MyLambda',
      };

      const adapter = factory.bind(context);
      const result = lambda012Control.run(adapter, context);

      expect(result).toBeNull();
    });

    it('should PASS for AWS::Serverless::Function whose role is not referenced by any other resource', () => {
      const template = {
        Resources: {
          MyLambdaRole: {
            Type: 'AWS::IAM::Role',
            Properties: {
              AssumeRolePolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Principal: { Service: 'lambda.amazonaws.com' },
                    Action: 'sts:AssumeRole',
                  },
                ],
              },
            },
          },
          MyServerlessLambda: {
            Type: 'AWS::Serverless::Function',
            Properties: {
              FunctionName: 'my-serverless-function',
              Runtime: 'nodejs20.x',
              Handler: 'index.handler',
              Role: 'MyLambdaRole',
              CodeUri: 's3://my-bucket/code.zip',
            },
          },
          UnrelatedQueue: {
            Type: 'AWS::SQS::Queue',
            Properties: {
              QueueName: 'unrelated-queue',
            },
          },
        },
      } as unknown as Template;

      const factory = new Lambda012CfnAdapterFactory();
      const context: CfnContext = {
        stackName: 'test-stack',
        template,
        resource: template.Resources!.MyServerlessLambda,
        logicalId: 'MyServerlessLambda',
      };

      const adapter = factory.bind(context);
      const result = lambda012Control.run(adapter, context);

      expect(result).toBeNull();
    });
  });
});
