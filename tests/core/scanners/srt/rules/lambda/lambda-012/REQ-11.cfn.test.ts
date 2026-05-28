import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-11 (CFN): orphan/unused execution role', () => {
  it('passes when an execution role resource exists but is not referenced by any Lambda function', () => {
    // Template defines:
    //  - One Lambda function using its own dedicated role ("LambdaRole")
    //  - One unused/orphan IAM role ("UnusedRole") that no Lambda references
    // The orphan role has no Lambda consumers, so there is no sharing violation.
    const template: Template = {
      Resources: {
        LambdaRole: {
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
        UnusedRole: {
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
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
            // After preprocessing, !GetAtt LambdaRole.Arn becomes "LambdaRole"
            Role: 'LambdaRole',
          },
        },
      },
    } as unknown as Template;

    const factory = new Lambda012CfnAdapterFactory();
    const logicalId = 'MyFunction';
    const resource = template.Resources![logicalId];

    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(adapter.sharesExecutionRole).toBe(false);
    expect(result).toBeNull();
  });

  it('passes for AWS::Serverless::Function when an orphan execution role exists', () => {
    const template: Template = {
      Resources: {
        ServerlessRole: {
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
        OrphanRole: {
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
        MyServerlessFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            Runtime: 'python3.11',
            Handler: 'app.handler',
            CodeUri: 's3://bucket/code.zip',
            Role: 'ServerlessRole',
          },
        },
      },
    } as unknown as Template;

    const factory = new Lambda012CfnAdapterFactory();
    const logicalId = 'MyServerlessFunction';
    const resource = template.Resources![logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(adapter.sharesExecutionRole).toBe(false);
    expect(result).toBeNull();
  });
});
