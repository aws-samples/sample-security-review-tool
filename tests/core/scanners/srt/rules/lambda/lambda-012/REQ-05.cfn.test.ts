import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-05 (CloudFormation)', () => {
  it('passes when the execution role is an external ARN not referenced by any other in-scope Lambda', () => {
    const externalRoleArn = 'arn:aws:iam::123456789012:role/ExternalSharedRole';

    const template = {
      Resources: {
        FunctionA: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'function-a',
            Role: externalRoleArn,
            Runtime: 'nodejs18.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        FunctionB: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'function-b',
            // Different role — no in-scope sharing
            Role: 'arn:aws:iam::123456789012:role/SomeOtherRole',
            Runtime: 'nodejs18.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
      },
    } as any;

    const factory = new Lambda012CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources.FunctionA,
      logicalId: 'FunctionA',
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes for a Serverless::Function that references an external role ARN unique within the template', () => {
    const externalRoleArn = 'arn:aws:iam::123456789012:role/PreExistingRole';

    const template = {
      Resources: {
        SamFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            FunctionName: 'sam-function',
            Role: externalRoleArn,
            Runtime: 'nodejs18.x',
            Handler: 'index.handler',
          },
        },
        OtherFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'other-function',
            Role: 'arn:aws:iam::123456789012:role/UnrelatedRole',
            Runtime: 'nodejs18.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
      },
    } as any;

    const factory = new Lambda012CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources.SamFunction,
      logicalId: 'SamFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
