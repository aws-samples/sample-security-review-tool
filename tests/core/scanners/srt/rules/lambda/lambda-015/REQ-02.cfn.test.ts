import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(template: Template, logicalId: string): CfnContext {
  const resource = template.Resources![logicalId];
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
}

describe('LAMBDA-015 REQ-02 (CloudFormation): case-insensitive match of "latest" must flag', () => {
  const factory = new Lambda015CfnAdapterFactory();

  it('flags AWS::Lambda::Function whose container image tag is "Latest" (mixed case)', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:Latest',
            },
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
          },
        },
      },
    };

    const ctx = buildContext(template, 'MyFunction');
    const adapter = factory.bind(ctx);
    const result = lambda015Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
    expect(result?.resourceName).toBe('MyFunction');
  });

  it('flags AWS::Lambda::Function whose container image tag is "LATEST" (all caps)', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:LATEST',
            },
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
          },
        },
      },
    };

    const ctx = buildContext(template, 'MyFunction');
    const adapter = factory.bind(ctx);
    const result = lambda015Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
  });

  it('flags AWS::Serverless::Function whose container image tag is "LaTeSt" (alternating case)', () => {
    const template: Template = {
      Resources: {
        MySamFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            PackageType: 'Image',
            ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:LaTeSt',
          },
        },
      },
    };

    const ctx = buildContext(template, 'MySamFunction');
    const adapter = factory.bind(ctx);
    const result = lambda015Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
    expect(result?.resourceName).toBe('MySamFunction');
  });
});
