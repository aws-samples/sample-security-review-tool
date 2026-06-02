import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STACK_NAME = 'test-stack';

function buildContext(template: Template, logicalId: string): CfnContext {
  const resource = template.Resources![logicalId];
  return { stackName: STACK_NAME, template, resource, logicalId };
}

function runControl(template: Template, logicalId: string) {
  const factory = new Lambda015CfnAdapterFactory();
  const ctx = buildContext(template, logicalId);
  const adapter = factory.bind(ctx);
  return lambda015Control.run(adapter, ctx);
}

describe('LAMBDA-015 REQ-04 (CloudFormation): Container image with specific non-latest tag passes', () => {
  it('passes when AWS::Lambda::Function uses a semantic version tag', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:1.2.3',
            },
            Role: 'arn:aws:iam::123456789012:role/my-role',
          },
        },
      },
    };

    const result = runControl(template, 'MyFunction');
    expect(result).toBeNull();
  });

  it('passes when AWS::Lambda::Function uses a build-number tag', () => {
    const template: Template = {
      Resources: {
        BuildFn: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:build-4567',
            },
            Role: 'arn:aws:iam::123456789012:role/my-role',
          },
        },
      },
    };

    const result = runControl(template, 'BuildFn');
    expect(result).toBeNull();
  });

  it('passes when AWS::Lambda::Function uses a commit SHA tag', () => {
    const template: Template = {
      Resources: {
        ShaFn: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:sha-a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
            },
            Role: 'arn:aws:iam::123456789012:role/my-role',
          },
        },
      },
    };

    const result = runControl(template, 'ShaFn');
    expect(result).toBeNull();
  });

  it('passes when AWS::Serverless::Function uses a specific version tag', () => {
    const template: Template = {
      Resources: {
        SamFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            PackageType: 'Image',
            ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v2.0.1',
          },
        },
      },
    };

    const result = runControl(template, 'SamFunction');
    expect(result).toBeNull();
  });
});
