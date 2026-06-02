import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda015CfnAdapterFactory();

function buildContext(template: Template, logicalId: string): CfnContext {
  const resource = template.Resources![logicalId];
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
}

describe('LAMBDA-015 (CFN) - container image deployment with no image reference at all', () => {
  it('passes for AWS::Lambda::Function configured for container image (PackageType: Image) but with no Code.ImageUri', () => {
    const template: Template = {
      Resources: {
        ContainerFn: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: {},
          },
        },
      },
    };

    const context = buildContext(template, 'ContainerFn');
    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes for AWS::Lambda::Function with PackageType Image and no Code property at all', () => {
    const template: Template = {
      Resources: {
        ContainerFn: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
          },
        },
      },
    };

    const context = buildContext(template, 'ContainerFn');
    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes for AWS::Serverless::Function with PackageType Image but no ImageUri property', () => {
    const template: Template = {
      Resources: {
        ServerlessContainerFn: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            PackageType: 'Image',
          },
        },
      },
    };

    const context = buildContext(template, 'ServerlessContainerFn');
    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
