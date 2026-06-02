import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const IMAGE_URI_WITH_LATEST_AND_DIGEST =
  '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:latest@sha256:abc123def4567890abc123def4567890abc123def4567890abc123def4567890';

function runControl(template: Template, logicalId: string) {
  const resource = template.Resources![logicalId]!;
  const factory = new Lambda015CfnAdapterFactory();
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context);
  return lambda015Control.run(adapter, context);
}

describe('LAMBDA-015 REQ-06 (CloudFormation): image URI with both latest tag and digest', () => {
  it('passes for AWS::Lambda::Function when ImageUri contains latest tag and digest', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: IMAGE_URI_WITH_LATEST_AND_DIGEST,
            },
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
          },
        },
      },
    };

    const result = runControl(template, 'MyFunction');
    expect(result).toBeNull();
  });

  it('passes for AWS::Serverless::Function when ImageUri contains latest tag and digest', () => {
    const template: Template = {
      Resources: {
        MyServerlessFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            PackageType: 'Image',
            ImageUri: IMAGE_URI_WITH_LATEST_AND_DIGEST,
          },
        },
      },
    };

    const result = runControl(template, 'MyServerlessFunction');
    expect(result).toBeNull();
  });
});
