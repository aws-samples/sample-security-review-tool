import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const DIGEST = 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const IMAGE_URI_WITH_DIGEST = `123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app@${DIGEST}`;

function runControl(template: Template, logicalId: string) {
  const factory = new Lambda015CfnAdapterFactory();
  const resource = template.Resources![logicalId];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context);
  return lambda015Control.run(adapter, context);
}

describe('LAMBDA-015 REQ-05 (CFN): container image pinned by digest with no tag', () => {
  it('passes for AWS::Lambda::Function whose Code.ImageUri pins by digest', () => {
    const template: Template = {
      Resources: {
        MyFn: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: IMAGE_URI_WITH_DIGEST,
            },
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
          },
        },
      },
    };

    const result = runControl(template, 'MyFn');
    expect(result).toBeNull();
  });

  it('passes for AWS::Serverless::Function whose ImageUri pins by digest', () => {
    const template: Template = {
      Resources: {
        MySamFn: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            PackageType: 'Image',
            ImageUri: IMAGE_URI_WITH_DIGEST,
          },
        },
      },
    };

    const result = runControl(template, 'MySamFn');
    expect(result).toBeNull();
  });
});
