import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-015 CloudFormation - REQ-11: unresolvable tag with known repository', () => {
  it('passes when AWS::Lambda::Function ImageUri has a known repository but the tag is supplied by an unresolvable Fn::ImportValue', () => {
    // The ImageUri field is a Fn::Join whose final segment (the tag) is an
    // unresolved Fn::ImportValue. The preprocessor cannot collapse this to a
    // string, so the rule sees an opaque object — neither a literal string
    // nor an Fn::If — and must treat the tag as unknown.
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: {
                'Fn::Join': [
                  ':',
                  [
                    '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app',
                    { 'Fn::ImportValue': 'SharedImageTagExport' },
                  ],
                ],
              },
            },
          },
        },
      },
    };

    const factory = new Lambda015CfnAdapterFactory();
    const resource = template.Resources!.MyFunction;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when AWS::Serverless::Function ImageUri has a known repository but the tag is supplied by an unresolvable Fn::ImportValue', () => {
    const template: Template = {
      Resources: {
        MyServerlessFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            PackageType: 'Image',
            ImageUri: {
              'Fn::Join': [
                ':',
                [
                  '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app',
                  { 'Fn::ImportValue': 'SharedImageTagExport' },
                ],
              ],
            },
          },
        },
      },
    };

    const factory = new Lambda015CfnAdapterFactory();
    const resource = template.Resources!.MyServerlessFunction;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyServerlessFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
