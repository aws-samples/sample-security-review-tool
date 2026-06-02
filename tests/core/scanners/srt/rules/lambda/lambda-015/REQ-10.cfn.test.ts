import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-015 REQ-10 (CloudFormation): unresolvable image URI', () => {
  it('passes when AWS::Lambda::Function ImageUri is an unresolved Fn::ImportValue', () => {
    const template: Template = {
      Resources: {
        MyFn: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              // Fn::ImportValue is not resolved by preprocessing — remains as an opaque object.
              ImageUri: { 'Fn::ImportValue': 'SharedImageUriExport' },
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['MyFn'],
      logicalId: 'MyFn',
    };

    const factory = new Lambda015CfnAdapterFactory();
    expect(factory.appliesTo('AWS::Lambda::Function')).toBe(true);
    const adapter = factory.bind(context);

    const result = lambda015Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('passes when AWS::Serverless::Function ImageUri is an unresolved Fn::ImportValue', () => {
    const template: Template = {
      Resources: {
        MySamFn: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            PackageType: 'Image',
            ImageUri: { 'Fn::ImportValue': 'SharedImageUriExport' },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['MySamFn'],
      logicalId: 'MySamFn',
    };

    const factory = new Lambda015CfnAdapterFactory();
    const adapter = factory.bind(context);

    const result = lambda015Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
