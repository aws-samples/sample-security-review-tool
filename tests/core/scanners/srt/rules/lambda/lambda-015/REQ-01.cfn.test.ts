import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-015 REQ-01 (CloudFormation): container image using latest tag', () => {
  it('flags AWS::Lambda::Function whose container image reference uses the lowercase :latest tag', () => {
    const template: Template = {
      Resources: {
        ContainerFn: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:latest',
            },
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
          },
        },
      },
    };

    const factory = new Lambda015CfnAdapterFactory();
    const resource = template.Resources!['ContainerFn'];
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'ContainerFn',
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
    expect(result?.resourceType).toBe('AWS::Lambda::Function');
    expect(result?.resourceName).toBe('ContainerFn');
    expect(result?.status).toBe('Open');
  });

  it('flags AWS::Serverless::Function whose container image reference uses the lowercase :latest tag', () => {
    const template: Template = {
      Resources: {
        SamContainerFn: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            PackageType: 'Image',
            ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-sam-app:latest',
          },
        },
      },
    };

    const factory = new Lambda015CfnAdapterFactory();
    const resource = template.Resources!['SamContainerFn'];
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'SamContainerFn',
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
    expect(result?.resourceType).toBe('AWS::Serverless::Function');
    expect(result?.resourceName).toBe('SamContainerFn');
    expect(result?.status).toBe('Open');
  });
});
