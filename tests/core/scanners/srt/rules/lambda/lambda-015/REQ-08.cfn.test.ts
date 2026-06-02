import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-015 REQ-08 [CFN] - Zip-package Lambda functions are out of scope', () => {
  const factory = new Lambda015CfnAdapterFactory();

  it('passes for AWS::Lambda::Function deployed as a zip archive (no Code.ImageUri)', () => {
    const template: Template = {
      Resources: {
        ZipFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-zip-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'SomeRole',
            PackageType: 'Zip',
            Code: {
              S3Bucket: 'my-deployment-bucket',
              S3Key: 'lambda/code.zip',
            },
          },
        },
      },
    };

    const resource = template.Resources!['ZipFunction']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'ZipFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes for AWS::Serverless::Function deployed as a zip archive (no ImageUri)', () => {
    const template: Template = {
      Resources: {
        SamZipFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            Runtime: 'python3.11',
            Handler: 'app.handler',
            CodeUri: 's3://my-bucket/code.zip',
            PackageType: 'Zip',
          },
        },
      },
    };

    const resource = template.Resources!['SamZipFunction']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'SamZipFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
