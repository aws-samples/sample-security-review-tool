import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-03 (CloudFormation): Lambda function uses a container image reference that
 * includes a repository but no tag and no digest. The OCI/Docker convention is
 * to default to 'latest' at pull time, so the rule must flag this as an
 * implicit 'latest' reference.
 */
describe('LAMBDA-015 REQ-03 (CloudFormation): untagged image reference is flagged as implicit latest', () => {
  const factory = new Lambda015CfnAdapterFactory();

  function runControl(resourceType: string, properties: Record<string, unknown>) {
    const logicalId = 'MyFunction';
    const template: Template = {
      Resources: {
        [logicalId]: {
          Type: resourceType,
          Properties: properties,
        },
      },
    } as unknown as Template;

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources![logicalId],
      logicalId,
    };

    const adapter = factory.bind(context);
    return lambda015Control.run(adapter, context);
  }

  it('flags AWS::Lambda::Function when ImageUri references an ECR repository with no tag and no digest', () => {
    const result = runControl('AWS::Lambda::Function', {
      PackageType: 'Image',
      Code: {
        ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo',
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
  });

  it('flags AWS::Serverless::Function when ImageUri references a repository with no tag and no digest', () => {
    const result = runControl('AWS::Serverless::Function', {
      PackageType: 'Image',
      ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
  });
});
