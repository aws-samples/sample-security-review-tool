import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (CloudFormation): Access logging configuration block is present on the
 * stage but contains no destination value (empty/missing destination).
 *
 * Expected behavior: FLAG. Per AWS docs, both DestinationArn and Format are
 * required to enable access logging. Without a destination, no logs are
 * actually delivered, so the stage should be treated as not having access
 * logging configured.
 */

const factory = new Apigw001CfnAdapterFactory();

function buildContext(template: Template, logicalId: string): CfnContext {
  const resource = (template.Resources as Record<string, any>)[logicalId];
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
}

describe('APIGW-001 REQ-07 (CFN): access logging block present but destination missing', () => {
  it('flags AWS::ApiGateway::Stage when AccessLogSetting has Format but no DestinationArn', () => {
    const template: Template = {
      Resources: {
        Stage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'Api',
            DeploymentId: 'Deployment',
            AccessLogSetting: {
              // DestinationArn intentionally omitted
              Format: '$context.requestId $context.identity.sourceIp',
            },
          },
        },
      },
    } as unknown as Template;

    const ctx = buildContext(template, 'Stage');
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
  });

  it('flags AWS::ApiGateway::Stage when AccessLogSetting has empty-string DestinationArn', () => {
    const template: Template = {
      Resources: {
        Stage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'Api',
            DeploymentId: 'Deployment',
            AccessLogSetting: {
              DestinationArn: '',
              Format: '$context.requestId',
            },
          },
        },
      },
    } as unknown as Template;

    const ctx = buildContext(template, 'Stage');
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
  });

  it('flags AWS::ApiGatewayV2::Stage when AccessLogSettings has Format but no DestinationArn', () => {
    const template: Template = {
      Resources: {
        Stage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            StageName: 'prod',
            ApiId: 'Api',
            AccessLogSettings: {
              // DestinationArn intentionally omitted
              Format: '$context.requestId',
            },
          },
        },
      },
    } as unknown as Template;

    const ctx = buildContext(template, 'Stage');
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
  });

  it('flags AWS::ApiGatewayV2::Stage when AccessLogSettings has empty-string DestinationArn', () => {
    const template: Template = {
      Resources: {
        Stage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            StageName: 'prod',
            ApiId: 'Api',
            AccessLogSettings: {
              DestinationArn: '',
              Format: '$context.requestId',
            },
          },
        },
      },
    } as unknown as Template;

    const ctx = buildContext(template, 'Stage');
    const adapter = factory.bind(ctx);
    const result = apigw001Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-001');
  });
});
