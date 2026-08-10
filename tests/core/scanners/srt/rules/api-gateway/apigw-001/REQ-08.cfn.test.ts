import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (CloudFormation): Access log destination value depends on a condition or
 * input that cannot be resolved at analysis time.
 *
 * Expected behavior: PASS. The rule must not flag non-compliance when the
 * DestinationArn is an unresolved intrinsic (e.g. Fn::If, Fn::ImportValue),
 * because forcing a verdict from unknown configuration would produce false
 * positives.
 */
describe('APIGW-001 CFN — REQ-08: unresolvable access log destination', () => {
  const factory = new Apigw001CfnAdapterFactory();

  it('does NOT flag a v1 stage whose DestinationArn is an unresolved Fn::If', () => {
    const template: Template = {
      Resources: {
        Stage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'Api',
            DeploymentId: 'Deployment',
            AccessLogSetting: {
              DestinationArn: {
                'Fn::If': [
                  'UseSharedLogGroup',
                  { 'Fn::ImportValue': 'shared-log-group-arn' },
                  { 'Fn::GetAtt': ['LocalLogGroup', 'Arn'] },
                ],
              },
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const resource = template.Resources!['Stage']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'Stage',
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does NOT flag a v2 stage whose DestinationArn is an unresolved Fn::ImportValue', () => {
    const template: Template = {
      Resources: {
        HttpStage: {
          Type: 'AWS::ApiGatewayV2::Stage',
          Properties: {
            ApiId: 'HttpApi',
            StageName: '$default',
            AccessLogSettings: {
              DestinationArn: { 'Fn::ImportValue': 'cross-stack-access-log-group-arn' },
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const resource = template.Resources!['HttpStage']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'HttpStage',
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does NOT flag a v1 stage whose DestinationArn is an unresolved Fn::Join (object form)', () => {
    // Fn::Join that contains an Fn::ImportValue does not collapse during
    // preprocessing, so the rule sees an opaque object — must be treated as unknown.
    const template: Template = {
      Resources: {
        Stage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'Api',
            DeploymentId: 'Deployment',
            AccessLogSetting: {
              DestinationArn: {
                'Fn::Join': [
                  '',
                  [
                    'arn:aws:logs:us-east-1:123456789012:log-group:',
                    { 'Fn::ImportValue': 'shared-log-group-name' },
                  ],
                ],
              },
              Format: '$context.requestId',
            },
          },
        },
      },
    };

    const resource = template.Resources!['Stage']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'Stage',
    };

    const adapter = factory.bind(context);
    const result = apigw001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
