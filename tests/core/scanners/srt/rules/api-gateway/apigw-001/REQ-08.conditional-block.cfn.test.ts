import { describe, it, expect } from 'vitest';
import { apigw001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-001/apigw-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (CloudFormation), Fn::If wrapping the whole access-log block.
 *
 * The other REQ-08 cases put the intrinsic inside DestinationArn. Real templates
 * more often make the entire block conditional and drop it with AWS::NoValue:
 *   AccessLogSetting: !If [Cond, {DestinationArn, Format}, !Ref AWS::NoValue]
 * Expected behavior is still PASS — a branch that configures logging means the
 * stage is not provably non-compliant.
 */
describe('APIGW-001 CFN — REQ-08: Fn::If around the whole access-log block', () => {
  const factory = new Apigw001CfnAdapterFactory();

  const evaluate = (properties: Record<string, unknown>, type = 'AWS::ApiGateway::Stage') => {
    const template = { Resources: { Stage: { Type: type, Properties: properties } } } as unknown as Template;
    const resource = template.Resources!['Stage']!;
    const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId: 'Stage' };
    return apigw001Control.run(factory.bind(context), context);
  };

  const logGroup = {
    DestinationArn: { 'Fn::GetAtt': ['AccessLogGroup', 'Arn'] },
    Format: '$context.requestId',
  };

  it('does NOT flag a v1 stage whose AccessLogSetting is an Fn::If with AWS::NoValue', () => {
    const result = evaluate({
      StageName: 'prod',
      RestApiId: 'Api',
      DeploymentId: 'Deployment',
      AccessLogSetting: { 'Fn::If': ['EnableApiAccessLogs', logGroup, { Ref: 'AWS::NoValue' }] },
    });

    expect(result).toBeNull();
  });

  it('does NOT flag a v2 stage whose AccessLogSettings is an Fn::If with AWS::NoValue', () => {
    const result = evaluate(
      {
        ApiId: 'HttpApi',
        StageName: '$default',
        AccessLogSettings: { 'Fn::If': ['EnableApiAccessLogs', logGroup, { Ref: 'AWS::NoValue' }] },
      },
      'AWS::ApiGatewayV2::Stage',
    );

    expect(result).toBeNull();
  });

  it('does NOT flag when the configured branch is the else-branch', () => {
    const result = evaluate({
      StageName: 'prod',
      RestApiId: 'Api',
      DeploymentId: 'Deployment',
      AccessLogSetting: { 'Fn::If': ['DisableLogging', { Ref: 'AWS::NoValue' }, logGroup] },
    });

    expect(result).toBeNull();
  });

  it('still flags when no branch configures a destination', () => {
    const result = evaluate({
      StageName: 'prod',
      RestApiId: 'Api',
      DeploymentId: 'Deployment',
      AccessLogSetting: { 'Fn::If': ['EnableApiAccessLogs', { Format: '$context.requestId' }, { Ref: 'AWS::NoValue' }] },
    });

    expect(result?.check_id).toBe('APIGW-001');
  });

  it('evaluates log-group retention through the conditional block', () => {
    const template = {
      Resources: {
        Stage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            StageName: 'prod',
            RestApiId: 'Api',
            DeploymentId: 'Deployment',
            AccessLogSetting: { 'Fn::If': ['EnableApiAccessLogs', { DestinationArn: 'AccessLogGroup', Format: '$context.requestId' }, { Ref: 'AWS::NoValue' }] },
          },
        },
        AccessLogGroup: {
          Type: 'AWS::Logs::LogGroup',
          Properties: { LogGroupName: 'AccessLogGroup' },
        },
      },
    } as unknown as Template;

    const resource = template.Resources!['Stage']!;
    const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId: 'Stage' };
    const result = apigw001Control.run(factory.bind(context), context);

    expect(result?.check_id).toBe('APIGW-001');
  });
});
