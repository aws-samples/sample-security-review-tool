import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw006CfnAdapterFactory();

function scan(resource: Resource): ScanResult | null {
  const template = { Resources: { Stage: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Stage',
  };
  const adapter: Apigw006Adapter = factory.bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

function stage(properties: Record<string, unknown>): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'RestApi',
      DeploymentId: 'Deployment',
      StageName: 'prod',
      ...properties,
    },
  } as unknown as Resource;
}

describe('APIGW-006 REQ-13 (CloudFormation) — undeterminable method settings pass', () => {
  // Primary behaviour owned by this requirement: undeterminable => pass.
  it('passes when the presence of the stage method settings depends on an unresolved condition', () => {
    const result = scan(stage({
      MethodSettings: {
        'Fn::If': [
          'EnableLogging',
          [{ HttpMethod: '*', ResourcePath: '/*', LoggingLevel: 'INFO' }],
          [],
        ],
      },
    }));

    expect(result).toBeNull();
  });

  it('passes when the logging level of the catch-all method setting depends on an unresolved condition', () => {
    const result = scan(stage({
      MethodSettings: [
        {
          HttpMethod: '*',
          ResourcePath: '/*',
          LoggingLevel: { 'Fn::If': ['VerboseLogging', 'INFO', 'ERROR'] },
        },
      ],
    }));

    expect(result).toBeNull();
  });

  it('passes when the logging level comes from an unresolved cross-stack import', () => {
    const result = scan(stage({
      MethodSettings: [
        {
          HttpMethod: '*',
          ResourcePath: '/*',
          LoggingLevel: { 'Fn::ImportValue': 'SharedLoggingLevel' },
        },
      ],
    }));

    expect(result).toBeNull();
  });

  // Opposite outcome: same catch-all setting, but a determinable, non-accepted logging level.
  it('flags a catch-all method setting whose logging level resolves to a non-accepted value', () => {
    const result = scan(stage({
      MethodSettings: [
        {
          HttpMethod: '*',
          ResourcePath: '/*',
          LoggingLevel: 'OFF',
        },
      ],
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });
});
