import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw006CfnAdapterFactory();

function buildContext(methodSettings: unknown[]): CfnContext {
  const resource = {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'RestApi',
      DeploymentId: 'Deployment',
      StageName: 'prod',
      MethodSettings: methodSettings,
    },
  } as unknown as Resource;

  const template = { Resources: { Stage: resource } } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: 'Stage' };
}

function scan(methodSettings: unknown[]) {
  const context = buildContext(methodSettings);
  const adapter = factory.bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 (CloudFormation) - method setting that turns logging off for one method', () => {
  // Primary behavior owned by this requirement: a narrower method setting with
  // LoggingLevel OFF leaves that method unlogged, so the stage is non-compliant
  // even though a catch-all setting enables logging.
  it('flags a stage whose catch-all setting is valid but a specific method setting sets LoggingLevel OFF', () => {
    const result = scan([
      { HttpMethod: '*', ResourcePath: '/*', LoggingLevel: 'INFO' },
      { HttpMethod: 'GET', ResourcePath: '/orders', LoggingLevel: 'OFF' },
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe('Stage');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });

  // Opposite outcome: identical shape, only the narrower setting's level changes
  // from OFF to an accepted level, so every method remains logged.
  it('does not flag when the narrower method setting uses an accepted logging level instead of OFF', () => {
    const result = scan([
      { HttpMethod: '*', ResourcePath: '/*', LoggingLevel: 'INFO' },
      { HttpMethod: 'GET', ResourcePath: '/orders', LoggingLevel: 'INFO' },
    ]);

    expect(result).toBeNull();
  });
});
