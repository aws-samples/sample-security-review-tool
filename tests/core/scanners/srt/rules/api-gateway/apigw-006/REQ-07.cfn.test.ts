import { describe, it, expect } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw006CfnAdapterFactory();

function buildContext(methodSettings: unknown[]): CfnContext {
  const template = {
    Resources: {
      ApiStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'RestApi',
          DeploymentId: 'Deployment',
          StageName: 'prod',
          MethodSettings: methodSettings,
        },
      },
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, never>)['ApiStage'],
    logicalId: 'ApiStage',
  } as CfnContext;
}

function run(methodSettings: unknown[]) {
  const context = buildContext(methodSettings);
  const adapter = factory.bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 (CloudFormation) — execution logging coverage for all methods', () => {
  // Primary behavior owned by this requirement: a logging level scoped to a single
  // method/path leaves the remaining methods without execution logging => flag.
  it('flags a stage whose only logging setting targets one specific method and path', () => {
    const result = run([
      { ResourcePath: '/orders', HttpMethod: 'GET', LoggingLevel: 'INFO' },
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result?.resourceName).toBe('ApiStage');
  });

  it('flags a stage with several method-specific logging settings but no catch-all', () => {
    const result = run([
      { ResourcePath: '/orders', HttpMethod: 'GET', LoggingLevel: 'INFO' },
      { ResourcePath: '/orders', HttpMethod: 'POST', LoggingLevel: 'ERROR' },
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: same shape, but the setting is the catch-all that covers
  // every method and path, so coverage is complete => no finding.
  it('does not flag a stage whose logging setting is a catch-all for all methods and paths', () => {
    const result = run([
      { ResourcePath: '/*', HttpMethod: '*', LoggingLevel: 'INFO' },
    ]);

    expect(result).toBeNull();
  });
});
