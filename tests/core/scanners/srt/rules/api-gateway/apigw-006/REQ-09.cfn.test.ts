import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (APIGW-006): A stage that has a catch-all method setting with an accepted
 * execution logging level PASSES even when additional method settings configure
 * unrelated features (metrics, throttling) without setting a logging level.
 */

const factory = new Apigw006CfnAdapterFactory();

function buildContext(methodSettings: unknown[]): CfnContext {
  const resource = {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'MyRestApi',
      DeploymentId: 'MyDeployment',
      StageName: 'prod',
      MethodSettings: methodSettings,
    },
  } as unknown as Resource;

  const template = { Resources: { MyStage: resource } } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: 'MyStage' };
}

function run(methodSettings: unknown[]) {
  const context = buildContext(methodSettings);
  const adapter = factory.bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 REQ-09 (CloudFormation)', () => {
  it('passes when a catch-all setting sets LoggingLevel INFO and another setting only enables metrics', () => {
    const result = run([
      { HttpMethod: '*', ResourcePath: '/*', LoggingLevel: 'INFO' },
      { HttpMethod: 'GET', ResourcePath: '/items', MetricsEnabled: true },
    ]);

    expect(result).toBeNull();
  });

  it('passes when a catch-all setting sets LoggingLevel ERROR and another setting only configures throttling', () => {
    const result = run([
      { HttpMethod: 'POST', ResourcePath: '/items', ThrottlingBurstLimit: 100, ThrottlingRateLimit: 50 },
      { HttpMethod: '*', ResourcePath: '/*', LoggingLevel: 'ERROR' },
    ]);

    expect(result).toBeNull();
  });

  it('passes when an additional catch-all setting configures only metrics alongside the logging catch-all', () => {
    const result = run([
      { HttpMethod: '*', ResourcePath: '/*', LoggingLevel: 'INFO' },
      { HttpMethod: '*', ResourcePath: '/*', MetricsEnabled: true },
    ]);

    expect(result).toBeNull();
  });

  // Opposite outcome: the same shape, but the catch-all logging level is not accepted.
  // Primary behavior for an unaccepted level belongs to the logging-level requirement.
  it('flags when the catch-all setting uses a non-accepted logging level alongside the unrelated setting', () => {
    const result = run([
      { HttpMethod: '*', ResourcePath: '/*', LoggingLevel: 'OFF' },
      { HttpMethod: 'GET', ResourcePath: '/items', MetricsEnabled: true },
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });
});
