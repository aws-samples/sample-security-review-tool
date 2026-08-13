import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008CfnAdapterFactory();

function buildContext(resource: Resource, logicalId = 'ApiStage'): CfnContext {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId };
}

function run(resource: Resource) {
  const context = buildContext(resource);
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

function stageWith(methodSettings: unknown[]): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'RestApi',
      DeploymentId: 'Deployment',
      StageName: 'prod',
      MethodSettings: methodSettings,
    },
  } as unknown as Resource;
}

describe('APIGW-008 (CloudFormation) - mixed method settings where every caching-enabled method encrypts cache data', () => {
  // Primary behavior owned by APIGW-008: only methods with caching enabled need encrypted cache data.
  it('passes when all caching-enabled method settings encrypt cache data and other settings only tune non-caching behavior', () => {
    const result = run(
      stageWith([
        {
          HttpMethod: 'GET',
          ResourcePath: '/items',
          CachingEnabled: true,
          CacheDataEncrypted: true,
          CacheTtlInSeconds: 300,
        },
        {
          HttpMethod: 'GET',
          ResourcePath: '/items/{id}',
          CachingEnabled: true,
          CacheDataEncrypted: true,
        },
        {
          HttpMethod: 'POST',
          ResourcePath: '/items',
          CachingEnabled: false,
          ThrottlingBurstLimit: 100,
          ThrottlingRateLimit: 50,
        },
        {
          HttpMethod: '*',
          ResourcePath: '/*',
          LoggingLevel: 'INFO',
          MetricsEnabled: true,
        },
      ]),
    );

    expect(result).toBeNull();
  });

  it('flags the stage when one caching-enabled method leaves cache data unencrypted (opposite case)', () => {
    const result = run(
      stageWith([
        {
          HttpMethod: 'GET',
          ResourcePath: '/items',
          CachingEnabled: true,
          CacheDataEncrypted: true,
          CacheTtlInSeconds: 300,
        },
        {
          HttpMethod: 'GET',
          ResourcePath: '/items/{id}',
          CachingEnabled: true,
          CacheDataEncrypted: false,
        },
        {
          HttpMethod: 'POST',
          ResourcePath: '/items',
          CachingEnabled: false,
          ThrottlingBurstLimit: 100,
          ThrottlingRateLimit: 50,
        },
        {
          HttpMethod: '*',
          ResourcePath: '/*',
          LoggingLevel: 'INFO',
          MetricsEnabled: true,
        },
      ]),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });
});
