import { describe, expect, it } from 'vitest';

import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008CfnAdapterFactory();

function buildContext(resource: Resource, logicalId = 'ApiStage'): CfnContext {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId };
}

function scan(resource: Resource) {
  const context = buildContext(resource);
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

function stage(methodSettings: Record<string, unknown>[]): Resource {
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

describe('APIGW-008 (CloudFormation) - catch-all leaves caching off while a specific method caches with encryption', () => {
  // Primary behavior owned by APIGW-008: only cached methods must encrypt cache data.
  it('passes when the catch-all disables caching and the specific cached method encrypts its cache data', () => {
    const result = scan(
      stage([
        { HttpMethod: '*', ResourcePath: '/*', CachingEnabled: false },
        { HttpMethod: 'GET', ResourcePath: '/items', CachingEnabled: true, CacheDataEncrypted: true },
      ]),
    );

    expect(result).toBeNull();
  });

  it('flags when that same specific cached method leaves cache data encryption disabled', () => {
    const result = scan(
      stage([
        { HttpMethod: '*', ResourcePath: '/*', CachingEnabled: false },
        { HttpMethod: 'GET', ResourcePath: '/items', CachingEnabled: true, CacheDataEncrypted: false },
      ]),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('ApiStage');
  });
});
