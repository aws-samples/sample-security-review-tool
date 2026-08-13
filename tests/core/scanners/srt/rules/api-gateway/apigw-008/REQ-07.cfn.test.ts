import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { CfnContext, Resource, Template, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008CfnAdapterFactory();

function scan(resource: Resource, logicalId = 'ApiStage'): ScanResult | null {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter as never, context);
}

function stageWithMethodSettings(methodSettings: unknown[]): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: { Ref: 'RestApi' },
      DeploymentId: { Ref: 'Deployment' },
      StageName: 'prod',
      MethodSettings: methodSettings,
    },
  } as unknown as Resource;
}

describe('APIGW-008 (CloudFormation) - per-method encryption does not cover a different cached method', () => {
  // Primary behavior owned by APIGW-008: encryption set on one method does not
  // protect a *different* method that has caching enabled.
  it('flags a stage where caching is enabled on one method and encryption is set only on another method', () => {
    const resource = stageWithMethodSettings([
      // The method that actually caches -- unencrypted
      {
        HttpMethod: 'GET',
        ResourcePath: '/items',
        CachingEnabled: true,
        CacheDataEncrypted: false,
      },
      // A different method carries the encryption setting, but does not cache
      {
        HttpMethod: 'POST',
        ResourcePath: '/orders',
        CachingEnabled: false,
        CacheDataEncrypted: true,
      },
    ]);

    const result = scan(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result?.resourceName).toBe('ApiStage');
  });

  it('flags the same layout when the caching method simply omits CacheDataEncrypted', () => {
    const resource = stageWithMethodSettings([
      { HttpMethod: 'GET', ResourcePath: '/items', CachingEnabled: true },
      { HttpMethod: 'POST', ResourcePath: '/orders', CachingEnabled: false, CacheDataEncrypted: true },
    ]);

    expect(scan(resource)).not.toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict -- move the encryption
  // onto the method that is actually caching.
  it('does not flag when the caching method itself has cache data encryption enabled', () => {
    const resource = stageWithMethodSettings([
      {
        HttpMethod: 'GET',
        ResourcePath: '/items',
        CachingEnabled: true,
        CacheDataEncrypted: true,
      },
      {
        HttpMethod: 'POST',
        ResourcePath: '/orders',
        CachingEnabled: false,
        CacheDataEncrypted: true,
      },
    ]);

    expect(scan(resource)).toBeNull();
  });
});
