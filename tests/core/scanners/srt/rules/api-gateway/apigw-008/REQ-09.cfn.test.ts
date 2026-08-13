import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { CfnContext, Template, Resource, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (APIGW-008): API Gateway stages with caching enabled must have cache data
 * encryption enabled for ALL cached methods.
 *
 * Scenario: multiple method-level settings enable caching, some encrypted and at
 * least one not encrypted -> expected behavior: FLAG.
 */

const factory = new Apigw008CfnAdapterFactory();

function buildStage(methodSettings: unknown[]): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'MyRestApi',
      DeploymentId: 'MyDeployment',
      StageName: 'prod',
      CacheClusterEnabled: true,
      CacheClusterSize: '0.5',
      MethodSettings: methodSettings,
    },
  } as unknown as Resource;
}

function scan(resource: Resource): ScanResult | null {
  const template = { Resources: { MyStage: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'MyStage',
  };
  const adapter = factory.bind(context) as Apigw008Adapter;
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-09 (CloudFormation): per-method cache encryption must cover every cached method', () => {
  it('flags a stage where several methods enable caching but one lacks cache data encryption', () => {
    const result = scan(buildStage([
      { ResourcePath: '/items', HttpMethod: 'GET', CachingEnabled: true, CacheDataEncrypted: true },
      { ResourcePath: '/items', HttpMethod: 'POST', CachingEnabled: true, CacheDataEncrypted: true },
      { ResourcePath: '/orders', HttpMethod: 'GET', CachingEnabled: true, CacheDataEncrypted: false },
    ]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result?.resourceName).toBe('MyStage');
  });

  // Nearest input that flips the verdict: the same set of cached methods, with the
  // one offending method's CacheDataEncrypted turned on instead of off.
  it('does not flag when every cached method has cache data encryption enabled', () => {
    const result = scan(buildStage([
      { ResourcePath: '/items', HttpMethod: 'GET', CachingEnabled: true, CacheDataEncrypted: true },
      { ResourcePath: '/items', HttpMethod: 'POST', CachingEnabled: true, CacheDataEncrypted: true },
      { ResourcePath: '/orders', HttpMethod: 'GET', CachingEnabled: true, CacheDataEncrypted: true },
    ]));

    expect(result).toBeNull();
  });
});
