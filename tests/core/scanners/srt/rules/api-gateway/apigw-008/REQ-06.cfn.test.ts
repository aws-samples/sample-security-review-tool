import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (APIGW-008): Caching enabled for one specific method/path while cache data
 * encryption is disabled or unspecified for that method => FLAG.
 */

const factory = new Apigw008CfnAdapterFactory();

function stage(methodSettings: unknown[]): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'MyRestApi',
      DeploymentId: 'MyDeployment',
      StageName: 'prod',
      MethodSettings: methodSettings,
    },
  } as unknown as Resource;
}

function run(resource: Resource): ScanResult | null {
  const template = { Resources: { ApiStage: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'ApiStage',
  };
  const adapter = factory.bind(context) as Apigw008Adapter;
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-06 (CloudFormation): per-method caching without cache data encryption', () => {
  it('flags a stage where one specific method/path caches with CacheDataEncrypted false', () => {
    const result = run(
      stage([
        {
          ResourcePath: '/pets',
          HttpMethod: 'GET',
          CachingEnabled: true,
          CacheDataEncrypted: false,
        },
      ]),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result?.resourceName).toBe('ApiStage');
  });

  it('flags a stage where one specific method/path caches with CacheDataEncrypted unspecified', () => {
    const result = run(
      stage([
        {
          ResourcePath: '/pets',
          HttpMethod: 'GET',
          CachingEnabled: true,
        },
      ]),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });

  // Opposite outcome: nearest input that flips the verdict — the same single
  // cached method, but with cache data encryption enabled.
  it('does not flag when the same cached method/path sets CacheDataEncrypted true', () => {
    const result = run(
      stage([
        {
          ResourcePath: '/pets',
          HttpMethod: 'GET',
          CachingEnabled: true,
          CacheDataEncrypted: true,
        },
      ]),
    );

    expect(result).toBeNull();
  });
});
