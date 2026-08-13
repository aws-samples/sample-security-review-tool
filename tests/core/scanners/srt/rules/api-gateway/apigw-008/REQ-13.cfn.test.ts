import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STACK_NAME = 'test-stack';
const LOGICAL_ID = 'ApiStage';

const factory = new Apigw008CfnAdapterFactory();

function buildContext(resource: Resource): CfnContext {
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  return { stackName: STACK_NAME, template, resource, logicalId: LOGICAL_ID };
}

function scan(resource: Resource): ScanResult | null {
  const context = buildContext(resource);
  const adapter = factory.bind(context) as Apigw008Adapter;
  return apigw008Control.run(adapter, context);
}

function stage(cacheDataEncrypted: unknown): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'RestApi',
      DeploymentId: 'Deployment',
      StageName: 'prod',
      CacheClusterEnabled: true,
      MethodSettings: [
        {
          ResourcePath: '/*',
          HttpMethod: '*',
          CachingEnabled: true,
          CacheDataEncrypted: cacheDataEncrypted,
        },
      ],
    },
  } as unknown as Resource;
}

describe('APIGW-008 (CloudFormation) - indeterminate cache data encryption value', () => {
  // Primary behavior owned by this requirement: caching is on, but the
  // encryption value depends on an unresolvable condition -> must pass.
  it('passes when CacheDataEncrypted is an unresolved Fn::If', () => {
    const result = scan(stage({ 'Fn::If': ['UseEncryption', true, false] }));

    expect(result).toBeNull();
  });

  it('passes when CacheDataEncrypted is an unresolved Fn::ImportValue', () => {
    const result = scan(stage({ 'Fn::ImportValue': 'SharedCacheEncryptionFlag' }));

    expect(result).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict - the value is
  // resolvable and resolves to "not encrypted".
  it('flags the stage when CacheDataEncrypted resolves to false (owned by the unencrypted-cache requirement)', () => {
    const result = scan(stage(false));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });
});
