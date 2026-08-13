import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008CfnAdapterFactory();

function buildStage(methodSettings: unknown): Resource {
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

function scan(resource: Resource) {
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

describe('APIGW-008 REQ-04 (CloudFormation): catch-all method setting with caching enabled and cache data encryption explicitly disabled', () => {
  // Primary behavior owned by this requirement: flag the unencrypted cached catch-all setting.
  it('flags a stage whose catch-all method setting enables caching and explicitly disables cache data encryption', () => {
    const result = scan(buildStage([
      {
        HttpMethod: '*',
        ResourcePath: '/*',
        CachingEnabled: true,
        CacheDataEncrypted: false,
      },
    ]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result?.resourceName).toBe('ApiStage');
  });

  // Opposite outcome: same catch-all setting, encryption present and enabled -> no finding.
  it('does not flag when the catch-all method setting enables caching with cache data encryption enabled', () => {
    const result = scan(buildStage([
      {
        HttpMethod: '*',
        ResourcePath: '/*',
        CachingEnabled: true,
        CacheDataEncrypted: true,
      },
    ]));

    expect(result).toBeNull();
  });
});
