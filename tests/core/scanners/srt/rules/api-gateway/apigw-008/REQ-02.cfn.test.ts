import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-02 (APIGW-008): A catch-all method setting (HttpMethod '*', ResourcePath '/*')
 * that enables response caching AND cache data encryption satisfies the requirement
 * for every method of the stage -> pass (no finding).
 */

const factory = new Apigw008CfnAdapterFactory();

function buildContext(resource: Resource, logicalId = 'ApiStage'): CfnContext {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId };
}

function runControl(resource: Resource, logicalId = 'ApiStage') {
  const context = buildContext(resource, logicalId);
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

function stageWithCatchAll(cacheDataEncrypted: unknown): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'MyRestApi',
      DeploymentId: 'MyDeployment',
      StageName: 'prod',
      CacheClusterEnabled: true,
      CacheClusterSize: '0.5',
      MethodSettings: [
        {
          HttpMethod: '*',
          ResourcePath: '/*',
          CachingEnabled: true,
          CacheDataEncrypted: cacheDataEncrypted,
        },
      ],
    },
  } as unknown as Resource;
}

describe('APIGW-008 REQ-02 (CloudFormation): catch-all caching with cache data encryption', () => {
  it('passes when the catch-all method setting enables caching and cache data encryption', () => {
    expect(runControl(stageWithCatchAll(true))).toBeNull();
  });

  it('applies to the applicable stage resource type', () => {
    expect(factory.appliesTo('AWS::ApiGateway::Stage')).toBe(true);
  });

  // Opposite outcome: identical catch-all setting, encryption present but disabled -> finding.
  it('flags when the catch-all method setting enables caching with cache data encryption disabled', () => {
    const result = runControl(stageWithCatchAll(false));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('ApiStage');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });

  it('passes for a catch-all inside StageDescription on a Deployment when encryption is enabled', () => {
    const deployment = {
      Type: 'AWS::ApiGateway::Deployment',
      Properties: {
        RestApiId: 'MyRestApi',
        StageName: 'prod',
        StageDescription: {
          CacheClusterEnabled: true,
          MethodSettings: [
            {
              HttpMethod: '*',
              ResourcePath: '/*',
              CachingEnabled: true,
              CacheDataEncrypted: true,
            },
          ],
        },
      },
    } as unknown as Resource;

    expect(runControl(deployment, 'ApiDeployment')).toBeNull();
  });
});
