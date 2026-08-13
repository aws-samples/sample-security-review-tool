import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (APIGW-008): a per-method setting that overrides the catch-all's
 * encryption to disabled, while keeping caching enabled for that method,
 * must be flagged — the more specific setting wins.
 */

const factory = new Apigw008CfnAdapterFactory();

function scan(methodSettings: unknown[]): ScanResult | null {
  const resource = {
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

const catchAllEncrypted = {
  HttpMethod: '*',
  ResourcePath: '/*',
  CachingEnabled: true,
  CacheDataEncrypted: true,
};

describe('APIGW-008 REQ-10 (CloudFormation): per-method override of catch-all encryption', () => {
  it('flags the stage when a specific method keeps caching enabled but disables cache data encryption', () => {
    const result = scan([
      catchAllEncrypted,
      {
        HttpMethod: 'GET',
        ResourcePath: '/pets',
        CachingEnabled: true,
        CacheDataEncrypted: false,
      },
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('MyStage');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });

  it('flags the stage when the override lives in StageDescription.MethodSettings', () => {
    const resource = {
      Type: 'AWS::ApiGateway::Deployment',
      Properties: {
        RestApiId: 'MyRestApi',
        StageName: 'prod',
        StageDescription: {
          CacheClusterEnabled: true,
          MethodSettings: [
            catchAllEncrypted,
            {
              HttpMethod: 'POST',
              ResourcePath: '/orders',
              CachingEnabled: true,
              CacheDataEncrypted: false,
            },
          ],
        },
      },
    } as unknown as Resource;

    const template = { Resources: { MyDeployment: resource } } as unknown as Template;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyDeployment',
    };

    const result = apigw008Control.run(factory.bind(context) as Apigw008Adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });

  // Opposite outcome: nearest input that flips the verdict — the specific
  // method setting agrees with the catch-all and keeps encryption enabled.
  it('does not flag when the specific method setting keeps cache data encryption enabled', () => {
    const result = scan([
      catchAllEncrypted,
      {
        HttpMethod: 'GET',
        ResourcePath: '/pets',
        CachingEnabled: true,
        CacheDataEncrypted: true,
      },
    ]);

    expect(result).toBeNull();
  });
});
