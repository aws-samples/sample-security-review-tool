import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008CfnAdapterFactory();

function runControl(logicalId: string, resource: Resource): ScanResult | null {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context) as Apigw008Adapter;
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 (CloudFormation) - method settings collection present but empty', () => {
  // Primary behavior owned by this requirement: an empty MethodSettings collection
  // means no method has caching enabled, so the rule does not apply.
  it('passes when MethodSettings is present but has no entries', () => {
    const result = runControl('Stage', {
      Type: 'AWS::ApiGateway::Stage',
      Properties: {
        RestApiId: 'RestApi',
        DeploymentId: 'Deployment',
        StageName: 'prod',
        CacheClusterEnabled: true,
        MethodSettings: [],
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  it('passes when StageDescription.MethodSettings is present but has no entries', () => {
    const result = runControl('Deployment', {
      Type: 'AWS::ApiGateway::Deployment',
      Properties: {
        RestApiId: 'RestApi',
        StageName: 'prod',
        StageDescription: {
          CacheClusterEnabled: true,
          MethodSettings: [],
        },
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict - the collection
  // contains a cached method whose cache data is not encrypted.
  it('flags when the collection contains a caching-enabled entry without cache data encryption', () => {
    const result = runControl('Stage', {
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
            CacheDataEncrypted: false,
          },
        ],
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('Stage');
  });
});
