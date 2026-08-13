import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008CfnAdapterFactory();

/**
 * REQ-17 (APIGW-008): the encryption check keys off the per-method caching
 * setting, NOT off whether a stage cache cluster is provisioned. A method with
 * CachingEnabled: true and CacheDataEncrypted: false must be flagged even when
 * the stage has no cache cluster enabled / provisioned.
 */
function buildTemplate(cacheDataEncrypted: boolean): Template {
  return {
    Resources: {
      ApiStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'MyApi',
          DeploymentId: 'MyDeployment',
          StageName: 'prod',
          // No cache cluster: caching is not (yet) effective at stage level.
          CacheClusterEnabled: false,
          MethodSettings: [
            {
              HttpMethod: 'GET',
              ResourcePath: '/items',
              CachingEnabled: true,
              CacheDataEncrypted: cacheDataEncrypted,
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template): ScanResult | null {
  const resource = (template.Resources as Record<string, never>)['ApiStage'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'ApiStage',
  };
  const adapter = factory.bind(context) as Apigw008Adapter;
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-17 (CloudFormation)', () => {
  it('flags method-level caching with CacheDataEncrypted false even when no stage cache cluster is provisioned', () => {
    const result = run(buildTemplate(false));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('ApiStage');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });

  // Opposite outcome: nearest input that flips the verdict — encryption enabled.
  it('does not flag the same stage when CacheDataEncrypted is true', () => {
    expect(run(buildTemplate(true))).toBeNull();
  });
});
