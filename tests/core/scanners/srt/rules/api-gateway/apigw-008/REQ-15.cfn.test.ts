import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-15 (APIGW-008): Method-level caching settings may be supplied by a related
 * resource that explicitly targets the assessed stage. When that related
 * configuration enables caching for all of the stage's methods AND encrypts the
 * cached data, the assessed stage is compliant.
 *
 * CloudFormation representation: an AWS::ApiGateway::Deployment whose StageName
 * matches the assessed AWS::ApiGateway::Stage (same RestApiId) carries the
 * catch-all MethodSettings for that stage.
 */

const factory = new Apigw008CfnAdapterFactory();

function buildTemplate(cacheDataEncrypted: boolean): Template {
  return {
    Resources: {
      ApiStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'RestApi',
          StageName: 'prod',
          DeploymentId: 'ApiDeployment',
        },
      },
      ApiDeployment: {
        Type: 'AWS::ApiGateway::Deployment',
        Properties: {
          RestApiId: 'RestApi',
          StageName: 'prod',
          StageDescription: {
            MethodSettings: [
              {
                HttpMethod: '*',
                ResourcePath: '/*',
                CachingEnabled: true,
                CacheDataEncrypted: cacheDataEncrypted,
              },
            ],
          },
        },
      },
    },
  } as unknown as Template;
}

function assess(template: Template, logicalId: string) {
  const resources = template.Resources as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId],
    logicalId,
  };
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

describe('APIGW-008 REQ-15 (CloudFormation): related resource supplies encrypted catch-all caching for the assessed stage', () => {
  it('passes the assessed stage when a related deployment enables caching for all methods with cache data encryption', () => {
    const result = assess(buildTemplate(true), 'ApiStage');
    expect(result).toBeNull();
  });

  // Opposite outcome: identical wiring, only the encryption flag flips to false.
  it('flags the assessed stage when the related deployment enables caching for all methods without cache data encryption', () => {
    const result = assess(buildTemplate(false), 'ApiStage');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('ApiStage');
  });
});
