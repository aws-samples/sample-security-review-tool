import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { Apigw008Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw008CfnAdapterFactory();

/**
 * Runs APIGW-008 over every applicable resource in the template and
 * returns the findings that were produced.
 */
function scan(template: Template): ScanResult[] {
  const results: ScanResult[] = [];
  for (const [logicalId, resource] of Object.entries(template.Resources ?? {})) {
    const resourceType = (resource as { Type: string }).Type;
    if (!factory.appliesTo(resourceType)) continue;
    const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
    const adapter = factory.bind(context) as Apigw008Adapter;
    const result = apigw008Control.run(adapter, context);
    if (result) results.push(result);
  }
  return results;
}

describe('APIGW-008 (CloudFormation) - stage without any method-level caching', () => {
  // Primary behavior owned by this requirement: no caching anywhere => nothing to encrypt => pass.
  it('passes a stage that declares no MethodSettings at all', () => {
    const template: Template = {
      Resources: {
        ApiDeployment: {
          Type: 'AWS::ApiGateway::Deployment',
          Properties: {
            RestApiId: 'RestApi',
          },
        },
        ApiStage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            RestApiId: 'RestApi',
            DeploymentId: 'ApiDeployment',
            StageName: 'prod',
          },
        },
      },
    } as unknown as Template;

    expect(scan(template)).toEqual([]);
  });

  it('passes a stage whose MethodSettings exist but leave caching disabled', () => {
    const template: Template = {
      Resources: {
        ApiStage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            RestApiId: 'RestApi',
            DeploymentId: 'ApiDeployment',
            StageName: 'prod',
            MethodSettings: [
              {
                ResourcePath: '/*',
                HttpMethod: '*',
                CachingEnabled: false,
                LoggingLevel: 'INFO',
              },
            ],
          },
        },
      },
    } as unknown as Template;

    expect(scan(template)).toEqual([]);
  });

  // Opposite outcome: caching IS enabled and the cached data is unencrypted => finding.
  it('flags a stage with caching enabled but cache data encryption disabled', () => {
    const template: Template = {
      Resources: {
        ApiStage: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            RestApiId: 'RestApi',
            DeploymentId: 'ApiDeployment',
            StageName: 'prod',
            MethodSettings: [
              {
                ResourcePath: '/*',
                HttpMethod: '*',
                CachingEnabled: true,
                CacheDataEncrypted: false,
                LoggingLevel: 'INFO',
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const results = scan(template);
    expect(results).toHaveLength(1);
    expect(results[0]?.check_id).toBe('APIGW-008');
    expect(results[0]?.resourceName).toBe('ApiStage');
  });
});
