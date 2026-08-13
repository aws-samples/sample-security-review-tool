import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-03 (CloudFormation) — APIGW-008
 * A catch-all method setting (HttpMethod '*', ResourcePath '/*') enables response
 * caching but specifies NO value for CacheDataEncrypted. Because cache data
 * encryption defaults to disabled, every cached method would store responses
 * unencrypted, so the control must flag.
 */

const factory = new Apigw008CfnAdapterFactory();

function buildTemplate(resource: Resource): Template {
  return { Resources: { ApiStage: resource } } as unknown as Template;
}

function run(resource: Resource) {
  const template = buildTemplate(resource);
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'ApiStage',
  };
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

function stageWithCatchAll(setting: Record<string, unknown>): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: { Ref: 'RestApi' },
      DeploymentId: { Ref: 'Deployment' },
      StageName: 'prod',
      MethodSettings: [setting],
    },
  } as unknown as Resource;
}

describe('APIGW-008 REQ-03 (CloudFormation): catch-all caching without cache data encryption', () => {
  it('flags a stage whose catch-all method setting enables caching and omits CacheDataEncrypted', () => {
    const result = run(
      stageWithCatchAll({
        HttpMethod: '*',
        ResourcePath: '/*',
        CachingEnabled: true,
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result?.resourceName).toBe('ApiStage');
  });

  // Opposite outcome: same catch-all setting, but encryption explicitly enabled.
  // Primary behavior (flagging the omitted value) is owned by the test above.
  it('does not flag when the same catch-all setting sets CacheDataEncrypted to true', () => {
    const result = run(
      stageWithCatchAll({
        HttpMethod: '*',
        ResourcePath: '/*',
        CachingEnabled: true,
        CacheDataEncrypted: true,
      }),
    );

    expect(result).toBeNull();
  });
});
