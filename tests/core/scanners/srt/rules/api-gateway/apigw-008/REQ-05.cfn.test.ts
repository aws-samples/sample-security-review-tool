import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (APIGW-008): Caching is enabled only for one specific method and path,
 * and that same specific setting also enables cache data encryption -> PASS.
 */

const factory = new Apigw008CfnAdapterFactory();

function runControl(resource: Resource, logicalId = 'PetsApiStage') {
  const template: Template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context);
  return apigw008Control.run(adapter, context);
}

function stageWithSpecificMethod(cacheDataEncrypted: boolean): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'PetsApi',
      DeploymentId: 'PetsApiDeployment',
      StageName: 'prod',
      MethodSettings: [
        {
          ResourcePath: '/pets',
          HttpMethod: 'GET',
          CachingEnabled: true,
          CacheDataEncrypted: cacheDataEncrypted,
        },
      ],
    },
  } as unknown as Resource;
}

describe('APIGW-008 REQ-05 (CloudFormation)', () => {
  it('passes when the only method with caching enabled also has cache data encryption enabled', () => {
    expect(runControl(stageWithSpecificMethod(true))).toBeNull();
  });

  // Opposite outcome: same single cached method, encryption present but disabled -> must flag.
  it('flags when that same specific cached method has cache data encryption disabled', () => {
    const result = runControl(stageWithSpecificMethod(false));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });
});
