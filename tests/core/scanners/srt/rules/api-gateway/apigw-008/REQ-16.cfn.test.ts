import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-16 (APIGW-008): Cache-data-encryption coverage must apply to the ASSESSED stage.
 * Encryption enabled by a configuration resource that targets a DIFFERENT stage
 * leaves the assessed stage's cached responses unencrypted -> flag.
 */

const factory = new Apigw008CfnAdapterFactory();

function buildTemplate(options: {
  readonly assessedStageEncrypted: boolean;
  readonly otherStageEncrypted: boolean;
}): Template {
  return {
    Resources: {
      // Assessed stage: caching enabled for all methods.
      ProdStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: 'MyApi',
          CacheClusterEnabled: true,
          MethodSettings: [
            {
              ResourcePath: '/*',
              HttpMethod: '*',
              CachingEnabled: true,
              CacheDataEncrypted: options.assessedStageEncrypted,
            },
          ],
        },
      },
      // Separate configuration resource that targets a DIFFERENT stage ("dev").
      DevDeployment: {
        Type: 'AWS::ApiGateway::Deployment',
        Properties: {
          RestApiId: 'MyApi',
          StageName: 'dev',
          StageDescription: {
            CacheClusterEnabled: true,
            MethodSettings: [
              {
                ResourcePath: '/*',
                HttpMethod: '*',
                CachingEnabled: true,
                CacheDataEncrypted: options.otherStageEncrypted,
              },
            ],
          },
        },
      },
    },
  } as unknown as Template;
}

function assessProdStage(template: Template): ScanResult | null {
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, any>)['ProdStage'],
    logicalId: 'ProdStage',
  };
  return apigw008Control.run(factory.bind(context), context);
}

describe('APIGW-008 REQ-16 (CloudFormation): encryption must cover the assessed stage', () => {
  it('flags the assessed stage when its cached methods are unencrypted and only another stage has cache data encryption', () => {
    const result = assessProdStage(
      buildTemplate({ assessedStageEncrypted: false, otherStageEncrypted: true }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
    expect(result?.resourceName).toBe('ProdStage');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });

  // Opposite outcome: the encryption setting belongs to the assessed stage, and the
  // unencrypted cache configuration belongs to the other stage -> no finding.
  it('does not flag the assessed stage when its own cached methods are encrypted and only another stage is unencrypted', () => {
    const result = assessProdStage(
      buildTemplate({ assessedStageEncrypted: true, otherStageEncrypted: false }),
    );

    expect(result).toBeNull();
  });
});
