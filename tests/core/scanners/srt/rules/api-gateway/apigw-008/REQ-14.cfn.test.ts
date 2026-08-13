import { describe, it, expect } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-14 (CloudFormation) — APIGW-008
 * Requirement under test: when it cannot be determined at analysis time whether
 * caching is enabled for the stage's methods (the value is an unresolved
 * intrinsic such as Fn::If) and no cache data encryption is configured, the
 * control must NOT report a finding — the precondition (caching enabled) is
 * never established.
 *
 * The opposite-outcome test below (caching literally enabled, encryption still
 * absent) belongs to the primary APIGW-008 behavior and is included so this file
 * can only pass with a control that actually discriminates.
 */

const factory = new Apigw008CfnAdapterFactory();

function run(resource: Resource, logicalId = 'ApiStage') {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  return apigw008Control.run(factory.bind(context) as never, context);
}

describe('APIGW-008 REQ-14 (CloudFormation): unresolvable caching state, no cache encryption', () => {
  it('does not report a finding when CachingEnabled is an unresolved Fn::If and CacheDataEncrypted is absent', () => {
    const resource = {
      Type: 'AWS::ApiGateway::Stage',
      Properties: {
        RestApiId: 'RestApi',
        DeploymentId: 'Deployment',
        StageName: 'prod',
        MethodSettings: [
          {
            ResourcePath: '/*',
            HttpMethod: '*',
            CachingEnabled: { 'Fn::If': ['EnableCaching', true, false] },
          },
        ],
      },
    } as unknown as Resource;

    expect(run(resource)).toBeNull();
  });

  it('does not report a finding when CachingEnabled is an unresolved Fn::ImportValue in StageDescription and CacheDataEncrypted is absent', () => {
    const resource = {
      Type: 'AWS::ApiGateway::Deployment',
      Properties: {
        RestApiId: 'RestApi',
        StageDescription: {
          MethodSettings: [
            {
              ResourcePath: '/*',
              HttpMethod: '*',
              CachingEnabled: { 'Fn::ImportValue': 'SharedCachingFlag' },
            },
          ],
        },
      },
    } as unknown as Resource;

    expect(run(resource, 'ApiDeployment')).toBeNull();
  });

  // Opposite outcome — primary APIGW-008 behavior: caching is KNOWN enabled and
  // cache data encryption is not enabled, so a finding must be reported.
  it('reports a finding when CachingEnabled is literally true and CacheDataEncrypted is absent', () => {
    const resource = {
      Type: 'AWS::ApiGateway::Stage',
      Properties: {
        RestApiId: 'RestApi',
        DeploymentId: 'Deployment',
        StageName: 'prod',
        MethodSettings: [
          {
            ResourcePath: '/*',
            HttpMethod: '*',
            CachingEnabled: true,
          },
        ],
      },
    } as unknown as Resource;

    const result = run(resource);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });
});
