import { describe, expect, it } from 'vitest';
import { apigw008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-008/apigw-008.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-18 (APIGW-008): A catch-all method setting (HttpMethod `*`, ResourcePath `/*`)
 * that enables cache data encryption covers every cached method. A per-method
 * setting that enables caching without stating an encryption value inherits
 * encryption from the catch-all and must NOT be flagged.
 */

const factory = new Apigw008CfnAdapterFactory();

function buildTemplate(methodSettings: Record<string, unknown>[]): Template {
  return {
    Resources: {
      ApiStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'RestApi',
          StageName: 'prod',
          MethodSettings: methodSettings,
        },
      },
    },
  } as unknown as Template;
}

function runControl(template: Template) {
  const resource = (template.Resources as Record<string, any>)['ApiStage'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'ApiStage',
  };
  return apigw008Control.run(factory.bind(context), context);
}

const CATCH_ALL_ENCRYPTED = {
  HttpMethod: '*',
  ResourcePath: '/*',
  CachingEnabled: true,
  CacheDataEncrypted: true,
};

describe('APIGW-008 REQ-18 (CloudFormation)', () => {
  it('passes when a method enables caching without an encryption value and a catch-all setting enables cache data encryption', () => {
    const template = buildTemplate([
      CATCH_ALL_ENCRYPTED,
      { HttpMethod: 'GET', ResourcePath: '/items', CachingEnabled: true },
    ]);

    expect(runControl(template)).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict is the same
  // per-method setting stating CacheDataEncrypted explicitly as false.
  it('flags when a cached method explicitly sets CacheDataEncrypted to false despite the encrypted catch-all', () => {
    const template = buildTemplate([
      CATCH_ALL_ENCRYPTED,
      { HttpMethod: 'GET', ResourcePath: '/items', CachingEnabled: true, CacheDataEncrypted: false },
    ]);

    const result = runControl(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-008');
  });
});
