import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw006CfnAdapterFactory();

/**
 * REQ-08 (APIGW-006): A stage with no catch-all method setting must be flagged,
 * even when every method currently declared in the template has its own
 * per-method setting with a valid logging level.
 */
function buildTemplate(methodSettings: unknown): Template {
  return {
    Resources: {
      Api: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: { Name: 'demo-api' },
      },
      ItemsResource: {
        Type: 'AWS::ApiGateway::Resource',
        Properties: { RestApiId: 'Api', ParentId: 'Api', PathPart: 'items' },
      },
      GetItems: {
        Type: 'AWS::ApiGateway::Method',
        Properties: { RestApiId: 'Api', ResourceId: 'ItemsResource', HttpMethod: 'GET', AuthorizationType: 'NONE' },
      },
      PostItems: {
        Type: 'AWS::ApiGateway::Method',
        Properties: { RestApiId: 'Api', ResourceId: 'ItemsResource', HttpMethod: 'POST', AuthorizationType: 'NONE' },
      },
      Stage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: 'Api',
          DeploymentId: 'Deployment',
          StageName: 'prod',
          MethodSettings: methodSettings,
        },
      },
    },
  } as unknown as Template;
}

function contextFor(template: Template): CfnContext {
  return {
    stackName: 'test-stack',
    template,
    resource: template.Resources!['Stage'],
    logicalId: 'Stage',
  };
}

describe('APIGW-006 REQ-08 (CloudFormation): per-method settings do not satisfy the catch-all requirement', () => {
  it('flags a stage whose only method settings are per-method entries with valid logging levels', () => {
    const template = buildTemplate([
      { ResourcePath: '/items', HttpMethod: 'GET', LoggingLevel: 'INFO' },
      { ResourcePath: '/items', HttpMethod: 'POST', LoggingLevel: 'ERROR' },
    ]);
    const adapter = factory.bind(contextFor(template)) as Apigw006Adapter;

    const result = apigw006Control.run(adapter, contextFor(template));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe('Stage');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same
  // template, but coverage is expressed as a catch-all method setting.
  it('does not flag the same stage when a catch-all method setting with a valid logging level is present', () => {
    const template = buildTemplate([
      { ResourcePath: '/*', HttpMethod: '*', LoggingLevel: 'INFO' },
    ]);
    const adapter = factory.bind(contextFor(template)) as Apigw006Adapter;

    const result = apigw006Control.run(adapter, contextFor(template));

    expect(result).toBeNull();
  });
});
