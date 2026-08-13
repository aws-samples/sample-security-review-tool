import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (APIGW-006): A catch-all method logging setting with a valid logging level that belongs to a
 * DIFFERENT stage (or a different API) must not satisfy the assessed stage — the assessed stage is flagged.
 *
 * In CloudFormation, method settings are declared inline on the AWS::ApiGateway::Stage they belong to, so
 * "a separate logging-settings resource targeting another stage/API" is represented by a second, unrelated
 * stage resource carrying the catch-all INFO setting.
 */

const factory = new Apigw006CfnAdapterFactory();

function buildTemplate(assessedMethodSettings: unknown, otherMethodSettings: unknown): Template {
  return {
    Resources: {
      RestApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: { Name: 'assessed-api' },
      },
      OtherRestApi: {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: { Name: 'other-api' },
      },
      AssessedStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'prod',
          RestApiId: 'RestApi',
          DeploymentId: 'Deployment',
          ...(assessedMethodSettings === undefined ? {} : { MethodSettings: assessedMethodSettings }),
        },
      },
      OtherStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          StageName: 'dev',
          RestApiId: 'OtherRestApi',
          DeploymentId: 'OtherDeployment',
          ...(otherMethodSettings === undefined ? {} : { MethodSettings: otherMethodSettings }),
        },
      },
    },
  } as unknown as Template;
}

function contextFor(template: Template, logicalId: string): CfnContext {
  const resource = (template.Resources as Record<string, Resource>)[logicalId];
  return { stackName: 'test-stack', template, resource, logicalId };
}

function run(template: Template, logicalId: string) {
  const context = contextFor(template, logicalId);
  return apigw006Control.run(factory.bind(context), context);
}

const catchAllInfo = [{ HttpMethod: '*', ResourcePath: '/*', LoggingLevel: 'INFO' }];

describe('APIGW-006 REQ-12 (CloudFormation): catch-all logging settings attached to another stage/API', () => {
  it('flags the assessed stage when the valid catch-all logging setting belongs to a different stage and API', () => {
    const template = buildTemplate(undefined, catchAllInfo);

    const result = run(template, 'AssessedStage');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe('AssessedStage');
  });

  // Opposite outcome: same template shape, but the catch-all INFO setting is attached to the assessed
  // stage itself, which is the pass case owned by the primary APIGW-006 behavior.
  it('does not flag the assessed stage when the valid catch-all logging setting is attached to it', () => {
    const template = buildTemplate(catchAllInfo, undefined);

    const result = run(template, 'AssessedStage');

    expect(result).toBeNull();
  });
});
