import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STAGE_TYPE = 'AWS::ApiGateway::Stage';
const LOGICAL_ID = 'ApiStage';

function buildTemplate(loggingLevel: string): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: STAGE_TYPE,
        Properties: {
          RestApiId: 'RestApi',
          DeploymentId: 'Deployment',
          StageName: 'prod',
          // Catch-all method setting: every resource path, every HTTP method
          MethodSettings: [
            {
              ResourcePath: '/*',
              HttpMethod: '*',
              LoggingLevel: loggingLevel,
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function buildContext(template: Template): CfnContext {
  const resource = (template.Resources as Record<string, Resource>)[LOGICAL_ID]!;
  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function run(loggingLevel: string) {
  const context = buildContext(buildTemplate(loggingLevel));
  const factory = new Apigw006CfnAdapterFactory();
  expect(factory.appliesTo(STAGE_TYPE)).toBe(true);
  const adapter = factory.bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 REQ-03 (CloudFormation): catch-all method setting with logging level ERROR', () => {
  // Primary behavior owned by this requirement: ERROR is an accepted execution logging level
  // and the catch-all scope covers every method, so the stage passes.
  it('passes a stage whose catch-all method setting sets LoggingLevel to ERROR', () => {
    expect(run('ERROR')).toBeNull();
  });

  // Opposite case: identical catch-all setting, but the logging level is present and not accepted.
  it('flags a stage whose catch-all method setting sets LoggingLevel to OFF', () => {
    const result = run('OFF');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe(STAGE_TYPE);
  });
});
