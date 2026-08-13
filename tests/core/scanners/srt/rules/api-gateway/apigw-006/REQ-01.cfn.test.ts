import { describe, it, expect } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * APIGW-006 — API Gateway stages must have CloudWatch execution logging enabled,
 * with the logging level set to INFO or ERROR for all methods (or via a catch-all
 * method setting).
 *
 * REQ-01 (primary behavior owned by this file): a stage with NO method-level
 * logging configuration at all must be flagged, because the effective execution
 * logging level defaults to off.
 */

const STAGE_LOGICAL_ID = 'ProdStage';

function buildContext(stageProperties: Record<string, unknown>): CfnContext {
  const stage = {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'MyRestApi',
      DeploymentId: 'MyDeployment',
      StageName: 'prod',
      ...stageProperties,
    },
  } as unknown as Resource;

  const template = {
    Resources: {
      [STAGE_LOGICAL_ID]: stage,
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource: stage,
    logicalId: STAGE_LOGICAL_ID,
  };
}

function runControl(context: CfnContext) {
  const adapter = new Apigw006CfnAdapterFactory().bind(context);
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 REQ-01 (CloudFormation): stage with no method-level logging configuration', () => {
  it('flags a stage that declares no MethodSettings at all', () => {
    const result = runControl(buildContext({}));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result?.resourceName).toBe(STAGE_LOGICAL_ID);
  });

  it('flags a stage whose MethodSettings list is empty', () => {
    const result = runControl(buildContext({ MethodSettings: [] }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same stage,
  // but with a catch-all method setting that enables execution logging at INFO.
  it('does not flag a stage with a catch-all MethodSettings entry at INFO logging level', () => {
    const result = runControl(
      buildContext({
        MethodSettings: [
          {
            HttpMethod: '*',
            ResourcePath: '/*',
            LoggingLevel: 'INFO',
          },
        ],
      }),
    );

    expect(result).toBeNull();
  });
});
