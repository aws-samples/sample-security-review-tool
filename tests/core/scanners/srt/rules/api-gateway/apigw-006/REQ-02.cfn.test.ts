import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STAGE_LOGICAL_ID = 'ProdStage';

function stageWithCatchAllLoggingLevel(loggingLevel: string): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'RestApi',
      DeploymentId: 'Deployment',
      StageName: 'prod',
      MethodSettings: [
        {
          // Catch-all: every HTTP method on every resource path
          ResourcePath: '/*',
          HttpMethod: '*',
          LoggingLevel: loggingLevel,
        },
      ],
    },
  } as unknown as Resource;
}

function buildContext(resource: Resource): CfnContext {
  const template = {
    Resources: {
      [STAGE_LOGICAL_ID]: resource,
    },
  } as unknown as Template;
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: STAGE_LOGICAL_ID,
  };
}

function run(resource: Resource) {
  const context = buildContext(resource);
  const adapter = new Apigw006CfnAdapterFactory().bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 REQ-02 (CloudFormation): catch-all method setting with INFO logging level', () => {
  // Primary behavior owned by this requirement: a catch-all method setting
  // (HttpMethod '*' on ResourcePath '/*') with LoggingLevel INFO satisfies the
  // rule for every method of the stage.
  it('passes when the catch-all method setting has LoggingLevel INFO', () => {
    expect(run(stageWithCatchAllLoggingLevel('INFO'))).toBeNull();
  });

  // Opposite outcome: same catch-all setting, present as before, but the
  // logging level does not meet the accepted standard (INFO or ERROR).
  it('flags when the catch-all method setting has LoggingLevel OFF', () => {
    const result = run(stageWithCatchAllLoggingLevel('OFF'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe(STAGE_LOGICAL_ID);
  });
});
