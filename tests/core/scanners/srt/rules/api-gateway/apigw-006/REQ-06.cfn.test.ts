import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (APIGW-006): A stage that declares a method settings collection containing no
 * entries configures no logging level for any method, so it must be flagged exactly as if
 * no configuration were present.
 */

const factory = new Apigw006CfnAdapterFactory();

function scan(stage: Resource): ReturnType<typeof apigw006Control.run> {
  const template = { Resources: { ApiStage: stage } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: stage,
    logicalId: 'ApiStage',
  };
  const adapter = factory.bind(context);
  return apigw006Control.run(adapter, context);
}

function stageWithMethodSettings(methodSettings: unknown): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'RestApi',
      DeploymentId: 'Deployment',
      StageName: 'prod',
      MethodSettings: methodSettings,
    },
  } as unknown as Resource;
}

describe('APIGW-006 CloudFormation - empty method settings collection', () => {
  it('flags a stage whose MethodSettings array is empty', () => {
    const result = scan(stageWithMethodSettings([]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceName).toBe('ApiStage');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
  });

  // Opposite outcome: the nearest input that flips the verdict is the same collection
  // holding one catch-all entry with an accepted logging level.
  it('does not flag a stage whose MethodSettings array has a catch-all entry with an accepted logging level', () => {
    const result = scan(
      stageWithMethodSettings([
        { ResourcePath: '/*', HttpMethod: '*', LoggingLevel: 'INFO' },
      ]),
    );

    expect(result).toBeNull();
  });
});
